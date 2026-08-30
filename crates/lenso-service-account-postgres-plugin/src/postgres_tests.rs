use std::str::FromStr;

use futures::join;
use lenso_postgres_kit::OwnedPostgres;
use sqlx::{AssertSqlSafe, Connection, PgConnection, Row, postgres::PgConnectOptions};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    ServiceAccountOperator,
    crypto::{CredentialSecret, ReceiptCipher},
    schema::schema_plan,
    storage::{self, CommandClaim, Mutation},
};

const SCHEMA: &str = "service_accounts";

/// Exercises the durable security boundaries against a real server. CI and release runs set
/// `LENSO_TEST_POSTGRES_ADMIN_URL`; local unit runs can leave it unset.
#[tokio::test]
#[ignore = "requires LENSO_TEST_POSTGRES_ADMIN_URL and CREATE DATABASE"]
#[allow(clippy::too_many_lines)]
async fn restart_concurrency_and_secret_once_acceptance() {
    let admin_url = std::env::var("LENSO_TEST_POSTGRES_ADMIN_URL")
        .expect("set LENSO_TEST_POSTGRES_ADMIN_URL for PostgreSQL acceptance");
    let database_name = format!("lenso_sa_test_{}", Uuid::new_v4().simple());
    let database_url = create_database(&admin_url, &database_name).await;

    ServiceAccountOperator::setup(&database_url, SCHEMA)
        .await
        .expect("setup schema");
    let postgres = OwnedPostgres::prepare(&database_url, schema_plan(SCHEMA).expect("plan"))
        .await
        .expect("prepare schema");
    let receipt_cipher = ReceiptCipher::derive(b"acceptance receipt key material over 32 bytes");
    let pepper = b"acceptance pepper material over 32 bytes";

    let create_intent = [1_u8; 32];
    assert!(matches!(
        storage::claim_command(&postgres, "admin-api", "create", "create-1", &create_intent)
            .await
            .expect("claim create"),
        CommandClaim::Claimed
    ));
    assert!(matches!(
        storage::claim_command(
            &postgres,
            "other-admin",
            "create",
            "create-1",
            &create_intent
        )
        .await
        .expect("caller-scoped claim"),
        CommandClaim::Claimed
    ));
    assert!(matches!(
        storage::claim_command(&postgres, "admin-api", "create", "create-1", &[2_u8; 32])
            .await
            .expect("conflicting claim"),
        CommandClaim::Conflict
    ));

    let secret = CredentialSecret::generate().expect("credential secret");
    let raw_secret = secret.expose();
    let verifier = secret.verifier(pepper).expect("credential verifier");
    let now = OffsetDateTime::now_utc();
    let aad = b"admin-api\0create\0create-1";
    let cipher = receipt_cipher.clone();
    let account = storage::create_account(
        &postgres,
        "admin-api",
        "create",
        "create-1",
        100,
        "sa_acceptance",
        "org_acceptance",
        "usr_service_account",
        "Release bot",
        "release bot",
        &secret.credential_id,
        &verifier,
        now,
        now + Duration::hours(1),
        move |_| {
            cipher
                .encrypt(&serde_json::json!({"secret": null}), aad)
                .map_err(Into::into)
        },
    )
    .await
    .expect("create account")
    .expect("within account limit");
    assert_eq!(account.revision, 1);
    assert!(raw_secret.starts_with("lenso_sa_sac_"));

    assert!(matches!(
        storage::claim_command(
            &postgres,
            "admin-api",
            "create",
            "create-duplicate",
            &[8_u8; 32],
        )
        .await
        .expect("claim duplicate name"),
        CommandClaim::Claimed
    ));
    let duplicate = CredentialSecret::generate().expect("duplicate credential");
    let duplicate_verifier = duplicate.verifier(pepper).expect("duplicate verifier");
    let duplicate_error = storage::create_account(
        &postgres,
        "admin-api",
        "create",
        "create-duplicate",
        100,
        "sa_duplicate",
        "org_acceptance",
        "usr_duplicate_service_account",
        "Release BOT",
        "release bot",
        &duplicate.credential_id,
        &duplicate_verifier,
        now,
        now + Duration::hours(1),
        |_| unreachable!("duplicate name cannot create a receipt"),
    )
    .await
    .expect_err("organization name key must be unique");
    assert_eq!(
        storage::unique_constraint(&duplicate_error),
        Some("service_accounts_organization_name_unique")
    );

    let stored: (String, Vec<u8>) = sqlx::query(
        "SELECT c.verifier,m.response_ciphertext FROM service_account_credentials c JOIN service_account_commands m ON m.caller_instance='admin-api' AND m.operation='create' AND m.idempotency_key='create-1' WHERE c.credential_id=$1",
    )
    .bind(&secret.credential_id)
    .fetch_one(postgres.pool())
    .await
    .map(|row| (row.get("verifier"), row.get("response_ciphertext")))
    .expect("load protected state");
    assert!(!stored.0.contains(&raw_secret));
    assert!(
        !stored
            .1
            .windows(raw_secret.len())
            .any(|window| window == raw_secret.as_bytes())
    );

    // A process restart sees the durable receipt, but the receipt has only a null secret.
    postgres.pool().close().await;
    drop(postgres);
    let postgres = OwnedPostgres::prepare(&database_url, schema_plan(SCHEMA).expect("plan"))
        .await
        .expect("prepare after restart");
    let CommandClaim::CompletedSuccess { nonce, ciphertext } =
        storage::claim_command(&postgres, "admin-api", "create", "create-1", &create_intent)
            .await
            .expect("replay create")
    else {
        panic!("restart must load a completed receipt");
    };
    let replay: serde_json::Value = receipt_cipher
        .decrypt(&nonce, &ciphertext, aad)
        .expect("decrypt receipt");
    assert!(replay["secret"].is_null());

    // Two rotations from revision 1 race; exactly one advances the CAS revision.
    let first = CredentialSecret::generate().expect("first rotation");
    let second = CredentialSecret::generate().expect("second rotation");
    let first_verifier = first.verifier(pepper).expect("first verifier");
    let second_verifier = second.verifier(pepper).expect("second verifier");
    for key in ["rotate-1", "rotate-2"] {
        assert!(matches!(
            storage::claim_command(&postgres, "admin-api", "rotate_secret", key, &[3_u8; 32])
                .await
                .expect("claim rotation"),
            CommandClaim::Claimed
        ));
    }
    let first_cipher = receipt_cipher.clone();
    let second_cipher = receipt_cipher.clone();
    let first_id = first.credential_id.clone();
    let second_id = second.credential_id.clone();
    let rotate_time = OffsetDateTime::now_utc();
    let first_rotation = storage::rotate_account(
        &postgres,
        "admin-api",
        "rotate_secret",
        "rotate-1",
        "org_acceptance",
        "sa_acceptance",
        1,
        &first_id,
        &first_verifier,
        rotate_time,
        rotate_time + Duration::minutes(5),
        rotate_time + Duration::hours(1),
        move |_| {
            first_cipher
                .encrypt(&serde_json::json!({"secret": null}), b"rotate-1")
                .map_err(Into::into)
        },
    );
    let second_rotation = storage::rotate_account(
        &postgres,
        "admin-api",
        "rotate_secret",
        "rotate-2",
        "org_acceptance",
        "sa_acceptance",
        1,
        &second_id,
        &second_verifier,
        rotate_time,
        rotate_time + Duration::minutes(5),
        rotate_time + Duration::hours(1),
        move |_| {
            second_cipher
                .encrypt(&serde_json::json!({"secret": null}), b"rotate-2")
                .map_err(Into::into)
        },
    );
    let (first_result, second_result) = join!(first_rotation, second_rotation);
    let first_result = first_result.expect("first rotation result");
    let second_result = second_result.expect("second rotation result");
    assert!(matches!(
        (&first_result, &second_result),
        (Mutation::Updated(_), Mutation::RevisionConflict)
            | (Mutation::RevisionConflict, Mutation::Updated(_))
    ));
    let (winning_credential_id, winning_key, winning_aad, winning_secret) =
        if matches!(&first_result, Mutation::Updated(_)) {
            (first_id, "rotate-1", b"rotate-1".as_slice(), first.expose())
        } else {
            (
                second_id,
                "rotate-2",
                b"rotate-2".as_slice(),
                second.expose(),
            )
        };
    let CommandClaim::CompletedSuccess { nonce, ciphertext } = storage::claim_command(
        &postgres,
        "admin-api",
        "rotate_secret",
        winning_key,
        &[3_u8; 32],
    )
    .await
    .expect("replay winning rotation") else {
        panic!("winning rotation must have a durable receipt");
    };
    let replay: serde_json::Value = receipt_cipher
        .decrypt(&nonce, &ciphertext, winning_aad)
        .expect("decrypt rotation receipt");
    assert!(replay["secret"].is_null());
    assert!(
        !ciphertext
            .windows(winning_secret.len())
            .any(|window| window == winning_secret.as_bytes())
    );

    // Revocation locks the account and all credentials before a pending exchange may issue.
    assert!(matches!(
        storage::claim_command(&postgres, "admin-api", "revoke", "revoke-1", &[4_u8; 32])
            .await
            .expect("claim revoke"),
        CommandClaim::Claimed
    ));
    let cipher = receipt_cipher.clone();
    assert!(matches!(
        storage::revoke_account(
            &postgres,
            "admin-api",
            "revoke",
            "revoke-1",
            "org_acceptance",
            "sa_acceptance",
            2,
            move |_| cipher
                .encrypt(&serde_json::json!({"revoked": true}), b"revoke-1")
                .map_err(Into::into),
        )
        .await
        .expect("revoke account"),
        Mutation::Updated(_)
    ));
    assert!(matches!(
        storage::claim_command(
            &postgres,
            "auth-ingress",
            "exchange_secret",
            "exchange-revoked",
            &[5_u8; 32],
        )
        .await
        .expect("claim revoked exchange"),
        CommandClaim::Claimed
    ));
    assert!(
        storage::mark_exchange_issuing(
            &postgres,
            "auth-ingress",
            "exchange-revoked",
            &winning_credential_id,
            "sa_acceptance",
            OffsetDateTime::now_utc(),
        )
        .await
        .expect("recheck revoked credential")
        .is_none()
    );

    let expired = CredentialSecret::generate().expect("expired credential");
    let expired_verifier = expired.verifier(pepper).expect("expired verifier");
    assert!(matches!(
        storage::claim_command(
            &postgres,
            "admin-api",
            "create",
            "create-expired",
            &[6_u8; 32],
        )
        .await
        .expect("claim expired fixture"),
        CommandClaim::Claimed
    ));
    let cipher = receipt_cipher.clone();
    storage::create_account(
        &postgres,
        "admin-api",
        "create",
        "create-expired",
        100,
        "sa_expired",
        "org_acceptance",
        "usr_expired_service_account",
        "Expired bot",
        "expired bot",
        &expired.credential_id,
        &expired_verifier,
        now - Duration::hours(2),
        now - Duration::hours(1),
        move |_| {
            cipher
                .encrypt(&serde_json::json!({"secret": null}), b"create-expired")
                .map_err(Into::into)
        },
    )
    .await
    .expect("create expired fixture")
    .expect("within account limit");
    assert!(matches!(
        storage::claim_command(
            &postgres,
            "auth-ingress",
            "exchange_secret",
            "exchange-expired",
            &[7_u8; 32],
        )
        .await
        .expect("claim expired exchange"),
        CommandClaim::Claimed
    ));
    assert!(
        storage::mark_exchange_issuing(
            &postgres,
            "auth-ingress",
            "exchange-expired",
            &expired.credential_id,
            "sa_expired",
            OffsetDateTime::now_utc(),
        )
        .await
        .expect("recheck expired credential")
        .is_none()
    );

    assert!(
        storage::reserve_rate_slot(&postgres, "auth-ingress", now, 60, 1, 300)
            .await
            .expect("first rate slot")
    );
    assert!(
        !storage::reserve_rate_slot(&postgres, "auth-ingress", now, 60, 1, 300)
            .await
            .expect("bounded rate slot")
    );

    postgres.pool().close().await;
    drop(postgres);
    drop_database(&admin_url, &database_name).await;
}

async fn create_database(admin_url: &str, database_name: &str) -> String {
    let options = PgConnectOptions::from_str(admin_url).expect("valid admin URL");
    let mut connection = PgConnection::connect_with(&options)
        .await
        .expect("connect to PostgreSQL admin database");
    let create = format!("CREATE DATABASE \"{database_name}\"");
    sqlx::query(AssertSqlSafe(create))
        .execute(&mut connection)
        .await
        .expect("create isolated test database");
    let (base, _) = admin_url
        .rsplit_once('/')
        .expect("admin URL includes a database path");
    format!("{base}/{database_name}")
}

async fn drop_database(admin_url: &str, database_name: &str) {
    let options = PgConnectOptions::from_str(admin_url).expect("valid admin URL");
    let mut connection = PgConnection::connect_with(&options)
        .await
        .expect("reconnect to PostgreSQL admin database");
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1")
        .bind(database_name)
        .execute(&mut connection)
        .await
        .expect("terminate isolated test sessions");
    let drop = format!("DROP DATABASE \"{database_name}\"");
    sqlx::query(AssertSqlSafe(drop))
        .execute(&mut connection)
        .await
        .expect("drop isolated test database");
}
