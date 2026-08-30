use lenso_postgres_kit::OwnedPostgres;
use sqlx::{Postgres, Row, Transaction};
use time::{Duration, OffsetDateTime};

use crate::ServiceAccountPluginError;

pub(crate) enum CommandClaim {
    Claimed,
    CompletedSuccess { nonce: Vec<u8>, ciphertext: Vec<u8> },
    CompletedError(String),
    Conflict,
    InProgress,
}

impl std::fmt::Debug for CommandClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Claimed => formatter.write_str("Claimed"),
            Self::CompletedSuccess { .. } => formatter
                .debug_struct("CompletedSuccess")
                .field("receipt", &"<redacted>")
                .finish(),
            Self::CompletedError(code) => {
                formatter.debug_tuple("CompletedError").field(code).finish()
            }
            Self::Conflict => formatter.write_str("Conflict"),
            Self::InProgress => formatter.write_str("InProgress"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AccountRow {
    pub service_account_id: String,
    pub organization_id: String,
    pub subject: String,
    pub name: String,
    pub status: String,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub rotated_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub credential_expires_at: Option<OffsetDateTime>,
}

pub(crate) struct CredentialRow {
    pub credential_id: String,
    pub service_account_id: String,
    pub organization_id: String,
    pub subject: String,
    pub account_status: String,
    pub verifier: String,
    pub valid_from: OffsetDateTime,
    pub valid_until: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

impl std::fmt::Debug for CredentialRow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialRow")
            .field("credential_id", &self.credential_id)
            .field("service_account_id", &self.service_account_id)
            .field("organization_id", &self.organization_id)
            .field("subject", &self.subject)
            .field("account_status", &self.account_status)
            .field("verifier", &"<redacted>")
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum Mutation<T> {
    Updated(T),
    NotFound,
    Revoked,
    RevisionConflict,
}

pub(crate) async fn prune(
    postgres: &OwnedPostgres,
    receipt_ttl_seconds: i64,
) -> Result<(), ServiceAccountPluginError> {
    sqlx::query(
        "DELETE FROM service_account_commands WHERE completed_at IS NOT NULL AND completed_at < now() - make_interval(secs => $1)",
    )
    .bind(receipt_ttl_seconds)
    .execute(postgres.pool())
    .await
    .map_err(database("prune service-account receipts"))?;
    Ok(())
}

pub(crate) async fn claim_command(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    intent_hash: &[u8; 32],
) -> Result<CommandClaim, ServiceAccountPluginError> {
    let inserted = sqlx::query(
        "INSERT INTO service_account_commands(caller_instance,operation,idempotency_key,intent_hash,status) VALUES($1,$2,$3,$4,'reserved') ON CONFLICT DO NOTHING",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .bind(intent_hash.as_slice())
    .execute(postgres.pool())
    .await
    .map_err(database("reserve service-account command"))?
    .rows_affected()
        == 1;
    if inserted {
        return Ok(CommandClaim::Claimed);
    }
    let row = sqlx::query(
        "SELECT intent_hash,status,response_nonce,response_ciphertext,error_code FROM service_account_commands WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .fetch_one(postgres.pool())
    .await
    .map_err(database("load service-account command"))?;
    let existing: Vec<u8> = row
        .try_get("intent_hash")
        .map_err(database("decode service-account command intent"))?;
    if existing.as_slice() != intent_hash {
        return Ok(CommandClaim::Conflict);
    }
    let status: String = row
        .try_get("status")
        .map_err(database("decode service-account command status"))?;
    match status.as_str() {
        "completed_success" => Ok(CommandClaim::CompletedSuccess {
            nonce: row
                .try_get("response_nonce")
                .map_err(database("decode service-account receipt nonce"))?,
            ciphertext: row
                .try_get("response_ciphertext")
                .map_err(database("decode service-account receipt ciphertext"))?,
        }),
        "completed_error" => Ok(CommandClaim::CompletedError(
            row.try_get("error_code")
                .map_err(database("decode service-account command error"))?,
        )),
        _ => Ok(CommandClaim::InProgress),
    }
}

pub(crate) async fn complete_success(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), ServiceAccountPluginError> {
    let changed = sqlx::query(
        "UPDATE service_account_commands SET status='completed_success',response_nonce=$4,response_ciphertext=$5,completed_at=now(),updated_at=now() WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3 AND status IN ('reserved','verifying','issuing')",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .bind(nonce)
    .bind(ciphertext)
    .execute(&mut **transaction)
    .await
    .map_err(database("complete service-account command"))?
    .rows_affected();
    if changed != 1 {
        return Err(ServiceAccountPluginError::Invariant(
            "service-account command was not completable",
        ));
    }
    Ok(())
}

pub(crate) async fn complete_error(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    error_code: &str,
) -> Result<(), ServiceAccountPluginError> {
    let changed = sqlx::query(
        "UPDATE service_account_commands SET status='completed_error',error_code=$4,completed_at=now(),updated_at=now() WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3 AND status IN ('reserved','verifying','issuing')",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .bind(error_code)
    .execute(postgres.pool())
    .await
    .map_err(database("complete failed service-account command"))?
    .rows_affected();
    if changed != 1 {
        return Err(ServiceAccountPluginError::Invariant(
            "service-account command error was not completable",
        ));
    }
    Ok(())
}

pub(crate) async fn complete_success_owned(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), ServiceAccountPluginError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(database("begin service-account receipt completion"))?;
    complete_success(
        &mut transaction,
        caller,
        operation,
        idempotency_key,
        nonce,
        ciphertext,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(database("commit service-account receipt completion"))?;
    Ok(())
}

pub(crate) async fn load_account(
    postgres: &OwnedPostgres,
    organization_id: &str,
    service_account_id: &str,
) -> Result<Option<AccountRow>, ServiceAccountPluginError> {
    let row = sqlx::query(
        "SELECT a.service_account_id,a.organization_id,a.subject,a.name,a.status,a.revision,a.created_at,a.rotated_at,a.revoked_at,(SELECT c.valid_until FROM service_account_credentials c WHERE c.service_account_id=a.service_account_id ORDER BY c.created_at DESC,c.credential_id DESC LIMIT 1) AS credential_expires_at FROM service_accounts a WHERE a.organization_id=$1 AND a.service_account_id=$2",
    )
    .bind(organization_id)
    .bind(service_account_id)
    .fetch_optional(postgres.pool())
    .await
    .map_err(database("load service account"))?;
    row.as_ref().map(decode_account).transpose()
}

pub(crate) async fn list_accounts(
    postgres: &OwnedPostgres,
    organization_id: &str,
    after: Option<&str>,
    limit_plus_one: i64,
) -> Result<Vec<AccountRow>, ServiceAccountPluginError> {
    let rows = sqlx::query(
        "SELECT a.service_account_id,a.organization_id,a.subject,a.name,a.status,a.revision,a.created_at,a.rotated_at,a.revoked_at,(SELECT c.valid_until FROM service_account_credentials c WHERE c.service_account_id=a.service_account_id ORDER BY c.created_at DESC,c.credential_id DESC LIMIT 1) AS credential_expires_at FROM service_accounts a WHERE a.organization_id=$1 AND ($2::TEXT IS NULL OR a.service_account_id>$2) ORDER BY a.service_account_id LIMIT $3",
    )
    .bind(organization_id)
    .bind(after)
    .bind(limit_plus_one)
    .fetch_all(postgres.pool())
    .await
    .map_err(database("list service accounts"))?;
    rows.iter().map(decode_account).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_account<F>(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    max_accounts: i64,
    service_account_id: &str,
    organization_id: &str,
    subject: &str,
    name: &str,
    name_key: &str,
    credential_id: &str,
    verifier: &str,
    valid_from: OffsetDateTime,
    valid_until: OffsetDateTime,
    receipt: F,
) -> Result<Option<AccountRow>, ServiceAccountPluginError>
where
    F: FnOnce(&AccountRow) -> Result<([u8; 12], Vec<u8>), ServiceAccountPluginError>,
{
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(database("begin service-account creation"))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(organization_id)
        .execute(&mut *transaction)
        .await
        .map_err(database("lock service-account organization"))?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM service_accounts WHERE organization_id=$1")
            .bind(organization_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(database("count service accounts"))?;
    if count >= max_accounts {
        transaction
            .rollback()
            .await
            .map_err(database("rollback service-account limit"))?;
        return Ok(None);
    }
    sqlx::query(
        "INSERT INTO service_accounts(service_account_id,organization_id,subject,name,name_key,status) VALUES($1,$2,$3,$4,$5,'active')",
    )
    .bind(service_account_id)
    .bind(organization_id)
    .bind(subject)
    .bind(name)
    .bind(name_key)
    .execute(&mut *transaction)
    .await
    .map_err(database("insert service account"))?;
    sqlx::query(
        "INSERT INTO service_account_credentials(credential_id,service_account_id,verifier,valid_from,valid_until) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(credential_id)
    .bind(service_account_id)
    .bind(verifier)
    .bind(valid_from)
    .bind(valid_until)
    .execute(&mut *transaction)
    .await
    .map_err(database("insert service-account credential"))?;
    let row = load_account_in_transaction(&mut transaction, organization_id, service_account_id)
        .await?
        .ok_or(ServiceAccountPluginError::Invariant(
            "created service account is missing",
        ))?;
    let (nonce, ciphertext) = receipt(&row)?;
    complete_success(
        &mut transaction,
        caller,
        operation,
        idempotency_key,
        &nonce,
        &ciphertext,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(database("commit service-account creation"))?;
    Ok(Some(row))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn rotate_account<F>(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    organization_id: &str,
    service_account_id: &str,
    expected_revision: i64,
    credential_id: &str,
    verifier: &str,
    valid_from: OffsetDateTime,
    overlap_until: OffsetDateTime,
    valid_until: OffsetDateTime,
    receipt: F,
) -> Result<Mutation<AccountRow>, ServiceAccountPluginError>
where
    F: FnOnce(&AccountRow) -> Result<([u8; 12], Vec<u8>), ServiceAccountPluginError>,
{
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(database("begin service-account rotation"))?;
    let Some(current) = lock_account(&mut transaction, organization_id, service_account_id).await?
    else {
        transaction
            .rollback()
            .await
            .map_err(database("rollback missing service account"))?;
        return Ok(Mutation::NotFound);
    };
    if current.status == "revoked" {
        transaction
            .rollback()
            .await
            .map_err(database("rollback revoked service account"))?;
        return Ok(Mutation::Revoked);
    }
    if current.revision != expected_revision {
        transaction
            .rollback()
            .await
            .map_err(database("rollback rotation revision conflict"))?;
        return Ok(Mutation::RevisionConflict);
    }
    sqlx::query(
        "UPDATE service_account_credentials SET valid_until=LEAST(valid_until,$2),superseded_at=COALESCE(superseded_at,$1) WHERE service_account_id=$3 AND revoked_at IS NULL AND valid_until>$1",
    )
    .bind(valid_from)
    .bind(overlap_until)
    .bind(service_account_id)
    .execute(&mut *transaction)
    .await
    .map_err(database("bound previous service-account credentials"))?;
    sqlx::query(
        "INSERT INTO service_account_credentials(credential_id,service_account_id,verifier,valid_from,valid_until) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(credential_id)
    .bind(service_account_id)
    .bind(verifier)
    .bind(valid_from)
    .bind(valid_until)
    .execute(&mut *transaction)
    .await
    .map_err(database("insert rotated service-account credential"))?;
    sqlx::query(
        "UPDATE service_accounts SET revision=revision+1,rotated_at=$2,updated_at=$2 WHERE service_account_id=$1",
    )
    .bind(service_account_id)
    .bind(valid_from)
    .execute(&mut *transaction)
    .await
    .map_err(database("advance rotated service account"))?;
    let row = load_account_in_transaction(&mut transaction, organization_id, service_account_id)
        .await?
        .ok_or(ServiceAccountPluginError::Invariant(
            "rotated service account is missing",
        ))?;
    let (nonce, ciphertext) = receipt(&row)?;
    complete_success(
        &mut transaction,
        caller,
        operation,
        idempotency_key,
        &nonce,
        &ciphertext,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(database("commit service-account rotation"))?;
    Ok(Mutation::Updated(row))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn revoke_account<F>(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    organization_id: &str,
    service_account_id: &str,
    expected_revision: i64,
    receipt: F,
) -> Result<Mutation<(AccountRow, bool)>, ServiceAccountPluginError>
where
    F: FnOnce(&(AccountRow, bool)) -> Result<([u8; 12], Vec<u8>), ServiceAccountPluginError>,
{
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(database("begin service-account revocation"))?;
    let Some(current) = lock_account(&mut transaction, organization_id, service_account_id).await?
    else {
        transaction
            .rollback()
            .await
            .map_err(database("rollback missing service-account revocation"))?;
        return Ok(Mutation::NotFound);
    };
    if current.revision != expected_revision {
        transaction
            .rollback()
            .await
            .map_err(database("rollback revocation revision conflict"))?;
        return Ok(Mutation::RevisionConflict);
    }
    let changed = current.status != "revoked";
    if changed {
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            "UPDATE service_accounts SET status='revoked',revision=revision+1,revoked_at=$2,updated_at=$2 WHERE service_account_id=$1",
        )
        .bind(service_account_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database("revoke service account"))?;
        sqlx::query(
            "UPDATE service_account_credentials SET revoked_at=COALESCE(revoked_at,$2),valid_until=GREATEST(valid_from,LEAST(valid_until,$2)) WHERE service_account_id=$1",
        )
        .bind(service_account_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database("revoke service-account credentials"))?;
    }
    let row = load_account_in_transaction(&mut transaction, organization_id, service_account_id)
        .await?
        .ok_or(ServiceAccountPluginError::Invariant(
            "revoked service account is missing",
        ))?;
    let result = (row, changed);
    let (nonce, ciphertext) = receipt(&result)?;
    complete_success(
        &mut transaction,
        caller,
        operation,
        idempotency_key,
        &nonce,
        &ciphertext,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(database("commit service-account revocation"))?;
    Ok(Mutation::Updated(result))
}

pub(crate) async fn load_credential(
    postgres: &OwnedPostgres,
    credential_id: &str,
) -> Result<Option<CredentialRow>, ServiceAccountPluginError> {
    let row = sqlx::query(
        "SELECT c.credential_id,c.service_account_id,a.organization_id,a.subject,a.status AS account_status,c.verifier,c.valid_from,c.valid_until,c.revoked_at FROM service_account_credentials c JOIN service_accounts a ON a.service_account_id=c.service_account_id WHERE c.credential_id=$1",
    )
    .bind(credential_id)
    .fetch_optional(postgres.pool())
    .await
    .map_err(database("load service-account credential"))?;
    row.as_ref().map(decode_credential).transpose()
}

pub(crate) async fn mark_exchange_issuing(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    credential_id: &str,
    service_account_id: &str,
    now: OffsetDateTime,
) -> Result<Option<CredentialRow>, ServiceAccountPluginError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(database("begin service-account exchange"))?;
    let account_status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM service_accounts WHERE service_account_id=$1 FOR UPDATE",
    )
    .bind(service_account_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database("lock exchanged service account"))?;
    if account_status.as_deref() != Some("active") {
        transaction
            .rollback()
            .await
            .map_err(database("rollback inactive service-account exchange"))?;
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT c.credential_id,c.service_account_id,a.organization_id,a.subject,a.status AS account_status,c.verifier,c.valid_from,c.valid_until,c.revoked_at FROM service_account_credentials c JOIN service_accounts a ON a.service_account_id=c.service_account_id WHERE c.credential_id=$1 AND c.service_account_id=$2 AND a.status='active' AND c.revoked_at IS NULL AND c.valid_from<=$3 AND c.valid_until>$3 FOR UPDATE OF c",
    )
    .bind(credential_id)
    .bind(service_account_id)
    .bind(now)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database("recheck service-account credential"))?;
    let Some(row) = row else {
        transaction
            .rollback()
            .await
            .map_err(database("rollback invalid service-account exchange"))?;
        return Ok(None);
    };
    let credential = decode_credential(&row)?;
    sqlx::query("UPDATE service_account_credentials SET last_used_at=$2 WHERE credential_id=$1")
        .bind(credential_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database("record service-account credential use"))?;
    let advanced = sqlx::query(
        "UPDATE service_account_commands SET status='issuing',updated_at=$4 WHERE caller_instance=$1 AND operation='exchange_secret' AND idempotency_key=$2 AND status='reserved' AND EXISTS(SELECT 1 FROM service_account_credentials WHERE credential_id=$3)",
    )
    .bind(caller)
    .bind(idempotency_key)
    .bind(credential_id)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database("mark service-account exchange issuing"))?
    .rows_affected();
    if advanced != 1 {
        transaction
            .rollback()
            .await
            .map_err(database("rollback stale service-account exchange"))?;
        return Ok(None);
    }
    transaction
        .commit()
        .await
        .map_err(database("commit verified service-account exchange"))?;
    Ok(Some(credential))
}

pub(crate) async fn reserve_rate_slot(
    postgres: &OwnedPostgres,
    caller: &str,
    now: OffsetDateTime,
    window_seconds: i64,
    max_attempts: i64,
    lockout_seconds: i64,
) -> Result<bool, ServiceAccountPluginError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(database("begin service-account rate admission"))?;
    sqlx::query(
        "INSERT INTO service_account_exchange_limits(caller_instance,window_started_at,attempts) VALUES($1,$2,0) ON CONFLICT DO NOTHING",
    )
    .bind(caller)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database("initialize service-account rate limit"))?;
    let row = sqlx::query(
        "SELECT window_started_at,attempts,locked_until FROM service_account_exchange_limits WHERE caller_instance=$1 FOR UPDATE",
    )
    .bind(caller)
    .fetch_one(&mut *transaction)
    .await
    .map_err(database("lock service-account rate limit"))?;
    let mut window_started_at: OffsetDateTime = row
        .try_get("window_started_at")
        .map_err(database("decode service-account rate window"))?;
    let mut attempts: i64 = row
        .try_get("attempts")
        .map_err(database("decode service-account rate attempts"))?;
    let locked_until: Option<OffsetDateTime> = row
        .try_get("locked_until")
        .map_err(database("decode service-account lockout"))?;
    if locked_until.is_some_and(|until| now < until) {
        transaction
            .commit()
            .await
            .map_err(database("commit active service-account lockout"))?;
        return Ok(false);
    }
    if now >= window_started_at + Duration::seconds(window_seconds) {
        window_started_at = now;
        attempts = 0;
    }
    if attempts >= max_attempts {
        sqlx::query(
            "UPDATE service_account_exchange_limits SET window_started_at=$2,locked_until=$3 WHERE caller_instance=$1",
        )
        .bind(caller)
        .bind(window_started_at)
        .bind(now + Duration::seconds(lockout_seconds))
        .execute(&mut *transaction)
        .await
        .map_err(database("lock out service-account caller"))?;
        transaction
            .commit()
            .await
            .map_err(database("commit service-account lockout"))?;
        return Ok(false);
    }
    sqlx::query(
        "UPDATE service_account_exchange_limits SET window_started_at=$2,attempts=$3,locked_until=NULL WHERE caller_instance=$1",
    )
    .bind(caller)
    .bind(window_started_at)
    .bind(attempts + 1)
    .execute(&mut *transaction)
    .await
    .map_err(database("consume service-account rate slot"))?;
    transaction
        .commit()
        .await
        .map_err(database("commit service-account rate admission"))?;
    Ok(true)
}

async fn lock_account(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    service_account_id: &str,
) -> Result<Option<AccountRow>, ServiceAccountPluginError> {
    let row = sqlx::query(
        "SELECT a.service_account_id,a.organization_id,a.subject,a.name,a.status,a.revision,a.created_at,a.rotated_at,a.revoked_at,(SELECT c.valid_until FROM service_account_credentials c WHERE c.service_account_id=a.service_account_id ORDER BY c.created_at DESC,c.credential_id DESC LIMIT 1) AS credential_expires_at FROM service_accounts a WHERE a.organization_id=$1 AND a.service_account_id=$2 FOR UPDATE OF a",
    )
    .bind(organization_id)
    .bind(service_account_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database("lock service account"))?;
    row.as_ref().map(decode_account).transpose()
}

async fn load_account_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    service_account_id: &str,
) -> Result<Option<AccountRow>, ServiceAccountPluginError> {
    let row = sqlx::query(
        "SELECT a.service_account_id,a.organization_id,a.subject,a.name,a.status,a.revision,a.created_at,a.rotated_at,a.revoked_at,(SELECT c.valid_until FROM service_account_credentials c WHERE c.service_account_id=a.service_account_id ORDER BY c.created_at DESC,c.credential_id DESC LIMIT 1) AS credential_expires_at FROM service_accounts a WHERE a.organization_id=$1 AND a.service_account_id=$2",
    )
    .bind(organization_id)
    .bind(service_account_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database("reload service account"))?;
    row.as_ref().map(decode_account).transpose()
}

fn decode_account(row: &sqlx::postgres::PgRow) -> Result<AccountRow, ServiceAccountPluginError> {
    Ok(AccountRow {
        service_account_id: row
            .try_get("service_account_id")
            .map_err(database("decode service-account id"))?,
        organization_id: row
            .try_get("organization_id")
            .map_err(database("decode service-account organization"))?,
        subject: row
            .try_get("subject")
            .map_err(database("decode service-account subject"))?,
        name: row
            .try_get("name")
            .map_err(database("decode service-account name"))?,
        status: row
            .try_get("status")
            .map_err(database("decode service-account status"))?,
        revision: row
            .try_get("revision")
            .map_err(database("decode service-account revision"))?,
        created_at: row
            .try_get("created_at")
            .map_err(database("decode service-account creation time"))?,
        rotated_at: row
            .try_get("rotated_at")
            .map_err(database("decode service-account rotation time"))?,
        revoked_at: row
            .try_get("revoked_at")
            .map_err(database("decode service-account revocation time"))?,
        credential_expires_at: row
            .try_get("credential_expires_at")
            .map_err(database("decode service-account credential expiry"))?,
    })
}

fn decode_credential(
    row: &sqlx::postgres::PgRow,
) -> Result<CredentialRow, ServiceAccountPluginError> {
    Ok(CredentialRow {
        credential_id: row
            .try_get("credential_id")
            .map_err(database("decode credential id"))?,
        service_account_id: row
            .try_get("service_account_id")
            .map_err(database("decode credential service account"))?,
        organization_id: row
            .try_get("organization_id")
            .map_err(database("decode credential organization"))?,
        subject: row
            .try_get("subject")
            .map_err(database("decode credential subject"))?,
        account_status: row
            .try_get("account_status")
            .map_err(database("decode credential account status"))?,
        verifier: row
            .try_get("verifier")
            .map_err(database("decode credential verifier"))?,
        valid_from: row
            .try_get("valid_from")
            .map_err(database("decode credential validity start"))?,
        valid_until: row
            .try_get("valid_until")
            .map_err(database("decode credential expiry"))?,
        revoked_at: row
            .try_get("revoked_at")
            .map_err(database("decode credential revocation"))?,
    })
}

pub(crate) fn database(
    operation: &'static str,
) -> impl FnOnce(sqlx::Error) -> ServiceAccountPluginError {
    move |source| ServiceAccountPluginError::Database { operation, source }
}

pub(crate) fn unique_constraint(error: &ServiceAccountPluginError) -> Option<&str> {
    match error {
        ServiceAccountPluginError::Database {
            source: sqlx::Error::Database(database),
            ..
        } if database.is_unique_violation() => database.constraint(),
        _ => None,
    }
}
