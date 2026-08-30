use std::rc::Rc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso_capability_identity_directory::{
    DirectoryEnsureIdentityInvocationError, EnsureIdentityRequest,
};
use lenso_capability_service_account as capability;
use lenso_capability_service_account::{
    CREATE_OPERATION, CreateError, CreateServiceAccountRequest, CreateServiceAccountResponse,
    GET_OPERATION, GetError, GetServiceAccountRequest, GetServiceAccountResponse, LIST_OPERATION,
    ListError, ListServiceAccountsRequest, ListServiceAccountsResponse, REVOKE_OPERATION,
    ROTATE_SECRET_OPERATION, RevokeError, RevokeServiceAccountRequest,
    RevokeServiceAccountResponse, RotateSecretError, RotateServiceAccountSecretRequest,
    RotateServiceAccountSecretResponse, ServiceAccountCreate, ServiceAccountGet,
    ServiceAccountList, ServiceAccountRevoke, ServiceAccountRotateSecret, ServiceAccountStatus,
    ServiceAccountSummary,
};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    ActiveServiceAccount, ServiceAccountPlugin, ServiceAccountPluginError,
    authorization::{AuthorizationError, MANAGE_PERMISSION, READ_PERMISSION, authorize_management},
    crypto::CredentialSecret,
    storage::{self, AccountRow, CommandClaim, Mutation},
};

#[allow(clippy::too_many_lines)]
pub(crate) fn create(
    plugin: &ServiceAccountPlugin,
    context: InvocationContext,
    request: CreateServiceAccountRequest,
) -> NativeRequestFuture<ServiceAccountCreate> {
    let active = plugin.active();
    let membership = plugin.membership.clone();
    let access_control = plugin.access_control.clone();
    let directory = plugin.directory.clone();
    Box::pin(async move {
        let active = active?;
        if !valid_idempotency_key(&request.idempotency_key)
            || !valid_token(&request.organization_id, 256)
            || !valid_name(&request.name)
        {
            return Ok(Err(CreateError::InvalidRequest));
        }
        let authorization = match authorize_management(
            &active,
            &membership,
            &access_control,
            &context,
            capability::CAPABILITY_ID,
            CREATE_OPERATION,
            &request.organization_id,
            MANAGE_PERMISSION,
        )
        .await
        {
            Ok(authorization) => authorization,
            Err(error) => match map_create_authorization(error) {
                Ok(error) => return Ok(Err(error)),
                Err(error) => return Err(error),
            },
        };
        storage::prune(
            &active.postgres,
            i64::try_from(active.config.receipt_ttl_seconds).expect("validated"),
        )
        .await
        .map_err(runtime)?;
        let intent = actor_intent_hash(&authorization.actor_subject, &request).map_err(runtime)?;
        let aad = receipt_aad(
            &authorization.caller,
            CREATE_OPERATION,
            &request.idempotency_key,
        );
        match storage::claim_command(
            &active.postgres,
            &authorization.caller,
            CREATE_OPERATION,
            &request.idempotency_key,
            &intent,
        )
        .await
        .map_err(runtime)?
        {
            CommandClaim::Claimed => {}
            CommandClaim::CompletedSuccess { nonce, ciphertext } => {
                let mut response: CreateServiceAccountResponse = active
                    .receipt_cipher
                    .decrypt(&nonce, &ciphertext, &aad)
                    .map_err(ServiceAccountPluginError::from)
                    .map_err(runtime)?;
                response.created = false;
                response.secret = None;
                return Ok(Ok(response));
            }
            CommandClaim::CompletedError(code) => {
                return Ok(Err(create_error(&code).map_err(runtime)?));
            }
            CommandClaim::Conflict => return Ok(Err(CreateError::IdempotencyConflict)),
            CommandClaim::InProgress => return Ok(Err(CreateError::OperationInProgress)),
        }

        let service_account_id = random_id("sa_").map_err(runtime)?;
        let external_subject = format!("{}:{service_account_id}", request.organization_id);
        let identity = match directory
            .ensure_identity_with_context(
                context,
                EnsureIdentityRequest {
                    provider: active.config.directory_provider.clone(),
                    external_subject,
                },
            )
            .await
        {
            Ok(identity) if valid_token(&identity.subject, 256) => identity,
            Ok(_) | Err(DirectoryEnsureIdentityInvocationError::Domain(_)) => {
                storage::complete_error(
                    &active.postgres,
                    &authorization.caller,
                    CREATE_OPERATION,
                    &request.idempotency_key,
                    "directory_rejected",
                )
                .await
                .map_err(runtime)?;
                return Ok(Err(CreateError::DirectoryRejected));
            }
            Err(DirectoryEnsureIdentityInvocationError::Runtime(error)) => return Err(error),
        };
        let credential = CredentialSecret::generate()
            .map_err(ServiceAccountPluginError::from)
            .map_err(runtime)?;
        let verifier = credential
            .verifier(&active.pepper)
            .map_err(ServiceAccountPluginError::from)
            .map_err(runtime)?;
        let now = OffsetDateTime::now_utc();
        let valid_until = now
            + Duration::seconds(
                i64::try_from(active.config.credential_ttl_seconds).expect("validated"),
            );
        let name = request.name.trim().to_owned();
        let name_key = name.to_ascii_lowercase();
        let receipt_cipher = active.receipt_cipher.clone();
        let receipt_aad = aad.clone();
        let created = storage::create_account(
            &active.postgres,
            &authorization.caller,
            CREATE_OPERATION,
            &request.idempotency_key,
            i64::from(active.config.max_accounts_per_organization),
            &service_account_id,
            &request.organization_id,
            &identity.subject,
            &name,
            &name_key,
            &credential.credential_id,
            &verifier,
            now,
            valid_until,
            move |row| {
                receipt_cipher
                    .encrypt(
                        &CreateServiceAccountResponse {
                            account: summary(row)?,
                            created: true,
                            secret: None,
                        },
                        &receipt_aad,
                    )
                    .map_err(ServiceAccountPluginError::from)
            },
        )
        .await;
        let row = match created {
            Ok(Some(row)) => row,
            Ok(None) => {
                record_create_error(
                    &active,
                    &authorization.caller,
                    &request.idempotency_key,
                    "too_many_service_accounts",
                )
                .await?;
                return Ok(Err(CreateError::TooManyServiceAccounts));
            }
            Err(error)
                if storage::unique_constraint(&error)
                    == Some("service_accounts_organization_name_unique") =>
            {
                record_create_error(
                    &active,
                    &authorization.caller,
                    &request.idempotency_key,
                    "name_conflict",
                )
                .await?;
                return Ok(Err(CreateError::NameConflict));
            }
            Err(error)
                if storage::unique_constraint(&error)
                    == Some("service_accounts_subject_unique") =>
            {
                record_create_error(
                    &active,
                    &authorization.caller,
                    &request.idempotency_key,
                    "directory_rejected",
                )
                .await?;
                return Ok(Err(CreateError::DirectoryRejected));
            }
            Err(error) => return Err(runtime(error)),
        };
        Ok(Ok(CreateServiceAccountResponse {
            account: summary(&row).map_err(runtime)?,
            created: true,
            secret: Some(credential.expose()),
        }))
    })
}

pub(crate) fn get(
    plugin: &ServiceAccountPlugin,
    context: InvocationContext,
    request: GetServiceAccountRequest,
) -> NativeRequestFuture<ServiceAccountGet> {
    let active = plugin.active();
    let membership = plugin.membership.clone();
    let access_control = plugin.access_control.clone();
    Box::pin(async move {
        let active = active?;
        if !valid_token(&request.organization_id, 256)
            || !valid_token(&request.service_account_id, 128)
        {
            return Ok(Err(GetError::InvalidRequest));
        }
        match authorize_management(
            &active,
            &membership,
            &access_control,
            &context,
            capability::CAPABILITY_ID,
            GET_OPERATION,
            &request.organization_id,
            READ_PERMISSION,
        )
        .await
        {
            Ok(_) => {}
            Err(error) => match map_get_authorization(error) {
                Ok(error) => return Ok(Err(error)),
                Err(error) => return Err(error),
            },
        }
        let Some(row) = storage::load_account(
            &active.postgres,
            &request.organization_id,
            &request.service_account_id,
        )
        .await
        .map_err(runtime)?
        else {
            return Ok(Err(GetError::NotFound));
        };
        Ok(Ok(GetServiceAccountResponse {
            account: summary(&row).map_err(runtime)?,
        }))
    })
}

pub(crate) fn list(
    plugin: &ServiceAccountPlugin,
    context: InvocationContext,
    request: ListServiceAccountsRequest,
) -> NativeRequestFuture<ServiceAccountList> {
    let active = plugin.active();
    let membership = plugin.membership.clone();
    let access_control = plugin.access_control.clone();
    Box::pin(async move {
        let active = active?;
        let Some(limit) = parse_page_limit(&request.limit, active.config.max_page_size) else {
            return Ok(Err(ListError::InvalidRequest));
        };
        if !valid_token(&request.organization_id, 256)
            || request
                .after
                .as_deref()
                .is_some_and(|cursor| !valid_token(cursor, 128))
        {
            return Ok(Err(ListError::InvalidRequest));
        }
        match authorize_management(
            &active,
            &membership,
            &access_control,
            &context,
            capability::CAPABILITY_ID,
            LIST_OPERATION,
            &request.organization_id,
            READ_PERMISSION,
        )
        .await
        {
            Ok(_) => {}
            Err(error) => match map_list_authorization(error) {
                Ok(error) => return Ok(Err(error)),
                Err(error) => return Err(error),
            },
        }
        let mut rows = storage::list_accounts(
            &active.postgres,
            &request.organization_id,
            request.after.as_deref(),
            i64::from(limit) + 1,
        )
        .await
        .map_err(runtime)?;
        let has_more = rows.len() > usize::try_from(limit).expect("small page size");
        rows.truncate(usize::try_from(limit).expect("small page size"));
        let next_cursor = has_more
            .then(|| rows.last().map(|row| row.service_account_id.clone()))
            .flatten();
        let accounts = rows
            .iter()
            .map(summary)
            .collect::<Result<Vec<_>, _>>()
            .map_err(runtime)?;
        Ok(Ok(ListServiceAccountsResponse {
            accounts,
            next_cursor,
        }))
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn rotate_secret(
    plugin: &ServiceAccountPlugin,
    context: InvocationContext,
    request: RotateServiceAccountSecretRequest,
) -> NativeRequestFuture<ServiceAccountRotateSecret> {
    let active = plugin.active();
    let membership = plugin.membership.clone();
    let access_control = plugin.access_control.clone();
    Box::pin(async move {
        let active = active?;
        let Some(expected_revision) = valid_rotation(&request) else {
            return Ok(Err(RotateSecretError::InvalidRequest));
        };
        let authorization = match authorize_management(
            &active,
            &membership,
            &access_control,
            &context,
            capability::CAPABILITY_ID,
            ROTATE_SECRET_OPERATION,
            &request.organization_id,
            MANAGE_PERMISSION,
        )
        .await
        {
            Ok(authorization) => authorization,
            Err(error) => match map_rotate_authorization(error) {
                Ok(error) => return Ok(Err(error)),
                Err(error) => return Err(error),
            },
        };
        storage::prune(
            &active.postgres,
            i64::try_from(active.config.receipt_ttl_seconds).expect("validated"),
        )
        .await
        .map_err(runtime)?;
        let intent = actor_intent_hash(&authorization.actor_subject, &request).map_err(runtime)?;
        let aad = receipt_aad(
            &authorization.caller,
            ROTATE_SECRET_OPERATION,
            &request.idempotency_key,
        );
        match storage::claim_command(
            &active.postgres,
            &authorization.caller,
            ROTATE_SECRET_OPERATION,
            &request.idempotency_key,
            &intent,
        )
        .await
        .map_err(runtime)?
        {
            CommandClaim::Claimed => {}
            CommandClaim::CompletedSuccess { nonce, ciphertext } => {
                let mut response: RotateServiceAccountSecretResponse = active
                    .receipt_cipher
                    .decrypt(&nonce, &ciphertext, &aad)
                    .map_err(ServiceAccountPluginError::from)
                    .map_err(runtime)?;
                response.rotated = false;
                response.secret = None;
                return Ok(Ok(response));
            }
            CommandClaim::CompletedError(code) => {
                return Ok(Err(rotate_error(&code).map_err(runtime)?));
            }
            CommandClaim::Conflict => return Ok(Err(RotateSecretError::IdempotencyConflict)),
            CommandClaim::InProgress => return Ok(Err(RotateSecretError::OperationInProgress)),
        }
        let credential = CredentialSecret::generate()
            .map_err(ServiceAccountPluginError::from)
            .map_err(runtime)?;
        let verifier = credential
            .verifier(&active.pepper)
            .map_err(ServiceAccountPluginError::from)
            .map_err(runtime)?;
        let now = OffsetDateTime::now_utc();
        let overlap_until = now
            + Duration::seconds(
                i64::try_from(active.config.rotation_overlap_seconds).expect("validated"),
            );
        let valid_until = now
            + Duration::seconds(
                i64::try_from(active.config.credential_ttl_seconds).expect("validated"),
            );
        let receipt_cipher = active.receipt_cipher.clone();
        let receipt_aad = aad.clone();
        let result = storage::rotate_account(
            &active.postgres,
            &authorization.caller,
            ROTATE_SECRET_OPERATION,
            &request.idempotency_key,
            &request.organization_id,
            &request.service_account_id,
            expected_revision,
            &credential.credential_id,
            &verifier,
            now,
            overlap_until,
            valid_until,
            move |row| {
                receipt_cipher
                    .encrypt(
                        &RotateServiceAccountSecretResponse {
                            account: summary(row)?,
                            rotated: true,
                            secret: None,
                        },
                        &receipt_aad,
                    )
                    .map_err(ServiceAccountPluginError::from)
            },
        )
        .await
        .map_err(runtime)?;
        let row = match result {
            Mutation::Updated(row) => row,
            Mutation::NotFound => {
                record_rotate_error(&active, &authorization.caller, &request, "not_found").await?;
                return Ok(Err(RotateSecretError::NotFound));
            }
            Mutation::Revoked => {
                record_rotate_error(&active, &authorization.caller, &request, "revoked").await?;
                return Ok(Err(RotateSecretError::Revoked));
            }
            Mutation::RevisionConflict => {
                record_rotate_error(
                    &active,
                    &authorization.caller,
                    &request,
                    "revision_conflict",
                )
                .await?;
                return Ok(Err(RotateSecretError::RevisionConflict));
            }
        };
        Ok(Ok(RotateServiceAccountSecretResponse {
            account: summary(&row).map_err(runtime)?,
            rotated: true,
            secret: Some(credential.expose()),
        }))
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn revoke(
    plugin: &ServiceAccountPlugin,
    context: InvocationContext,
    request: RevokeServiceAccountRequest,
) -> NativeRequestFuture<ServiceAccountRevoke> {
    let active = plugin.active();
    let membership = plugin.membership.clone();
    let access_control = plugin.access_control.clone();
    Box::pin(async move {
        let active = active?;
        let Some(expected_revision) = valid_revocation(&request) else {
            return Ok(Err(RevokeError::InvalidRequest));
        };
        let authorization = match authorize_management(
            &active,
            &membership,
            &access_control,
            &context,
            capability::CAPABILITY_ID,
            REVOKE_OPERATION,
            &request.organization_id,
            MANAGE_PERMISSION,
        )
        .await
        {
            Ok(authorization) => authorization,
            Err(error) => match map_revoke_authorization(error) {
                Ok(error) => return Ok(Err(error)),
                Err(error) => return Err(error),
            },
        };
        storage::prune(
            &active.postgres,
            i64::try_from(active.config.receipt_ttl_seconds).expect("validated"),
        )
        .await
        .map_err(runtime)?;
        let intent = actor_intent_hash(&authorization.actor_subject, &request).map_err(runtime)?;
        let aad = receipt_aad(
            &authorization.caller,
            REVOKE_OPERATION,
            &request.idempotency_key,
        );
        match storage::claim_command(
            &active.postgres,
            &authorization.caller,
            REVOKE_OPERATION,
            &request.idempotency_key,
            &intent,
        )
        .await
        .map_err(runtime)?
        {
            CommandClaim::Claimed => {}
            CommandClaim::CompletedSuccess { nonce, ciphertext } => {
                let mut response: RevokeServiceAccountResponse = active
                    .receipt_cipher
                    .decrypt(&nonce, &ciphertext, &aad)
                    .map_err(ServiceAccountPluginError::from)
                    .map_err(runtime)?;
                response.revoked = false;
                return Ok(Ok(response));
            }
            CommandClaim::CompletedError(code) => {
                return Ok(Err(revoke_error(&code).map_err(runtime)?));
            }
            CommandClaim::Conflict => return Ok(Err(RevokeError::IdempotencyConflict)),
            CommandClaim::InProgress => return Ok(Err(RevokeError::OperationInProgress)),
        }
        let receipt_cipher = active.receipt_cipher.clone();
        let receipt_aad = aad.clone();
        let result = storage::revoke_account(
            &active.postgres,
            &authorization.caller,
            REVOKE_OPERATION,
            &request.idempotency_key,
            &request.organization_id,
            &request.service_account_id,
            expected_revision,
            move |(row, changed)| {
                receipt_cipher
                    .encrypt(
                        &RevokeServiceAccountResponse {
                            account: summary(row)?,
                            revoked: *changed,
                        },
                        &receipt_aad,
                    )
                    .map_err(ServiceAccountPluginError::from)
            },
        )
        .await
        .map_err(runtime)?;
        let (row, changed) = match result {
            Mutation::Updated(value) => value,
            Mutation::NotFound => {
                record_revoke_error(&active, &authorization.caller, &request, "not_found").await?;
                return Ok(Err(RevokeError::NotFound));
            }
            Mutation::RevisionConflict => {
                record_revoke_error(
                    &active,
                    &authorization.caller,
                    &request,
                    "revision_conflict",
                )
                .await?;
                return Ok(Err(RevokeError::RevisionConflict));
            }
            Mutation::Revoked => {
                return Err(runtime(ServiceAccountPluginError::Invariant(
                    "revocation returned an impossible state",
                )));
            }
        };
        Ok(Ok(RevokeServiceAccountResponse {
            account: summary(&row).map_err(runtime)?,
            revoked: changed,
        }))
    })
}

fn summary(row: &AccountRow) -> Result<ServiceAccountSummary, ServiceAccountPluginError> {
    Ok(ServiceAccountSummary {
        service_account_id: row.service_account_id.clone(),
        organization_id: row.organization_id.clone(),
        subject: row.subject.clone(),
        name: row.name.clone(),
        status: match row.status.as_str() {
            "active" => ServiceAccountStatus::Active,
            "revoked" => ServiceAccountStatus::Revoked,
            _ => {
                return Err(ServiceAccountPluginError::Invariant(
                    "unknown service-account status",
                ));
            }
        },
        revision: row.revision.to_string(),
        created_at: format_time(row.created_at)?,
        rotated_at: row.rotated_at.map(format_time).transpose()?,
        revoked_at: row.revoked_at.map(format_time).transpose()?,
        credential_expires_at: row.credential_expires_at.map(format_time).transpose()?,
    })
}

async fn record_create_error(
    active: &Rc<ActiveServiceAccount>,
    caller: &str,
    idempotency_key: &str,
    code: &str,
) -> Result<(), RuntimeFailure> {
    storage::complete_error(
        &active.postgres,
        caller,
        CREATE_OPERATION,
        idempotency_key,
        code,
    )
    .await
    .map_err(runtime)
}

async fn record_rotate_error(
    active: &Rc<ActiveServiceAccount>,
    caller: &str,
    request: &RotateServiceAccountSecretRequest,
    code: &str,
) -> Result<(), RuntimeFailure> {
    storage::complete_error(
        &active.postgres,
        caller,
        ROTATE_SECRET_OPERATION,
        &request.idempotency_key,
        code,
    )
    .await
    .map_err(runtime)
}

async fn record_revoke_error(
    active: &Rc<ActiveServiceAccount>,
    caller: &str,
    request: &RevokeServiceAccountRequest,
    code: &str,
) -> Result<(), RuntimeFailure> {
    storage::complete_error(
        &active.postgres,
        caller,
        REVOKE_OPERATION,
        &request.idempotency_key,
        code,
    )
    .await
    .map_err(runtime)
}

fn valid_rotation(request: &RotateServiceAccountSecretRequest) -> Option<i64> {
    let revision = parse_revision(&request.expected_revision)?;
    (valid_idempotency_key(&request.idempotency_key)
        && valid_token(&request.organization_id, 256)
        && valid_token(&request.service_account_id, 128))
    .then_some(revision)
}

fn valid_revocation(request: &RevokeServiceAccountRequest) -> Option<i64> {
    let revision = parse_revision(&request.expected_revision)?;
    (valid_idempotency_key(&request.idempotency_key)
        && valid_token(&request.organization_id, 256)
        && valid_token(&request.service_account_id, 128))
    .then_some(revision)
}

pub(crate) fn valid_idempotency_key(value: &str) -> bool {
    valid_token(value, 128)
}

pub(crate) fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_name(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| !character.is_control() && character.is_ascii())
}

fn parse_revision(value: &str) -> Option<i64> {
    value
        .parse::<i64>()
        .ok()
        .filter(|revision| *revision > 0 && revision.to_string() == value)
}

fn parse_page_limit(value: &str, max: u32) -> Option<u32> {
    value
        .parse::<u32>()
        .ok()
        .filter(|limit| *limit > 0 && *limit <= max && limit.to_string() == value)
}

pub(crate) fn actor_intent_hash<T: Serialize>(
    actor: &str,
    request: &T,
) -> Result<[u8; 32], ServiceAccountPluginError> {
    let bytes = serde_json::to_vec(&(actor, request))
        .map_err(ServiceAccountPluginError::SerializeReceipt)?;
    Ok(digest(&bytes))
}

pub(crate) fn request_intent_hash<T: Serialize>(
    request: &T,
) -> Result<[u8; 32], ServiceAccountPluginError> {
    let bytes = serde_json::to_vec(request).map_err(ServiceAccountPluginError::SerializeReceipt)?;
    Ok(digest(&bytes))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut result = [0_u8; 32];
    result.copy_from_slice(&digest);
    result
}

pub(crate) fn receipt_aad(caller: &str, operation: &str, idempotency_key: &str) -> Vec<u8> {
    format!("{caller}\0{operation}\0{idempotency_key}").into_bytes()
}

fn random_id(prefix: &str) -> Result<String, ServiceAccountPluginError> {
    let mut bytes = [0_u8; 24];
    getrandom::fill(&mut bytes).map_err(ServiceAccountPluginError::Random)?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

pub(crate) fn format_time(value: OffsetDateTime) -> Result<String, ServiceAccountPluginError> {
    value
        .format(&Rfc3339)
        .map_err(ServiceAccountPluginError::FormatTime)
}

fn map_create_authorization(error: AuthorizationError) -> Result<CreateError, RuntimeFailure> {
    map_authorization(error).map(|error| match error {
        AuthorizationDomain::Forbidden => CreateError::Forbidden,
        AuthorizationDomain::OrganizationNotFound => CreateError::OrganizationNotFound,
        AuthorizationDomain::MembershipRequired => CreateError::MembershipRequired,
        AuthorizationDomain::AccessDenied => CreateError::AccessDenied,
    })
}

fn map_get_authorization(error: AuthorizationError) -> Result<GetError, RuntimeFailure> {
    map_authorization(error).map(|error| match error {
        AuthorizationDomain::Forbidden => GetError::Forbidden,
        AuthorizationDomain::OrganizationNotFound => GetError::OrganizationNotFound,
        AuthorizationDomain::MembershipRequired => GetError::MembershipRequired,
        AuthorizationDomain::AccessDenied => GetError::AccessDenied,
    })
}

fn map_list_authorization(error: AuthorizationError) -> Result<ListError, RuntimeFailure> {
    map_authorization(error).map(|error| match error {
        AuthorizationDomain::Forbidden => ListError::Forbidden,
        AuthorizationDomain::OrganizationNotFound => ListError::OrganizationNotFound,
        AuthorizationDomain::MembershipRequired => ListError::MembershipRequired,
        AuthorizationDomain::AccessDenied => ListError::AccessDenied,
    })
}

fn map_rotate_authorization(
    error: AuthorizationError,
) -> Result<RotateSecretError, RuntimeFailure> {
    map_authorization(error).map(|error| match error {
        AuthorizationDomain::Forbidden => RotateSecretError::Forbidden,
        AuthorizationDomain::OrganizationNotFound => RotateSecretError::OrganizationNotFound,
        AuthorizationDomain::MembershipRequired => RotateSecretError::MembershipRequired,
        AuthorizationDomain::AccessDenied => RotateSecretError::AccessDenied,
    })
}

fn map_revoke_authorization(error: AuthorizationError) -> Result<RevokeError, RuntimeFailure> {
    map_authorization(error).map(|error| match error {
        AuthorizationDomain::Forbidden => RevokeError::Forbidden,
        AuthorizationDomain::OrganizationNotFound => RevokeError::OrganizationNotFound,
        AuthorizationDomain::MembershipRequired => RevokeError::MembershipRequired,
        AuthorizationDomain::AccessDenied => RevokeError::AccessDenied,
    })
}

enum AuthorizationDomain {
    Forbidden,
    OrganizationNotFound,
    MembershipRequired,
    AccessDenied,
}

fn map_authorization(error: AuthorizationError) -> Result<AuthorizationDomain, RuntimeFailure> {
    match error {
        AuthorizationError::Forbidden => Ok(AuthorizationDomain::Forbidden),
        AuthorizationError::OrganizationNotFound => Ok(AuthorizationDomain::OrganizationNotFound),
        AuthorizationError::MembershipRequired => Ok(AuthorizationDomain::MembershipRequired),
        AuthorizationError::AccessDenied => Ok(AuthorizationDomain::AccessDenied),
        AuthorizationError::Runtime(error) => Err(error),
    }
}

fn create_error(code: &str) -> Result<CreateError, ServiceAccountPluginError> {
    match code {
        "name_conflict" => Ok(CreateError::NameConflict),
        "directory_rejected" => Ok(CreateError::DirectoryRejected),
        "too_many_service_accounts" => Ok(CreateError::TooManyServiceAccounts),
        _ => Err(ServiceAccountPluginError::Invariant(
            "unknown create receipt error",
        )),
    }
}

fn rotate_error(code: &str) -> Result<RotateSecretError, ServiceAccountPluginError> {
    match code {
        "not_found" => Ok(RotateSecretError::NotFound),
        "revoked" => Ok(RotateSecretError::Revoked),
        "revision_conflict" => Ok(RotateSecretError::RevisionConflict),
        _ => Err(ServiceAccountPluginError::Invariant(
            "unknown rotate receipt error",
        )),
    }
}

fn revoke_error(code: &str) -> Result<RevokeError, ServiceAccountPluginError> {
    match code {
        "not_found" => Ok(RevokeError::NotFound),
        "revision_conflict" => Ok(RevokeError::RevisionConflict),
        _ => Err(ServiceAccountPluginError::Invariant(
            "unknown revoke receipt error",
        )),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn runtime(error: ServiceAccountPluginError) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    }
}
