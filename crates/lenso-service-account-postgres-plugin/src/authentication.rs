use std::collections::BTreeMap;

use lenso_capability_credential_issuer::{
    CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_identity_directory::{
    DirectoryReadStatusInvocationError, ReadStatusRequest, ReadStatusResponseStatus,
};
use lenso_capability_service_account_auth::{
    EXCHANGE_SECRET_OPERATION, ExchangeSecretError, ExchangeServiceAccountSecretRequest,
    ExchangeServiceAccountSecretResponse, ServiceAccount,
};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use serde_json::Value;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    ServiceAccountPlugin, ServiceAccountPluginError,
    crypto::{credential_id, verify_secret},
    management::{format_time, receipt_aad, request_intent_hash, valid_idempotency_key},
    storage::{self, CommandClaim, CredentialRow},
};

#[allow(clippy::too_many_lines)]
pub(crate) fn exchange_secret(
    plugin: &ServiceAccountPlugin,
    context: InvocationContext,
    request: ExchangeServiceAccountSecretRequest,
) -> NativeRequestFuture<ServiceAccount> {
    let active = plugin.active();
    let directory = plugin.directory.clone();
    let issuer = plugin.issuer.clone();
    Box::pin(async move {
        let active = active?;
        let Some(caller) = context
            .caller_instance()
            .filter(|caller| {
                active
                    .config
                    .authentication_callers
                    .iter()
                    .any(|allowed| allowed == caller)
            })
            .map(str::to_owned)
        else {
            return Ok(Err(ExchangeSecretError::Forbidden));
        };
        if !valid_idempotency_key(&request.idempotency_key)
            || request.secret.is_empty()
            || request.secret.len() > 512
        {
            return Ok(Err(ExchangeSecretError::InvalidRequest));
        }
        storage::prune(
            &active.postgres,
            i64::try_from(active.config.receipt_ttl_seconds).expect("validated"),
        )
        .await
        .map_err(runtime)?;
        let intent = request_intent_hash(&request).map_err(runtime)?;
        let aad = receipt_aad(&caller, EXCHANGE_SECRET_OPERATION, &request.idempotency_key);
        match storage::claim_command(
            &active.postgres,
            &caller,
            EXCHANGE_SECRET_OPERATION,
            &request.idempotency_key,
            &intent,
        )
        .await
        .map_err(runtime)?
        {
            CommandClaim::Claimed => {}
            CommandClaim::CompletedSuccess { nonce, ciphertext } => {
                return Ok(Ok(active
                    .receipt_cipher
                    .decrypt(&nonce, &ciphertext, &aad)
                    .map_err(ServiceAccountPluginError::from)
                    .map_err(runtime)?));
            }
            CommandClaim::CompletedError(code) => {
                return Ok(Err(exchange_error(&code).map_err(runtime)?));
            }
            CommandClaim::Conflict => return Ok(Err(ExchangeSecretError::IdempotencyConflict)),
            CommandClaim::InProgress => return Ok(Err(ExchangeSecretError::OperationInProgress)),
        }

        let now = OffsetDateTime::now_utc();
        if !storage::reserve_rate_slot(
            &active.postgres,
            &caller,
            now,
            i64::try_from(active.config.exchange_window_seconds).expect("validated"),
            i64::from(active.config.max_exchanges_per_window),
            i64::try_from(active.config.exchange_lockout_seconds).expect("validated"),
        )
        .await
        .map_err(runtime)?
        {
            record_error(&active, &caller, &request.idempotency_key, "rate_limited").await?;
            return Ok(Err(ExchangeSecretError::RateLimited));
        }

        let candidate = credential_id(&request.secret);
        let credential = match candidate {
            Some(credential_id) => storage::load_credential(&active.postgres, credential_id)
                .await
                .map_err(runtime)?,
            None => None,
        };
        let verifier = credential
            .as_ref()
            .map_or(active.dummy_verifier.as_str(), |row| row.verifier.as_str());
        let secret_matches = verify_secret(&request.secret, &active.pepper, verifier);
        let credential = credential.filter(|row| {
            secret_matches
                && row.account_status == "active"
                && row.revoked_at.is_none()
                && row.valid_from <= now
                && now < row.valid_until
        });
        let Some(credential) = credential else {
            record_error(
                &active,
                &caller,
                &request.idempotency_key,
                "invalid_credentials",
            )
            .await?;
            return Ok(Err(ExchangeSecretError::InvalidCredentials));
        };

        match directory
            .read_status_with_context(
                context.clone(),
                ReadStatusRequest {
                    subject: credential.subject.clone(),
                },
            )
            .await
        {
            Ok(response)
                if response.subject == credential.subject
                    && response.status == ReadStatusResponseStatus::Active => {}
            Ok(response) if response.subject == credential.subject => {
                record_error(&active, &caller, &request.idempotency_key, "disabled").await?;
                return Ok(Err(ExchangeSecretError::Disabled));
            }
            Ok(_) => {
                return Err(failure(
                    "Identity Directory returned another subject for service-account status",
                ));
            }
            Err(DirectoryReadStatusInvocationError::Domain(
                lenso_capability_identity_directory::ReadStatusError::NotFound
                | lenso_capability_identity_directory::ReadStatusError::InvalidSubject,
            )) => {
                record_error(&active, &caller, &request.idempotency_key, "disabled").await?;
                return Ok(Err(ExchangeSecretError::Disabled));
            }
            Err(DirectoryReadStatusInvocationError::Domain(_)) => {
                return Err(failure(
                    "Identity Directory returned an unknown service-account status error",
                ));
            }
            Err(DirectoryReadStatusInvocationError::Runtime(error)) => return Err(error),
        }

        let Some(credential) = storage::mark_exchange_issuing(
            &active.postgres,
            &caller,
            &request.idempotency_key,
            &credential.credential_id,
            &credential.service_account_id,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(runtime)?
        else {
            record_error(
                &active,
                &caller,
                &request.idempotency_key,
                "invalid_credentials",
            )
            .await?;
            return Ok(Err(ExchangeSecretError::InvalidCredentials));
        };
        let now = OffsetDateTime::now_utc();
        let requested_expiry = now
            + Duration::seconds(i64::try_from(active.config.token_ttl_seconds).expect("validated"));
        let expires_at = requested_expiry.min(credential.valid_until);
        if expires_at <= now {
            record_error(
                &active,
                &caller,
                &request.idempotency_key,
                "invalid_credentials",
            )
            .await?;
            return Ok(Err(ExchangeSecretError::InvalidCredentials));
        }
        let mut claims = BTreeMap::new();
        claims.insert(
            "organization_id".to_owned(),
            Value::String(credential.organization_id.clone()),
        );
        claims.insert(
            "service_account_id".to_owned(),
            Value::String(credential.service_account_id.clone()),
        );
        let session = match issuer
            .issue_with_context(
                context,
                IssueRequest {
                    subject: credential.subject.clone(),
                    actor_kind: "service_account".to_owned(),
                    assurance: "service_account_secret".to_owned(),
                    audience: active.config.token_audience.clone(),
                    claims,
                    expires_at: format_time(expires_at).map_err(runtime)?,
                },
            )
            .await
        {
            Ok(session) => session,
            Err(CredentialIssuerIssueInvocationError::Domain(IssueError::Disabled)) => {
                record_error(&active, &caller, &request.idempotency_key, "disabled").await?;
                return Ok(Err(ExchangeSecretError::Disabled));
            }
            Err(CredentialIssuerIssueInvocationError::Domain(_)) => {
                // The Issuer v1.1 contract has no idempotency key. Once issuing begins, any
                // non-definitive outcome stays durably in `issuing`; replay fails closed.
                return Err(failure(
                    "Credential Issuer returned an indeterminate service-account result",
                ));
            }
            Err(CredentialIssuerIssueInvocationError::Runtime(error)) => return Err(error),
        };
        if session.session_id.is_empty()
            || session.session_id.len() > 256
            || session.credential.is_empty()
            || session.credential.len() > 65_536
        {
            return Err(failure(
                "Credential Issuer returned an invalid service-account credential",
            ));
        }
        let Ok(actual_expiry) = OffsetDateTime::parse(&session.expires_at, &Rfc3339) else {
            return Err(failure(
                "Credential Issuer returned an invalid service-account expiry",
            ));
        };
        if actual_expiry <= OffsetDateTime::now_utc() || actual_expiry > expires_at {
            return Err(failure(
                "Credential Issuer exceeded the bounded service-account expiry",
            ));
        }
        let response = response(
            &credential,
            session.session_id,
            session.credential,
            session.expires_at,
        );
        let (nonce, ciphertext) = active
            .receipt_cipher
            .encrypt(&response, &aad)
            .map_err(ServiceAccountPluginError::from)
            .map_err(runtime)?;
        storage::complete_success_owned(
            &active.postgres,
            &caller,
            EXCHANGE_SECRET_OPERATION,
            &request.idempotency_key,
            &nonce,
            &ciphertext,
        )
        .await
        .map_err(runtime)?;
        Ok(Ok(response))
    })
}

fn response(
    credential: &CredentialRow,
    session_id: String,
    token: String,
    expires_at: String,
) -> ExchangeServiceAccountSecretResponse {
    ExchangeServiceAccountSecretResponse {
        service_account_id: credential.service_account_id.clone(),
        organization_id: credential.organization_id.clone(),
        subject: credential.subject.clone(),
        session_id,
        credential: token,
        expires_at,
    }
}

async fn record_error(
    active: &crate::ActiveServiceAccount,
    caller: &str,
    idempotency_key: &str,
    code: &str,
) -> Result<(), RuntimeFailure> {
    storage::complete_error(
        &active.postgres,
        caller,
        EXCHANGE_SECRET_OPERATION,
        idempotency_key,
        code,
    )
    .await
    .map_err(runtime)
}

fn exchange_error(code: &str) -> Result<ExchangeSecretError, ServiceAccountPluginError> {
    match code {
        "invalid_credentials" => Ok(ExchangeSecretError::InvalidCredentials),
        "rate_limited" => Ok(ExchangeSecretError::RateLimited),
        "disabled" => Ok(ExchangeSecretError::Disabled),
        _ => Err(ServiceAccountPluginError::Invariant(
            "unknown exchange receipt error",
        )),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn runtime(error: ServiceAccountPluginError) -> RuntimeFailure {
    failure(error.to_string())
}

fn failure(detail: impl Into<String>) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: detail.into(),
    }
}
