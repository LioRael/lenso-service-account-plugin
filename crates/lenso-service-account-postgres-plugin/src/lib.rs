//! PostgreSQL-backed organization Service Accounts for Lenso.

mod authentication;
mod authorization;
mod crypto;
mod management;
mod operator;
mod schema;
mod storage;

#[cfg(test)]
mod postgres_tests;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration as StdDuration};

use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port};
use lenso_auth_sdk::ActorAssertionVerifier;
use lenso_capability_access_control as access_control;
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_identity_directory as directory;
use lenso_capability_organization_membership as membership;
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_capability_service_account as management_capability;
use lenso_capability_service_account_auth as authentication_capability;
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    crypto::{CryptoError, ReceiptCipher, hash_secret},
    schema::schema_plan,
};

pub use operator::{ServiceAccountOperator, ServiceAccountOperatorError};

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccountConfig {
    schema: String,
    database_url_secret: String,
    credential_pepper_secret: String,
    receipt_encryption_key_secret: String,
    directory_provider: String,
    auth_issuer: String,
    auth_public_key: String,
    management_callers: Vec<String>,
    authentication_callers: Vec<String>,
    token_audience: Vec<String>,
    credential_ttl_seconds: u64,
    rotation_overlap_seconds: u64,
    token_ttl_seconds: u64,
    receipt_ttl_seconds: u64,
    exchange_window_seconds: u64,
    max_exchanges_per_window: u32,
    exchange_lockout_seconds: u64,
    max_page_size: u32,
    max_accounts_per_organization: u32,
}

impl ServiceAccountConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        credential_pepper_secret: impl Into<String>,
        receipt_encryption_key_secret: impl Into<String>,
        directory_provider: impl Into<String>,
        auth_issuer: impl Into<String>,
        auth_public_key: impl Into<String>,
        management_callers: Vec<String>,
        authentication_callers: Vec<String>,
        token_audience: Vec<String>,
        credential_ttl_seconds: u64,
        rotation_overlap_seconds: u64,
        token_ttl_seconds: u64,
        receipt_ttl_seconds: u64,
        exchange_window_seconds: u64,
        max_exchanges_per_window: u32,
        exchange_lockout_seconds: u64,
        max_page_size: u32,
        max_accounts_per_organization: u32,
    ) -> Result<Self, ServiceAccountConfigError> {
        let value = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            credential_pepper_secret: credential_pepper_secret.into(),
            receipt_encryption_key_secret: receipt_encryption_key_secret.into(),
            directory_provider: directory_provider.into(),
            auth_issuer: auth_issuer.into(),
            auth_public_key: auth_public_key.into(),
            management_callers,
            authentication_callers,
            token_audience,
            credential_ttl_seconds,
            rotation_overlap_seconds,
            token_ttl_seconds,
            receipt_ttl_seconds,
            exchange_window_seconds,
            max_exchanges_per_window,
            exchange_lockout_seconds,
            max_page_size,
            max_accounts_per_organization,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ServiceAccountConfigError> {
        schema_plan(self.schema.clone()).map_err(|_| ServiceAccountConfigError::InvalidSchema)?;
        let secret_references = [
            &self.database_url_secret,
            &self.credential_pepper_secret,
            &self.receipt_encryption_key_secret,
        ];
        if secret_references
            .iter()
            .any(|reference| !valid_secret_reference(reference))
            || secret_references.iter().collect::<BTreeSet<_>>().len() != secret_references.len()
        {
            return Err(ServiceAccountConfigError::InvalidSecretReferences);
        }
        if !valid_authority(&self.directory_provider, 128)
            || !valid_authority(&self.auth_issuer, 128)
        {
            return Err(ServiceAccountConfigError::InvalidAuthorities);
        }
        if self.auth_public_key.is_empty() || self.auth_public_key.len() > 256 {
            return Err(ServiceAccountConfigError::InvalidAuthPublicKey);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_public_key,
        )
        .map_err(|_| ServiceAccountConfigError::InvalidAuthPublicKey)?;
        validate_authority_set(&self.management_callers, 128)?;
        validate_authority_set(&self.authentication_callers, 128)?;
        validate_authority_set(&self.token_audience, 256)?;
        if !(300..=31_536_000).contains(&self.credential_ttl_seconds)
            || self.rotation_overlap_seconds > 3_600
            || self.rotation_overlap_seconds >= self.credential_ttl_seconds
            || !(1..=86_400).contains(&self.token_ttl_seconds)
            || self.token_ttl_seconds > self.credential_ttl_seconds
            || !(300..=604_800).contains(&self.receipt_ttl_seconds)
            || !(1..=3_600).contains(&self.exchange_window_seconds)
            || !(1..=10_000).contains(&self.max_exchanges_per_window)
            || !(1..=86_400).contains(&self.exchange_lockout_seconds)
            || !(1..=200).contains(&self.max_page_size)
            || !(1..=10_000).contains(&self.max_accounts_per_organization)
        {
            return Err(ServiceAccountConfigError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceAccountConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("database, credential pepper, and receipt encryption need distinct secret references")]
    InvalidSecretReferences,
    #[error("invalid Identity Directory provider or Auth issuer")]
    InvalidAuthorities,
    #[error("invalid Auth actor assertion public key")]
    InvalidAuthPublicKey,
    #[error("caller or audience sets must contain unique exact Instance keys")]
    InvalidAuthoritySet,
    #[error("invalid credential, token, receipt, rate, page, or organization limit")]
    InvalidLimits,
}

fn validate_config(config: &ServiceAccountConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Service Account configuration is invalid: {error}"),
        })
}

struct ActiveServiceAccount {
    postgres: OwnedPostgres,
    config: ServiceAccountConfig,
    pepper: Zeroizing<Vec<u8>>,
    receipt_cipher: ReceiptCipher,
    actor_verifier: ActorAssertionVerifier,
    dummy_verifier: String,
}

impl fmt::Debug for ActiveServiceAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveServiceAccount")
            .field("schema", &self.postgres.schema())
            .field("directory_provider", &self.config.directory_provider)
            .field("pepper", &"<redacted>")
            .field("receipt_cipher", &self.receipt_cipher)
            .field("dummy_verifier", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct ServiceAccountPlugin {
    #[config]
    config: ServiceAccountConfig,
    secrets: Port<secrets::SecretsClient>,
    directory: Port<directory::DirectoryClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
    membership: Port<membership::OrganizationMembershipClient>,
    access_control: Port<access_control::AccessControlClient>,
    postgres: Rc<RefCell<Option<OwnedPostgres>>>,
    active: Rc<RefCell<Option<Rc<ActiveServiceAccount>>>>,
}

impl fmt::Debug for ServiceAccountPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceAccountPlugin")
            .field("active", &self.active.borrow().is_some())
            .field(
                "management_caller_count",
                &self.config.management_callers.len(),
            )
            .field(
                "authentication_caller_count",
                &self.config.authentication_callers.len(),
            )
            .finish_non_exhaustive()
    }
}

// Both roles are intentionally named `ServiceAccount`; separate modules keep the generated
// native lowering support aliases scoped apart until codegen can disambiguate equal role names.
mod management_provider {
    #[allow(clippy::wildcard_imports)]
    use super::*;

    #[lenso::provides(management_capability::ServiceAccount)]
    impl ServiceAccountPlugin {}
}

mod authentication_provider {
    #[allow(clippy::wildcard_imports)]
    use super::*;

    #[lenso::provides(authentication_capability::ServiceAccount)]
    impl ServiceAccountPlugin {}
}

impl ServiceAccountPlugin {
    fn active(&self) -> Result<Rc<ActiveServiceAccount>, RuntimeFailure> {
        self.active
            .borrow()
            .clone()
            .ok_or_else(|| failure("Service Account Plugin is not active"))
    }

    fn create(
        &self,
        context: InvocationContext,
        request: management_capability::CreateServiceAccountRequest,
    ) -> NativeRequestFuture<management_capability::ServiceAccountCreate> {
        management::create(self, context, request)
    }

    fn get(
        &self,
        context: InvocationContext,
        request: management_capability::GetServiceAccountRequest,
    ) -> NativeRequestFuture<management_capability::ServiceAccountGet> {
        management::get(self, context, request)
    }

    fn list(
        &self,
        context: InvocationContext,
        request: management_capability::ListServiceAccountsRequest,
    ) -> NativeRequestFuture<management_capability::ServiceAccountList> {
        management::list(self, context, request)
    }

    fn rotate_secret(
        &self,
        context: InvocationContext,
        request: management_capability::RotateServiceAccountSecretRequest,
    ) -> NativeRequestFuture<management_capability::ServiceAccountRotateSecret> {
        management::rotate_secret(self, context, request)
    }

    fn revoke(
        &self,
        context: InvocationContext,
        request: management_capability::RevokeServiceAccountRequest,
    ) -> NativeRequestFuture<management_capability::ServiceAccountRevoke> {
        management::revoke(self, context, request)
    }

    fn exchange_secret(
        &self,
        context: InvocationContext,
        request: authentication_capability::ExchangeServiceAccountSecretRequest,
    ) -> NativeRequestFuture<authentication_capability::ServiceAccount> {
        authentication::exchange_secret(self, context, request)
    }
}

#[derive(Debug, Error)]
enum ServiceAccountPluginError {
    #[error("{operation}: {source}")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("failed to generate secure random material: {0}")]
    Random(getrandom::Error),
    #[error("failed to serialize idempotency intent: {0}")]
    SerializeReceipt(serde_json::Error),
    #[error("failed to format UTC timestamp: {0}")]
    FormatTime(time::error::Format),
    #[error("Plugin invariant failed: {0}")]
    Invariant(&'static str),
}

impl Lifecycle for ServiceAccountPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let database_url = self
            .secrets
            .resolve_with_context(
                dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation.clone())?,
                ResolveRequest {
                    reference: config.database_url_secret.clone(),
                },
            )
            .await
            .map(|value| Zeroizing::new(value.value))
            .map_err(|error| secret_error(error, "database URL"))?;
        let pepper = self
            .secrets
            .resolve_with_context(
                dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation.clone())?,
                ResolveRequest {
                    reference: config.credential_pepper_secret.clone(),
                },
            )
            .await
            .map(|value| Zeroizing::new(value.value.into_bytes()))
            .map_err(|error| secret_error(error, "credential pepper"))?;
        let receipt_key = self
            .secrets
            .resolve_with_context(
                dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?,
                ResolveRequest {
                    reference: config.receipt_encryption_key_secret.clone(),
                },
            )
            .await
            .map(|value| Zeroizing::new(value.value))
            .map_err(|error| secret_error(error, "receipt encryption key"))?;
        if pepper.len() < 32 || receipt_key.len() < 32 {
            return Err(failure(
                "Service Account pepper and receipt encryption key must each contain at least 32 bytes",
            ));
        }
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema_plan(config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| failure(error.to_string()))?;
        let actor_verifier = ActorAssertionVerifier::from_public_key_base64(
            config.auth_issuer.clone(),
            &config.auth_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "invalid Service Account Auth verification key".to_owned(),
        })?;
        let dummy_verifier = hash_secret("invalid service-account credential", &pepper)
            .map_err(ServiceAccountPluginError::from)
            .map_err(runtime)?;
        let receipt_cipher = ReceiptCipher::derive(receipt_key.as_bytes());
        self.postgres.replace(Some(postgres.clone()));
        self.active.replace(Some(Rc::new(ActiveServiceAccount {
            postgres,
            config,
            pepper,
            receipt_cipher,
            actor_verifier,
            dummy_verifier,
        })));
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.active.borrow_mut().take();
        let postgres = self.postgres.borrow_mut().take();
        if let Some(postgres) = postgres {
            postgres.pool().close().await;
        }
        Ok(())
    }
}

fn secret_error(error: SecretsInvocationError, label: &str) -> RuntimeFailure {
    match error {
        SecretsInvocationError::Domain(_) => {
            failure(format!("Service Account {label} secret was rejected"))
        }
        SecretsInvocationError::Runtime(error) => error,
    }
}

fn valid_secret_reference(value: &str) -> bool {
    valid_authority(value, 256)
}

fn valid_authority(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn validate_authority_set(
    values: &[String],
    max_length: usize,
) -> Result<(), ServiceAccountConfigError> {
    if values.is_empty()
        || values.len() > 64
        || values
            .iter()
            .any(|value| !valid_authority(value, max_length))
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        return Err(ServiceAccountConfigError::InvalidAuthoritySet);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_auth_sdk::ActorAssertionIssuer;

    fn config() -> ServiceAccountConfig {
        let public_key =
            ActorAssertionIssuer::new("auth.users", b"test signing key").public_key_base64();
        ServiceAccountConfig::new(
            "service_accounts",
            "database-url",
            "credential-pepper",
            "receipt-key",
            "service-accounts",
            "auth.users",
            public_key,
            vec!["admin-api".to_owned()],
            vec!["auth-ingress".to_owned()],
            vec!["application".to_owned()],
            86_400,
            300,
            900,
            86_400,
            60,
            100,
            300,
            100,
            1_000,
        )
        .expect("valid config")
    }

    #[test]
    fn config_requires_distinct_secret_references_and_bounded_overlap() {
        let valid = config();
        assert_eq!(valid.rotation_overlap_seconds, 300);

        let mut invalid = valid.clone();
        invalid.credential_pepper_secret = invalid.database_url_secret.clone();
        assert_eq!(
            invalid.validate(),
            Err(ServiceAccountConfigError::InvalidSecretReferences)
        );

        let mut invalid = valid;
        invalid.rotation_overlap_seconds = invalid.credential_ttl_seconds;
        assert_eq!(
            invalid.validate(),
            Err(ServiceAccountConfigError::InvalidLimits)
        );
    }

    #[test]
    fn receipt_cipher_debug_never_exposes_key_material() {
        let receipt_cipher = ReceiptCipher::derive(b"receipt material that is deliberately secret");
        assert!(!format!("{receipt_cipher:?}").contains("deliberately secret"));
    }

    #[test]
    fn configuration_schema_is_closed_and_requires_security_boundaries() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../configuration.schema.json"))
                .expect("valid configuration schema");
        assert_eq!(schema["additionalProperties"], false);
        let required = schema["required"].as_array().expect("required fields");
        let required_names = required
            .iter()
            .map(|value| value.as_str().expect("string field"))
            .collect::<BTreeSet<_>>();
        let property_names = schema["properties"]
            .as_object()
            .expect("configuration properties")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(required_names, property_names);
        for field in [
            "database_url_secret",
            "credential_pepper_secret",
            "receipt_encryption_key_secret",
            "management_callers",
            "authentication_callers",
            "token_audience",
            "rotation_overlap_seconds",
            "max_exchanges_per_window",
        ] {
            assert!(required_names.contains(field));
        }
    }
}
