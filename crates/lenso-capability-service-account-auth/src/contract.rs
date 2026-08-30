//! Authoritative source for Service Account secret exchange.

use lenso_contract_authoring as lenso;

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ExchangeServiceAccountSecretRequest {
    pub idempotency_key: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub secret: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ExchangeServiceAccountSecretResponse {
    pub service_account_id: String,
    pub organization_id: String,
    pub subject: String,
    pub session_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
pub enum ExchangeServiceAccountSecretError {
    Forbidden,
    InvalidRequest,
    InvalidCredentials,
    RateLimited,
    Disabled,
    IdempotencyConflict,
    OperationInProgress,
}

#[lenso::capability(
    id = "lenso.auth.service-account",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait ServiceAccountAuth {
    async fn exchange_secret(
        &self,
        context: lenso::Ctx<'_>,
        request: ExchangeServiceAccountSecretRequest,
    ) -> Result<ExchangeServiceAccountSecretResponse, ExchangeServiceAccountSecretError>;
}
