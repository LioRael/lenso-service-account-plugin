//! Authoritative source for Service Account management.

use lenso_contract_authoring as lenso;

#[derive(serde::Deserialize)]
pub struct Nullable<T>(Option<T>);

impl<T: lenso::JsonSchema> lenso::JsonSchema for Nullable<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Nullable_{}", T::schema_name()).into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        format!("Nullable<{}>", T::schema_id()).into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <Option<T> as lenso::JsonSchema>::json_schema(generator)
    }
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccountStatus {
    Active,
    Revoked,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ServiceAccountSummary {
    pub service_account_id: String,
    pub organization_id: String,
    pub subject: String,
    pub name: String,
    pub status: ServiceAccountStatus,
    pub revision: String,
    #[schemars(extend("format" = "date-time"))]
    pub created_at: String,
    #[schemars(extend("format" = "date-time"))]
    pub rotated_at: Nullable<String>,
    #[schemars(extend("format" = "date-time"))]
    pub revoked_at: Nullable<String>,
    #[schemars(extend("format" = "date-time"))]
    pub credential_expires_at: Nullable<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct CreateServiceAccountRequest {
    pub idempotency_key: String,
    pub organization_id: String,
    pub name: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct CreateServiceAccountResponse {
    pub account: ServiceAccountSummary,
    pub created: bool,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub secret: Nullable<String>,
}

#[derive(lenso::DomainError)]
pub enum CreateServiceAccountError {
    Forbidden,
    InvalidRequest,
    OrganizationNotFound,
    MembershipRequired,
    AccessDenied,
    NameConflict,
    DirectoryRejected,
    IdempotencyConflict,
    OperationInProgress,
    TooManyServiceAccounts,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct GetServiceAccountRequest {
    pub organization_id: String,
    pub service_account_id: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct GetServiceAccountResponse {
    pub account: ServiceAccountSummary,
}

#[derive(lenso::DomainError)]
pub enum GetServiceAccountError {
    Forbidden,
    InvalidRequest,
    OrganizationNotFound,
    MembershipRequired,
    AccessDenied,
    NotFound,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListServiceAccountsRequest {
    pub organization_id: String,
    pub after: Nullable<String>,
    pub limit: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListServiceAccountsResponse {
    pub accounts: Vec<ServiceAccountSummary>,
    pub next_cursor: Nullable<String>,
}

#[derive(lenso::DomainError)]
pub enum ListServiceAccountsError {
    Forbidden,
    InvalidRequest,
    OrganizationNotFound,
    MembershipRequired,
    AccessDenied,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RotateServiceAccountSecretRequest {
    pub idempotency_key: String,
    pub organization_id: String,
    pub service_account_id: String,
    pub expected_revision: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RotateServiceAccountSecretResponse {
    pub account: ServiceAccountSummary,
    pub rotated: bool,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub secret: Nullable<String>,
}

#[derive(lenso::DomainError)]
pub enum RotateServiceAccountSecretError {
    Forbidden,
    InvalidRequest,
    OrganizationNotFound,
    MembershipRequired,
    AccessDenied,
    NotFound,
    Revoked,
    RevisionConflict,
    IdempotencyConflict,
    OperationInProgress,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeServiceAccountRequest {
    pub idempotency_key: String,
    pub organization_id: String,
    pub service_account_id: String,
    pub expected_revision: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeServiceAccountResponse {
    pub account: ServiceAccountSummary,
    pub revoked: bool,
}

#[derive(lenso::DomainError)]
pub enum RevokeServiceAccountError {
    Forbidden,
    InvalidRequest,
    OrganizationNotFound,
    MembershipRequired,
    AccessDenied,
    NotFound,
    RevisionConflict,
    IdempotencyConflict,
    OperationInProgress,
}

#[lenso::capability(
    id = "lenso.service-account",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait ServiceAccount {
    async fn create(
        &self,
        context: lenso::Ctx<'_>,
        request: CreateServiceAccountRequest,
    ) -> Result<CreateServiceAccountResponse, CreateServiceAccountError>;
    async fn get(
        &self,
        context: lenso::Ctx<'_>,
        request: GetServiceAccountRequest,
    ) -> Result<GetServiceAccountResponse, GetServiceAccountError>;
    async fn list(
        &self,
        context: lenso::Ctx<'_>,
        request: ListServiceAccountsRequest,
    ) -> Result<ListServiceAccountsResponse, ListServiceAccountsError>;
    async fn rotate_secret(
        &self,
        context: lenso::Ctx<'_>,
        request: RotateServiceAccountSecretRequest,
    ) -> Result<RotateServiceAccountSecretResponse, RotateServiceAccountSecretError>;
    async fn revoke(
        &self,
        context: lenso::Ctx<'_>,
        request: RevokeServiceAccountRequest,
    ) -> Result<RevokeServiceAccountResponse, RevokeServiceAccountError>;
}
