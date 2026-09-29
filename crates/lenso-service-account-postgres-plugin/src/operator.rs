use lenso_postgres_kit::{PostgresKitError, SchemaOperator, SetupOutcome, UpgradeOutcome};
use sqlx::Row;
use thiserror::Error;
use time::OffsetDateTime;

use crate::schema::schema_plan;

#[derive(Clone, Copy, Debug, Default)]
pub struct ServiceAccountOperator;

/// Sanitized state for a caller-scoped command, without secret or receipt data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAccountCommandStatus {
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
}

impl ServiceAccountCommandStatus {
    /// An issuer call may have committed after the local admission point.
    pub fn requires_issuer_reconciliation(&self) -> bool {
        self.status == "issuing"
    }
}

impl ServiceAccountOperator {
    /// Reads one command's durable state through a privileged operator connection.
    /// This does not retry issuance, reset state, or decrypt a receipt.
    pub async fn inspect_command(
        database_url: &str,
        schema: &str,
        caller: &str,
        operation: &str,
        idempotency_key: &str,
    ) -> Result<Option<ServiceAccountCommandStatus>, ServiceAccountOperatorError> {
        if !crate::valid_caller(caller)
            || !crate::valid_authority(operation, 64)
            || !crate::valid_authority(idempotency_key, 128)
        {
            return Err(ServiceAccountOperatorError::InvalidCommandReference);
        }
        let postgres =
            lenso_postgres_kit::OwnedPostgres::prepare(database_url, schema_plan(schema)?).await?;
        let result = sqlx::query("SELECT status,created_at,updated_at,completed_at FROM service_account_commands WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3")
            .bind(caller).bind(operation).bind(idempotency_key).fetch_optional(postgres.pool()).await;
        postgres.pool().close().await;
        result?
            .map(|row| {
                Ok(ServiceAccountCommandStatus {
                    status: row.try_get("status")?,
                    created_at: row.try_get("created_at")?,
                    updated_at: row.try_get("updated_at")?,
                    completed_at: row.try_get("completed_at")?,
                })
            })
            .transpose()
    }

    pub async fn setup(
        database_url: &str,
        schema: &str,
    ) -> Result<SetupOutcome, ServiceAccountOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .setup()
            .await?)
    }

    pub async fn upgrade(
        database_url: &str,
        schema: &str,
    ) -> Result<UpgradeOutcome, ServiceAccountOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .upgrade()
            .await?)
    }
}

#[derive(Debug, Error)]
pub enum ServiceAccountOperatorError {
    #[error("invalid caller-scoped command reference")]
    InvalidCommandReference,
    #[error("command status lookup failed")]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Plan(#[from] lenso_postgres_kit::PlanError),
    #[error(transparent)]
    Postgres(#[from] PostgresKitError),
}
