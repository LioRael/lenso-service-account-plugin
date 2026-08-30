use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![(
    1,
    "create-service-account-state",
    "migrations/001_create_service_account_state.sql",
)];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_owns_credentials_revisions_commands_and_rate_limits() {
        let sql = MIGRATIONS[0].sql();
        assert!(sql.contains("service_accounts_organization_name_unique"));
        assert!(sql.contains("service_accounts_subject_unique"));
        assert!(sql.contains("verifier TEXT NOT NULL"));
        assert!(sql.contains("valid_until TIMESTAMPTZ NOT NULL"));
        assert!(sql.contains("PRIMARY KEY (caller_instance, operation, idempotency_key)"));
        assert!(sql.contains("service_account_exchange_limits"));
    }

    #[test]
    fn unsafe_schema_name_is_rejected() {
        assert!(schema_plan("public; DROP SCHEMA public").is_err());
    }
}
