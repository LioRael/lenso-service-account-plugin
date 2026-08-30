//! Portable Service Account management Capability.

#[allow(clippy::all, clippy::pedantic)]
mod generated {
    include!("generated.rs");
}

pub use generated::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> ServiceAccountSummary {
        ServiceAccountSummary {
            service_account_id: "sa_test".to_owned(),
            organization_id: "org_test".to_owned(),
            subject: "usr_machine".to_owned(),
            name: "Build bot".to_owned(),
            status: ServiceAccountStatus::Active,
            revision: "1".to_owned(),
            created_at: "2026-08-30T00:00:00Z".to_owned(),
            rotated_at: None,
            revoked_at: None,
            credential_expires_at: Some("2026-08-31T00:00:00Z".to_owned()),
        }
    }

    #[test]
    fn create_and_rotate_debug_redact_raw_secrets() {
        let create = CreateServiceAccountResponse {
            account: account(),
            created: true,
            secret: Some("lenso_sa_do_not_log".to_owned()),
        };
        let rotate = RotateServiceAccountSecretResponse {
            account: account(),
            rotated: true,
            secret: Some("lenso_sa_do_not_log".to_owned()),
        };
        assert!(!format!("{create:?}").contains("do_not_log"));
        assert!(!format!("{rotate:?}").contains("do_not_log"));
        assert!(format!("{create:?}").contains("<redacted>"));
        assert!(format!("{rotate:?}").contains("<redacted>"));
    }
}
