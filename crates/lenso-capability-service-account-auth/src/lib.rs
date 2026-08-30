//! Portable Service Account Auth Capability.

#[allow(clippy::all, clippy::pedantic)]
mod generated {
    include!("generated.rs");
}

pub use generated::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_debug_redacts_input_secret_and_issued_credential() {
        let request = ExchangeServiceAccountSecretRequest {
            idempotency_key: "exchange-1".to_owned(),
            secret: "lenso_sa_do_not_log".to_owned(),
        };
        let response = ExchangeServiceAccountSecretResponse {
            service_account_id: "sa_test".to_owned(),
            organization_id: "org_test".to_owned(),
            subject: "usr_machine".to_owned(),
            session_id: "session_test".to_owned(),
            credential: "issued_do_not_log".to_owned(),
            expires_at: "2026-08-30T00:15:00Z".to_owned(),
        };
        assert!(!format!("{request:?}").contains("do_not_log"));
        assert!(!format!("{response:?}").contains("do_not_log"));
        assert!(format!("{request:?}").contains("<redacted>"));
        assert!(format!("{response:?}").contains("<redacted>"));
    }
}
