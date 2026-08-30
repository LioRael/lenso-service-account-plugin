use lenso_auth_sdk::{ActorAssertion, ActorProjectionError, FixedClock, TypedActor};
use lenso_capability_access_control::{
    AccessControlClient, AccessControlInvocationError, CheckPermissionError,
    CheckPermissionRequest, CheckPermissionRequestScope,
};
use lenso_capability_organization_membership::{
    CheckMembershipError, CheckMembershipRequest, OrganizationMembershipClient,
    OrganizationMembershipInvocationError,
};
use lenso_kernel::{InvocationContext, RuntimeFailure};
use time::OffsetDateTime;

use crate::ActiveServiceAccount;

pub(crate) const READ_PERMISSION: &str = "service-account.read";
pub(crate) const MANAGE_PERMISSION: &str = "service-account.manage";

#[derive(Clone, Debug)]
pub(crate) struct AuthorizedManagement {
    pub caller: String,
    pub actor_subject: String,
}

#[derive(Debug)]
pub(crate) struct UserActor {
    subject: String,
}

impl TypedActor for UserActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if assertion.actor_kind() != "user" {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user".to_owned(),
                actual: assertion.actor_kind().to_owned(),
            });
        }
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Debug)]
pub(crate) enum AuthorizationError {
    Forbidden,
    OrganizationNotFound,
    MembershipRequired,
    AccessDenied,
    Runtime(RuntimeFailure),
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_management(
    active: &ActiveServiceAccount,
    membership: &OrganizationMembershipClient,
    access_control: &AccessControlClient,
    context: &InvocationContext,
    capability_id: &str,
    operation: &str,
    organization_id: &str,
    permission: &str,
) -> Result<AuthorizedManagement, AuthorizationError> {
    let caller = context
        .caller_instance()
        .filter(|caller| {
            active
                .config
                .management_callers
                .iter()
                .any(|allowed| allowed == caller)
        })
        .ok_or(AuthorizationError::Forbidden)?
        .to_owned();
    let actor = active
        .actor_verifier
        .project_context::<UserActor>(
            context,
            capability_id,
            operation,
            &FixedClock::new(OffsetDateTime::now_utc()),
        )
        .map_err(|_| AuthorizationError::Forbidden)?;
    if !valid_subject(&actor.subject) {
        return Err(AuthorizationError::Forbidden);
    }
    let membership = membership
        .check_membership_with_context(
            context.clone(),
            CheckMembershipRequest {
                organization_id: organization_id.to_owned(),
                subject: actor.subject.clone(),
            },
        )
        .await
        .map_err(|error| match error {
            OrganizationMembershipInvocationError::Domain(
                CheckMembershipError::OrganizationNotFound,
            ) => AuthorizationError::OrganizationNotFound,
            OrganizationMembershipInvocationError::Domain(CheckMembershipError::InvalidRequest) => {
                AuthorizationError::Runtime(failure(
                    "Organization Membership rejected a valid service-account request",
                ))
            }
            OrganizationMembershipInvocationError::Domain(CheckMembershipError::Unknown(_)) => {
                AuthorizationError::Runtime(failure(
                    "Organization Membership returned an unknown service-account error",
                ))
            }
            OrganizationMembershipInvocationError::Runtime(error) => {
                AuthorizationError::Runtime(error)
            }
        })?;
    if !membership.active {
        return Err(AuthorizationError::MembershipRequired);
    }
    let decision = access_control
        .check_permission_with_context(
            context.clone(),
            CheckPermissionRequest {
                subject: actor.subject.clone(),
                scope: CheckPermissionRequestScope {
                    kind: "organization".to_owned(),
                    id: organization_id.to_owned(),
                },
                permission: permission.to_owned(),
            },
        )
        .await
        .map_err(|error| match error {
            AccessControlInvocationError::Domain(CheckPermissionError::InvalidRequest) => {
                AuthorizationError::Runtime(failure(
                    "Access Control rejected a valid service-account permission request",
                ))
            }
            AccessControlInvocationError::Domain(CheckPermissionError::Unknown(_)) => {
                AuthorizationError::Runtime(failure(
                    "Access Control returned an unknown service-account error",
                ))
            }
            AccessControlInvocationError::Runtime(error) => AuthorizationError::Runtime(error),
        })?;
    if !decision.allowed {
        return Err(AuthorizationError::AccessDenied);
    }
    Ok(AuthorizedManagement {
        caller,
        actor_subject: actor.subject,
    })
}

fn valid_subject(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn failure(detail: impl Into<String>) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: detail.into(),
    }
}
