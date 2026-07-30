//! Scope Guard decision-path regression tests.

#![allow(unused_crate_dependencies)]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use grym_core::{
    DenialReason, OperatorAttestation, ScopeConfig, ScopeError, ScopeGuard, TechniqueTier,
    audit::MemoryAuditLog,
    config::{
        AuthorizationConfig, Engagement, LimitConfig, SafetyConfig, TargetScope, TechniqueConfig,
    },
};
use url::Url;

fn scope() -> Result<ScopeConfig, chrono::ParseError> {
    Ok(ScopeConfig {
        format_version: 1,
        engagement: Engagement {
            client: "Fixture Corp".to_owned(),
            engagement_id: "ENG-TEST-1".to_owned(),
            authorized_start: DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")?,
            authorized_end: DateTime::parse_from_rfc3339("2026-12-31T23:59:59+00:00")?,
            emergency_contact: "security@fixture.test".to_owned(),
        },
        targets: TargetScope {
            allow: vec!["*.fixture.test".to_owned(), "127.0.0.1".to_owned()],
            deny: vec!["admin.fixture.test".to_owned(), "*/logout".to_owned()],
        },
        limits: LimitConfig {
            max_requests_per_second_global: 10,
            max_requests_per_second_per_host: 2,
            max_response_bytes: 4096,
        },
        technique: TechniqueConfig {
            max_tier: TechniqueTier::SafeActive,
            deepness: Default::default(),
        },
        authorization: AuthorizationConfig {
            authorization_attested: true,
        },
        safety: SafetyConfig::default(),
    })
}

fn attestation() -> OperatorAttestation {
    OperatorAttestation {
        engagement_id: "ENG-TEST-1".to_owned(),
        confirmation: OperatorAttestation::required_phrase("ENG-TEST-1"),
    }
}

fn active_guard(audit: Arc<MemoryAuditLog>) -> Result<ScopeGuard, Box<dyn std::error::Error>> {
    Ok(ScopeGuard::new(scope()?, Some(attestation()), audit)?)
}

#[test]
fn denies_explicit_host_and_path_exclusions_before_allowing()
-> Result<(), Box<dyn std::error::Error>> {
    let audit = Arc::new(MemoryAuditLog::default());
    let guard = active_guard(Arc::clone(&audit))?;
    let now = DateTime::parse_from_rfc3339("2026-06-01T00:00:00+00:00")?.with_timezone(&Utc);

    let allowed = Url::parse("https://app.fixture.test/health")?;
    guard.authorize_url_at("fixture", &allowed, TechniqueTier::SafeActive, now)?;

    let denied_host = Url::parse("https://admin.fixture.test/health")?;
    let denied = guard.authorize_url_at("fixture", &denied_host, TechniqueTier::SafeActive, now);
    assert!(matches!(
        denied,
        Err(ScopeError::Denied {
            reason: DenialReason::ExplicitlyDenied,
            ..
        })
    ));

    let denied_path = Url::parse("https://app.fixture.test/logout")?;
    let denied = guard.authorize_url_at("fixture", &denied_path, TechniqueTier::SafeActive, now);
    assert!(matches!(
        denied,
        Err(ScopeError::Denied {
            reason: DenialReason::ExplicitlyDenied,
            ..
        })
    ));
    assert_eq!(audit.events()?.len(), 3);
    Ok(())
}

#[test]
fn denies_non_allowlisted_and_out_of_window_targets() -> Result<(), Box<dyn std::error::Error>> {
    let audit = Arc::new(MemoryAuditLog::default());
    let guard = active_guard(audit)?;
    let target = Url::parse("https://outside.test/")?;
    let in_window = DateTime::parse_from_rfc3339("2026-06-01T00:00:00+00:00")?.with_timezone(&Utc);
    let denied = guard.authorize_url_at("fixture", &target, TechniqueTier::SafeActive, in_window);
    assert!(matches!(
        denied,
        Err(ScopeError::Denied {
            reason: DenialReason::NotAllowlisted,
            ..
        })
    ));

    let allowed_target = Url::parse("https://app.fixture.test/")?;
    let expired = DateTime::parse_from_rfc3339("2027-01-01T00:00:00+00:00")?.with_timezone(&Utc);
    let denied = guard.authorize_url_at(
        "fixture",
        &allowed_target,
        TechniqueTier::SafeActive,
        expired,
    );
    assert!(matches!(
        denied,
        Err(ScopeError::Denied {
            reason: DenialReason::OutsideAuthorizedWindow,
            ..
        })
    ));
    Ok(())
}

#[test]
fn requires_typed_attestation_for_active_scope() -> Result<(), Box<dyn std::error::Error>> {
    let result = ScopeGuard::new(scope()?, None, Arc::new(MemoryAuditLog::default()));
    assert!(matches!(result, Err(ScopeError::AttestationRequired)));
    Ok(())
}
