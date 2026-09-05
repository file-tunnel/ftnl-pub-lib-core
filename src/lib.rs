#![forbid(unsafe_code)]

//! Frontend-safe File Tunnel runtime configuration.
//!
//! Hosts acquire credentials through Shared Auth and platform-secure storage.
//! This crate carries only non-secret transport and access-mode policy. It
//! cannot represent administrator, internal-service, database, object-store,
//! pairing-capability, event-ticket, or bearer-token configuration.

use std::{fmt, net::IpAddr};

use thiserror::Error;
use url::Url;

pub const FILE_TUNNEL_API_AUDIENCE: &str = "file-tunnel-api";
pub const API_BASE_ENV: &str = "FTNL_API_BASE";
pub const EVENTS_BASE_ENV: &str = "FTNL_EVENTS_BASE";
pub const ACCESS_MODE_ENV: &str = "FTNL_ACCESS_MODE";
pub const ORGANIZATION_ID_ENV: &str = "FTNL_ORGANIZATION_ID";

pub const FLAG_ENV_MAPPINGS: [(&str, &str); 4] = [
    ("--api-base", API_BASE_ENV),
    ("--events-base", EVENTS_BASE_ENV),
    ("--access-mode", ACCESS_MODE_ENV),
    ("--organization-id", ORGANIZATION_ID_ENV),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeInputs {
    pub api_base: String,
    pub events_base: String,
    pub access_mode: String,
    pub organization_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessMode {
    OneTime,
    Individual,
    Organization,
}

impl AccessMode {
    #[must_use]
    pub const fn requires_shared_auth(self) -> bool {
        matches!(self, Self::Individual | Self::Organization)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FrontendRuntimeConfig {
    api_base: ExternalHttpBase,
    events_base: ExternalWebSocketBase,
    access_mode: AccessMode,
    organization_id: Option<OrganizationId>,
}

impl fmt::Debug for FrontendRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrontendRuntimeConfig")
            .field("api_base", &self.api_base)
            .field("events_base", &self.events_base)
            .field("access_mode", &self.access_mode)
            .field(
                "organization_id",
                &self.organization_id.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl FrontendRuntimeConfig {
    pub fn from_inputs(inputs: RuntimeInputs) -> Result<Self, ConfigError> {
        let api_base = ExternalHttpBase::parse(&inputs.api_base)?;
        let events_base = ExternalWebSocketBase::parse(&inputs.events_base)?;
        let (access_mode, organization_id) = match inputs.access_mode.as_str() {
            "one_time" => {
                if inputs.organization_id.is_some() {
                    return Err(ConfigError::UnexpectedOrganizationId);
                }
                (AccessMode::OneTime, None)
            }
            "individual" => {
                if inputs.organization_id.is_some() {
                    return Err(ConfigError::UnexpectedOrganizationId);
                }
                (AccessMode::Individual, None)
            }
            "organization" => {
                let organization_id = inputs
                    .organization_id
                    .ok_or(ConfigError::MissingOrganizationId)?;
                (
                    AccessMode::Organization,
                    Some(OrganizationId::parse(organization_id)?),
                )
            }
            _ => return Err(ConfigError::UnsupportedAccessMode),
        };
        Ok(Self {
            api_base,
            events_base,
            access_mode,
            organization_id,
        })
    }

    #[must_use]
    pub fn api_base(&self) -> &Url {
        self.api_base.as_url()
    }

    #[must_use]
    pub fn events_base(&self) -> &Url {
        self.events_base.as_url()
    }

    #[must_use]
    pub const fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    #[must_use]
    pub const fn shared_auth_audience(&self) -> Option<&'static str> {
        if self.access_mode.requires_shared_auth() {
            Some(FILE_TUNNEL_API_AUDIENCE)
        } else {
            None
        }
    }

    /// Returns client-selected routing context. Services must independently
    /// verify membership and authorization for this identifier.
    #[must_use]
    pub fn organization_id(&self) -> Option<&str> {
        self.organization_id.as_ref().map(OrganizationId::as_str)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ExternalHttpBase(Url);

impl fmt::Debug for ExternalHttpBase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ExternalHttpBase")
            .field(&self.0)
            .finish()
    }
}

impl ExternalHttpBase {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        let url = parse_origin(value, "https", "http")?;
        Ok(Self(url))
    }

    fn as_url(&self) -> &Url {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ExternalWebSocketBase(Url);

impl fmt::Debug for ExternalWebSocketBase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ExternalWebSocketBase")
            .field(&self.0)
            .finish()
    }
}

impl ExternalWebSocketBase {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        let url = parse_origin(value, "wss", "ws")?;
        Ok(Self(url))
    }

    fn as_url(&self) -> &Url {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
struct OrganizationId(String);

impl OrganizationId {
    fn parse(value: String) -> Result<Self, ConfigError> {
        if is_opaque_id(&value) {
            Ok(Self(value))
        } else {
            Err(ConfigError::InvalidOrganizationId)
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_origin(
    value: &str,
    secure_scheme: &'static str,
    loopback_scheme: &'static str,
) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidOrigin)?;
    if url.host_str().is_none() {
        return Err(ConfigError::InvalidOrigin);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::EmbeddedUrlCredentials);
    }
    let loopback = is_loopback(&url);
    if url.scheme() != secure_scheme && !(loopback && url.scheme() == loopback_scheme) {
        return Err(ConfigError::InsecureOrUnsupportedOrigin);
    }
    if url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        return Err(ConfigError::OriginMustNotContainPathQueryOrFragment);
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

fn is_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.starts_with('/')
        && !value.contains("..")
        && !value.contains("//")
        && !value.contains("://")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ConfigError {
    #[error("the transport origin is invalid")]
    InvalidOrigin,
    #[error("credentials embedded in an origin are forbidden")]
    EmbeddedUrlCredentials,
    #[error("origins must not contain paths, queries, or fragments")]
    OriginMustNotContainPathQueryOrFragment,
    #[error("remote API and event origins require HTTPS and WSS")]
    InsecureOrUnsupportedOrigin,
    #[error("access mode must be exactly one_time, individual, or organization")]
    UnsupportedAccessMode,
    #[error("organization access requires an opaque organization identifier")]
    MissingOrganizationId,
    #[error("organization context is forbidden outside organization access")]
    UnexpectedOrganizationId,
    #[error("organization identifier is invalid")]
    InvalidOrganizationId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(mode: &str, organization_id: Option<&str>) -> RuntimeInputs {
        RuntimeInputs {
            api_base: "https://api.file-tunnel.example".into(),
            events_base: "wss://events.file-tunnel.example".into(),
            access_mode: mode.into(),
            organization_id: organization_id.map(str::to_owned),
        }
    }

    #[test]
    fn access_modes_keep_auth_and_product_context_distinct() {
        let one_time =
            FrontendRuntimeConfig::from_inputs(inputs("one_time", None)).expect("one-time config");
        assert_eq!(one_time.access_mode(), AccessMode::OneTime);
        assert_eq!(one_time.shared_auth_audience(), None);

        let individual = FrontendRuntimeConfig::from_inputs(inputs("individual", None))
            .expect("individual config");
        assert_eq!(individual.access_mode(), AccessMode::Individual);
        assert_eq!(
            individual.shared_auth_audience(),
            Some(FILE_TUNNEL_API_AUDIENCE)
        );

        let organization =
            FrontendRuntimeConfig::from_inputs(inputs("organization", Some("org_01")))
                .expect("organization config");
        assert_eq!(organization.access_mode(), AccessMode::Organization);
        assert_eq!(organization.organization_id(), Some("org_01"));
        assert_eq!(
            organization.shared_auth_audience(),
            Some(FILE_TUNNEL_API_AUDIENCE)
        );
    }

    #[test]
    fn cross_surface_organization_context_fails_closed() {
        for mode in ["one_time", "individual"] {
            assert_eq!(
                FrontendRuntimeConfig::from_inputs(inputs(mode, Some("org_01"))),
                Err(ConfigError::UnexpectedOrganizationId)
            );
        }
        assert_eq!(
            FrontendRuntimeConfig::from_inputs(inputs("organization", None)),
            Err(ConfigError::MissingOrganizationId)
        );
    }

    #[test]
    fn remote_cleartext_credentials_and_internal_transports_are_rejected() {
        let mut insecure_api = inputs("individual", None);
        insecure_api.api_base = "http://api.file-tunnel.example".into();
        assert_eq!(
            FrontendRuntimeConfig::from_inputs(insecure_api),
            Err(ConfigError::InsecureOrUnsupportedOrigin)
        );

        let mut insecure_events = inputs("individual", None);
        insecure_events.events_base = "ws://events.file-tunnel.example".into();
        assert_eq!(
            FrontendRuntimeConfig::from_inputs(insecure_events),
            Err(ConfigError::InsecureOrUnsupportedOrigin)
        );

        let mut credentials = inputs("individual", None);
        credentials.api_base = "https://user:secret@api.file-tunnel.example".into();
        assert_eq!(
            FrontendRuntimeConfig::from_inputs(credentials),
            Err(ConfigError::EmbeddedUrlCredentials)
        );

        for internal in ["tcp://127.0.0.1:9000", "nats://127.0.0.1:4222"] {
            let mut candidate = inputs("individual", None);
            candidate.events_base = internal.into();
            assert_eq!(
                FrontendRuntimeConfig::from_inputs(candidate),
                Err(ConfigError::InsecureOrUnsupportedOrigin)
            );
        }
    }

    #[test]
    fn origins_reject_paths_queries_and_fragments() {
        for invalid in [
            "https://api.file-tunnel.example/v1",
            "https://api.file-tunnel.example?token=secret",
            "https://api.file-tunnel.example#capability",
        ] {
            let mut candidate = inputs("individual", None);
            candidate.api_base = invalid.into();
            assert_eq!(
                FrontendRuntimeConfig::from_inputs(candidate),
                Err(ConfigError::OriginMustNotContainPathQueryOrFragment)
            );
        }
    }

    #[test]
    fn loopback_cleartext_is_limited_to_local_development() {
        let config = FrontendRuntimeConfig::from_inputs(RuntimeInputs {
            api_base: "http://127.0.0.1:8080".into(),
            events_base: "ws://localhost:8080".into(),
            access_mode: "one_time".into(),
            organization_id: None,
        })
        .expect("loopback config");
        assert_eq!(config.api_base().scheme(), "http");
        assert_eq!(config.events_base().scheme(), "ws");
    }

    #[test]
    fn organization_context_is_redacted_from_debug_output() {
        let config =
            FrontendRuntimeConfig::from_inputs(inputs("organization", Some("private-org")))
                .expect("organization config");
        let debug = format!("{config:?}");
        assert!(!debug.contains("private-org"));
        assert!(debug.contains("[redacted]"));
    }
}
