//! Bearer-token authentication for the retained local HTTP control plane.
//!
//! Protocol peers authenticate with their transport identity. These credentials are deliberately
//! limited to the non-peer authorities exposed by the HTTP adapter: administrative protocol
//! control and deposit-address clients. Only domain-separated token digests are retained after
//! configuration has been loaded.

use std::collections::BTreeSet;

use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable as _, ConstantTimeEq as _};
use thiserror::Error;

use crate::config::Hex32;

/// Version accepted by [`BearerAuthConfig`].
pub const BEARER_AUTH_SCHEMA_VERSION: u16 = 1;
/// Minimum entropy-bearing token representation accepted by this module.
pub const MIN_BEARER_TOKEN_BYTES: usize = 32;
/// Hard cap applied before hashing attacker-controlled authorization headers.
pub const MAX_BEARER_TOKEN_BYTES: usize = 256;
/// Hard cap on configured principals and per-request digest comparisons.
pub const MAX_BEARER_CREDENTIALS: usize = 64;
const MAX_PRINCIPAL_NAME_BYTES: usize = 64;

/// A non-peer authority in the local HTTP control plane.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthRole {
    /// DKG, resharing, activation, status, and emergency administration.
    Admin,
    /// Request and inspect quorum-certified deposit addresses.
    Deposits,
}

/// A compact allow-list used by route middleware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowedRoles(u8);

impl AllowedRoles {
    pub const ADMIN: Self = Self(1 << 0);
    pub const DEPOSITS: Self = Self(1 << 1);
    pub const ADMIN_OR_DEPOSITS: Self = Self(Self::ADMIN.0 | Self::DEPOSITS.0);

    const fn contains(self, role: AuthRole) -> bool {
        let flag = match role {
            AuthRole::Admin => Self::ADMIN.0,
            AuthRole::Deposits => Self::DEPOSITS.0,
        };
        (self.0 & flag) != 0
    }
}

/// Digest-only credential entry. The raw token must be supplied to clients out of band.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BearerCredentialConfig {
    pub principal: String,
    pub role: AuthRole,
    pub token_digest: Hex32,
}

/// Serializable control-plane authentication configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BearerAuthConfig {
    pub schema_version: u16,
    pub credentials: Vec<BearerCredentialConfig>,
}

/// An authenticated control-plane principal safe to attach to request extensions and audit logs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipal {
    pub name: String,
    pub role: AuthRole,
}

#[derive(Clone)]
struct Credential {
    principal: AuthenticatedPrincipal,
    digest: [u8; 32],
}

/// Digest-only, role-aware bearer-token authenticator.
#[derive(Clone)]
pub struct BearerAuthenticator {
    credentials: Vec<Credential>,
}

impl std::fmt::Debug for BearerAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BearerAuthenticator")
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AuthError {
    #[error("unsupported bearer-auth configuration version {0}")]
    UnsupportedVersion(u16),
    #[error("authentication configuration has too many credentials")]
    TooManyCredentials,
    #[error("authentication principal name is invalid")]
    InvalidPrincipal,
    #[error("duplicate authentication principal {0}")]
    DuplicatePrincipal(String),
    #[error("two authentication principals use the same token digest")]
    DuplicateToken,
    #[error("authentication configuration has no {0:?} credential")]
    MissingRole(AuthRole),
    #[error("authorization header is missing")]
    MissingAuthorization,
    #[error("multiple authorization headers are not allowed")]
    MultipleAuthorization,
    #[error("authorization header is malformed")]
    MalformedAuthorization,
    #[error(
        "bearer token must contain between {MIN_BEARER_TOKEN_BYTES} and {MAX_BEARER_TOKEN_BYTES} bytes"
    )]
    InvalidTokenLength,
    #[error("bearer token is invalid")]
    InvalidToken,
    #[error("authenticated principal is not allowed to use this route")]
    Forbidden,
}

impl BearerAuthenticator {
    /// Validate a digest-only configuration and construct an authenticator.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the schema is unsupported, its bounds are exceeded, credentials
    /// are ambiguous, principal names are unsafe, or the required admin role is absent.
    pub fn from_config(config: BearerAuthConfig) -> Result<Self, AuthError> {
        if config.schema_version != BEARER_AUTH_SCHEMA_VERSION {
            return Err(AuthError::UnsupportedVersion(config.schema_version));
        }
        if config.credentials.len() > MAX_BEARER_CREDENTIALS {
            return Err(AuthError::TooManyCredentials);
        }

        let mut principals = BTreeSet::new();
        let mut digests = BTreeSet::new();
        let mut roles = BTreeSet::new();
        let mut credentials = Vec::with_capacity(config.credentials.len());
        for configured in config.credentials {
            validate_principal(&configured.principal)?;
            if !principals.insert(configured.principal.clone()) {
                return Err(AuthError::DuplicatePrincipal(configured.principal));
            }
            if !digests.insert(configured.token_digest.0) {
                return Err(AuthError::DuplicateToken);
            }
            roles.insert(configured.role);
            credentials.push(Credential {
                principal: AuthenticatedPrincipal {
                    name: configured.principal,
                    role: configured.role,
                },
                digest: configured.token_digest.0,
            });
        }
        if !roles.contains(&AuthRole::Admin) {
            return Err(AuthError::MissingRole(AuthRole::Admin));
        }
        Ok(Self { credentials })
    }

    /// Authenticate exactly one `Authorization` header and enforce the route's role allow-list.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the header is missing, duplicated, malformed, unknown, or belongs
    /// to a principal whose role is not allowed.
    pub fn authorize_headers(
        &self,
        headers: &HeaderMap,
        allowed: AllowedRoles,
    ) -> Result<AuthenticatedPrincipal, AuthError> {
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let value = values.next().ok_or(AuthError::MissingAuthorization)?;
        if values.next().is_some() {
            return Err(AuthError::MultipleAuthorization);
        }
        self.authorize_value(value, allowed)
    }

    /// Authenticate one header value and enforce the route's role allow-list.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the header is malformed, the token is unknown, or the authenticated
    /// principal's role is not allowed.
    pub fn authorize_value(
        &self,
        value: &HeaderValue,
        allowed: AllowedRoles,
    ) -> Result<AuthenticatedPrincipal, AuthError> {
        let token = parse_bearer(value.as_bytes())?;
        let presented = bearer_token_digest(token)?;

        // Always compare the presented digest with every configured digest. Configuration rejects
        // duplicate digests, so exactly zero or one entry may match.
        let mut any_match = Choice::from(0);
        let mut matched_index = 0_u8;
        for (index, credential) in (0_u8..).zip(&self.credentials) {
            let equal = credential.digest.ct_eq(&presented);
            matched_index = u8::conditional_select(&matched_index, &index, equal);
            any_match |= equal;
        }
        if !bool::from(any_match) {
            return Err(AuthError::InvalidToken);
        }
        let principal = self.credentials[usize::from(matched_index)].principal.clone();
        if !allowed.contains(principal.role) {
            return Err(AuthError::Forbidden);
        }
        Ok(principal)
    }
}

/// Compute the value stored in [`BearerCredentialConfig`] without retaining the raw token.
///
/// # Errors
///
/// Returns [`AuthError`] if the supplied representation is too short, too long, or contains bytes
/// which cannot be used in the strict visible-ASCII bearer format.
pub fn bearer_token_digest(token: &[u8]) -> Result<[u8; 32], AuthError> {
    validate_token(token)?;
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/http-bearer-token/v1");
    let length = u64::try_from(token.len()).map_err(|_| AuthError::InvalidTokenLength)?;
    hasher.update(&length.to_le_bytes());
    hasher.update(token);
    Ok(*hasher.finalize().as_bytes())
}

fn parse_bearer(header: &[u8]) -> Result<&[u8], AuthError> {
    const PREFIX: &[u8] = b"Bearer ";
    if header.len() <= PREFIX.len() || !header[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return Err(AuthError::MalformedAuthorization);
    }
    let token = &header[PREFIX.len()..];
    validate_token(token)?;
    Ok(token)
}

fn validate_token(token: &[u8]) -> Result<(), AuthError> {
    if !(MIN_BEARER_TOKEN_BYTES..=MAX_BEARER_TOKEN_BYTES).contains(&token.len()) {
        return Err(AuthError::InvalidTokenLength);
    }
    // Opaque bearer credentials still use a visible, whitespace-free HTTP representation.
    if !token.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(AuthError::MalformedAuthorization);
    }
    Ok(())
}

fn validate_principal(principal: &str) -> Result<(), AuthError> {
    if principal.is_empty()
        || principal.len() > MAX_PRINCIPAL_NAME_BYTES
        || !principal
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AuthError::InvalidPrincipal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMIN_TOKEN: &[u8] = b"admin-token-000000000000000000000000";
    const DEPOSIT_TOKEN: &[u8] = b"deposit-token-0000000000000000000000";

    fn credential(principal: &str, role: AuthRole, token: &[u8]) -> BearerCredentialConfig {
        BearerCredentialConfig {
            principal: principal.to_owned(),
            role,
            token_digest: Hex32(bearer_token_digest(token).unwrap()),
        }
    }

    fn authenticator() -> BearerAuthenticator {
        BearerAuthenticator::from_config(BearerAuthConfig {
            schema_version: BEARER_AUTH_SCHEMA_VERSION,
            credentials: vec![
                credential("operator", AuthRole::Admin, ADMIN_TOKEN),
                credential("deposit-client", AuthRole::Deposits, DEPOSIT_TOKEN),
            ],
        })
        .unwrap()
    }

    fn bearer(token: &[u8]) -> HeaderValue {
        let mut value = b"Bearer ".to_vec();
        value.extend_from_slice(token);
        HeaderValue::from_bytes(&value).unwrap()
    }

    #[test]
    fn authenticates_control_plane_roles_without_retaining_tokens() {
        let auth = authenticator();
        assert_eq!(
            auth.authorize_value(&bearer(ADMIN_TOKEN), AllowedRoles::ADMIN).unwrap(),
            AuthenticatedPrincipal { name: "operator".to_owned(), role: AuthRole::Admin }
        );
        assert_eq!(
            auth.authorize_value(&bearer(DEPOSIT_TOKEN), AllowedRoles::DEPOSITS).unwrap(),
            AuthenticatedPrincipal { name: "deposit-client".to_owned(), role: AuthRole::Deposits }
        );
        let debug = format!("{auth:?}");
        assert!(!debug.contains(std::str::from_utf8(ADMIN_TOKEN).unwrap()));
        assert!(!debug.contains(std::str::from_utf8(DEPOSIT_TOKEN).unwrap()));
    }

    #[test]
    fn role_enforcement_distinguishes_authentication_from_authorization() {
        let auth = authenticator();
        assert_eq!(
            auth.authorize_value(&bearer(DEPOSIT_TOKEN), AllowedRoles::ADMIN),
            Err(AuthError::Forbidden)
        );
        assert!(
            auth.authorize_value(&bearer(ADMIN_TOKEN), AllowedRoles::ADMIN_OR_DEPOSITS).is_ok()
        );
        assert!(
            auth.authorize_value(&bearer(DEPOSIT_TOKEN), AllowedRoles::ADMIN_OR_DEPOSITS).is_ok()
        );
    }

    #[test]
    fn parses_scheme_case_insensitively_but_rejects_malformed_values() {
        let auth = authenticator();
        let mut lowercase = b"bearer ".to_vec();
        lowercase.extend_from_slice(ADMIN_TOKEN);
        assert!(
            auth.authorize_value(
                &HeaderValue::from_bytes(&lowercase).unwrap(),
                AllowedRoles::ADMIN
            )
            .is_ok()
        );
        for malformed in [
            b"Basic abcdefghijklmnopqrstuvwxyz0123456789".as_slice(),
            b"Bearer".as_slice(),
            b"Bearer short".as_slice(),
            b"Bearer token-with-whitespace-000000000000 000".as_slice(),
        ] {
            assert!(
                auth.authorize_value(
                    &HeaderValue::from_bytes(malformed).unwrap(),
                    AllowedRoles::ADMIN
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_missing_and_multiple_authorization_headers() {
        let auth = authenticator();
        let mut headers = HeaderMap::new();
        assert_eq!(
            auth.authorize_headers(&headers, AllowedRoles::ADMIN),
            Err(AuthError::MissingAuthorization)
        );
        headers.append(AUTHORIZATION, bearer(ADMIN_TOKEN));
        headers.append(AUTHORIZATION, bearer(ADMIN_TOKEN));
        assert_eq!(
            auth.authorize_headers(&headers, AllowedRoles::ADMIN),
            Err(AuthError::MultipleAuthorization)
        );
    }

    #[test]
    fn rejects_invalid_and_out_of_bounds_tokens() {
        let auth = authenticator();
        assert_eq!(
            auth.authorize_value(
                &bearer(b"other-token-000000000000000000000000"),
                AllowedRoles::ADMIN
            ),
            Err(AuthError::InvalidToken)
        );
        assert_eq!(bearer_token_digest(&[b'x'; 31]), Err(AuthError::InvalidTokenLength));
        assert_eq!(bearer_token_digest(&[b'x'; 257]), Err(AuthError::InvalidTokenLength));
    }

    #[test]
    fn configuration_requires_unique_principals_tokens_and_an_admin() {
        let admin = credential("operator", AuthRole::Admin, ADMIN_TOKEN);
        let deposits = credential("deposit-client", AuthRole::Deposits, DEPOSIT_TOKEN);
        let config = |credentials| BearerAuthConfig {
            schema_version: BEARER_AUTH_SCHEMA_VERSION,
            credentials,
        };
        assert_eq!(
            BearerAuthenticator::from_config(config(vec![deposits.clone()])).unwrap_err(),
            AuthError::MissingRole(AuthRole::Admin)
        );
        assert!(BearerAuthenticator::from_config(config(vec![admin.clone()])).is_ok());
        assert_eq!(
            BearerAuthenticator::from_config(config(vec![
                admin.clone(),
                admin.clone(),
                deposits.clone()
            ]))
            .unwrap_err(),
            AuthError::DuplicatePrincipal("operator".to_owned())
        );
        let same_token = BearerCredentialConfig {
            principal: "another".to_owned(),
            role: AuthRole::Deposits,
            token_digest: admin.token_digest,
        };
        assert_eq!(
            BearerAuthenticator::from_config(config(vec![admin, same_token])).unwrap_err(),
            AuthError::DuplicateToken
        );
        assert_eq!(
            BearerAuthenticator::from_config(BearerAuthConfig {
                schema_version: 2,
                credentials: vec![deposits],
            })
            .unwrap_err(),
            AuthError::UnsupportedVersion(2)
        );
        let too_many = (0..=MAX_BEARER_CREDENTIALS)
            .map(|index| BearerCredentialConfig {
                principal: format!("principal-{index}"),
                role: AuthRole::Admin,
                token_digest: Hex32([u8::try_from(index).unwrap(); 32]),
            })
            .collect();
        assert_eq!(
            BearerAuthenticator::from_config(config(too_many)).unwrap_err(),
            AuthError::TooManyCredentials
        );
    }

    #[test]
    fn configuration_rejects_names_that_are_unsafe_for_audit_logs() {
        for name in ["", "has space", "has\nnewline", &"x".repeat(65)] {
            let result = BearerAuthenticator::from_config(BearerAuthConfig {
                schema_version: BEARER_AUTH_SCHEMA_VERSION,
                credentials: vec![credential(name, AuthRole::Admin, ADMIN_TOKEN)],
            });
            assert_eq!(result.unwrap_err(), AuthError::InvalidPrincipal);
        }
    }
}
