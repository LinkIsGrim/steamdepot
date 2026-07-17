use prost::Message;

use crate::connection::CmConnection;
use crate::emsg::EMsg;
use crate::error::{Error, Result};
use crate::proto::{
    c_msg_ip_address, CAuthenticationBeginAuthSessionViaCredentialsRequest,
    CAuthenticationBeginAuthSessionViaCredentialsResponse, CAuthenticationDeviceDetails,
    CAuthenticationGetPasswordRsaPublicKeyRequest,
    CAuthenticationGetPasswordRsaPublicKeyResponse,
    CAuthenticationPollAuthSessionStatusRequest,
    CAuthenticationPollAuthSessionStatusResponse,
    CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest, CMsgClientLogon,
    CMsgClientLogonResponse, CMsgIpAddress, CMsgProtoBufHeader,
};
use crate::session::SessionState;

/// Anonymous SteamID: universe=Public(1), type=AnonUser(10), instance=0, account_id=0.
/// EAccountType 10 = AnonUser (for content downloads).
/// EAccountType 4 = AnonGameServer (for game servers registering with Steam, NOT downloads).
const ANONYMOUS_STEAM_ID: u64 = (1u64 << 56) | (10u64 << 52);

/// XOR mask applied to the login ID before sending as `obfuscated_private_ip`.
const LOGIN_ID_XOR: u32 = 0xBAADF00D;

/// Generate a random login ID.
///
/// Uses `RandomState` (seeded from OS entropy) + `Hasher` to produce a u32
/// without adding any dependencies.
pub fn rand_login_id() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u32
}

pub async fn login_anonymous(conn: &mut CmConnection) -> Result<SessionState> {
    login_anonymous_with_id(conn, rand_login_id()).await
}

pub async fn login_anonymous_with_id(
    conn: &mut CmConnection,
    login_id: u32,
) -> Result<SessionState> {
    let header = CMsgProtoBufHeader {
        steamid: Some(ANONYMOUS_STEAM_ID),
        ..Default::default()
    };

    let body = CMsgClientLogon {
        protocol_version: Some(65580),
        client_os_type: Some(20),
        obfuscated_private_ip: Some(CMsgIpAddress {
            ip: Some(c_msg_ip_address::Ip::V4(login_id ^ LOGIN_ID_XOR)),
        }),
        ..Default::default()
    };

    conn.send(EMsg::ClientLogon, &header, &body.encode_to_vec())
        .await?;

    await_logon_response(conn).await
}

// -------------------------------------------------------------------------
// Authenticated login helpers
// -------------------------------------------------------------------------

/// RSA public key for encrypting a password before auth.
pub struct RsaKey {
    pub modulus: String,
    pub exponent: String,
    pub timestamp: u64,
}

/// State of an in-progress auth session.
pub struct AuthSession {
    pub client_id: u64,
    pub request_id: Vec<u8>,
    pub steam_id: u64,
    pub allowed_confirmations: Vec<i32>,
    pub interval: f32,
}

/// Guard code type (matches EAuthSessionGuardType values).
#[derive(Debug, Clone, Copy)]
pub enum GuardType {
    EmailCode = 2,
    DeviceCode = 3,
}

impl AuthSession {
    /// Check whether the server requires a specific guard type.
    pub fn needs_guard(&self, guard_type: GuardType) -> bool {
        self.allowed_confirmations.contains(&(guard_type as i32))
    }
}

/// Tokens returned after a successful auth poll.
pub struct AuthTokens {
    pub refresh_token: String,
    pub access_token: String,
}

/// Get the RSA public key for encrypting a password.
pub async fn get_password_rsa_key(
    conn: &mut CmConnection,
    account_name: &str,
) -> Result<RsaKey> {
    let req = CAuthenticationGetPasswordRsaPublicKeyRequest {
        account_name: Some(account_name.to_string()),
    };
    let resp_bytes = conn
        .service_method_call(
            "Authentication.GetPasswordRSAPublicKey#1",
            &req.encode_to_vec(),
        )
        .await?;
    let resp = CAuthenticationGetPasswordRsaPublicKeyResponse::decode(resp_bytes.as_slice())?;
    Ok(RsaKey {
        modulus: resp.publickey_mod.unwrap_or_default(),
        exponent: resp.publickey_exp.unwrap_or_default(),
        timestamp: resp.timestamp.unwrap_or(0),
    })
}

/// Encrypt a password using the RSA public key from Steam.
pub fn encrypt_password(password: &str, rsa_key: &RsaKey) -> Result<String> {
    use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};

    let n = BigUint::parse_bytes(rsa_key.modulus.as_bytes(), 16)
        .ok_or_else(|| Error::Other("invalid RSA modulus".into()))?;
    let e = BigUint::parse_bytes(rsa_key.exponent.as_bytes(), 16)
        .ok_or_else(|| Error::Other("invalid RSA exponent".into()))?;

    let pub_key = RsaPublicKey::new(n, e)
        .map_err(|e| Error::Other(format!("invalid RSA key: {}", e)))?;

    let mut rng = rsa::rand_core::OsRng;
    let encrypted = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, password.as_bytes())
        .map_err(|e| Error::Other(format!("RSA encrypt failed: {}", e)))?;

    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted,
    ))
}

/// Begin an auth session with credentials.
pub async fn begin_auth_session(
    conn: &mut CmConnection,
    account_name: &str,
    encrypted_password: &str,
    timestamp: u64,
) -> Result<AuthSession> {
    let req = CAuthenticationBeginAuthSessionViaCredentialsRequest {
        account_name: Some(account_name.to_string()),
        encrypted_password: Some(encrypted_password.to_string()),
        encryption_timestamp: Some(timestamp),
        remember_login: Some(true),
        platform_type: Some(1), // SteamClient
        persistence: Some(1),   // Persistent
        website_id: Some("Client".to_string()),
        device_details: Some(CAuthenticationDeviceDetails {
            device_friendly_name: Some("steamdepot-rs".to_string()),
            platform_type: Some(1),
            os_type: Some(20), // Linux
            ..Default::default()
        }),
        ..Default::default()
    };
    let resp_bytes = conn
        .service_method_call(
            "Authentication.BeginAuthSessionViaCredentials#1",
            &req.encode_to_vec(),
        )
        .await?;
    let resp =
        CAuthenticationBeginAuthSessionViaCredentialsResponse::decode(resp_bytes.as_slice())?;

    let allowed: Vec<i32> = resp
        .allowed_confirmations
        .iter()
        .filter_map(|c| c.confirmation_type)
        .collect();

    Ok(AuthSession {
        client_id: resp.client_id.unwrap_or(0),
        request_id: resp.request_id.unwrap_or_default(),
        steam_id: resp.steamid.unwrap_or(0),
        allowed_confirmations: allowed,
        interval: resp.interval.unwrap_or(5.0),
    })
}

/// Begin a passwordless auth session (for newly created accounts with no password).
///
/// Calls `BeginAuthSessionViaCredentials` with only the account name/email,
/// omitting password fields. Steam will respond with `allowed_confirmations`
/// indicating that an email verification is required.
pub async fn begin_auth_session_passwordless(
    conn: &mut CmConnection,
    account_name: &str,
) -> Result<AuthSession> {
    let req = CAuthenticationBeginAuthSessionViaCredentialsRequest {
        account_name: Some(account_name.to_string()),
        remember_login: Some(true),
        platform_type: Some(1), // SteamClient
        persistence: Some(1),   // Persistent
        website_id: Some("Client".to_string()),
        device_details: Some(CAuthenticationDeviceDetails {
            device_friendly_name: Some("steamdepot-rs".to_string()),
            platform_type: Some(1),
            os_type: Some(20), // Linux
            ..Default::default()
        }),
        ..Default::default()
    };
    let resp_bytes = conn
        .service_method_call(
            "Authentication.BeginAuthSessionViaCredentials#1",
            &req.encode_to_vec(),
        )
        .await?;
    let resp =
        CAuthenticationBeginAuthSessionViaCredentialsResponse::decode(resp_bytes.as_slice())?;

    let allowed: Vec<i32> = resp
        .allowed_confirmations
        .iter()
        .filter_map(|c| c.confirmation_type)
        .collect();

    Ok(AuthSession {
        client_id: resp.client_id.unwrap_or(0),
        request_id: resp.request_id.unwrap_or_default(),
        steam_id: resp.steamid.unwrap_or(0),
        allowed_confirmations: allowed,
        interval: resp.interval.unwrap_or(5.0),
    })
}

/// Submit a Steam Guard code (email or TOTP).
pub async fn submit_guard_code(
    conn: &mut CmConnection,
    session: &AuthSession,
    code: &str,
    code_type: GuardType,
) -> Result<()> {
    let req = CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest {
        client_id: Some(session.client_id),
        steamid: Some(session.steam_id),
        code: Some(code.to_string()),
        code_type: Some(code_type as i32),
    };
    conn.service_method_call(
        "Authentication.UpdateAuthSessionWithSteamGuardCode#1",
        &req.encode_to_vec(),
    )
    .await?;
    Ok(())
}

/// Poll until auth session is confirmed, returns tokens.
pub async fn poll_auth_status(
    conn: &mut CmConnection,
    session: &AuthSession,
) -> Result<AuthTokens> {
    loop {
        let req = CAuthenticationPollAuthSessionStatusRequest {
            client_id: Some(session.client_id),
            request_id: Some(session.request_id.clone()),
            ..Default::default()
        };
        let resp_bytes = conn
            .service_method_call(
                "Authentication.PollAuthSessionStatus#1",
                &req.encode_to_vec(),
            )
            .await?;
        let resp =
            CAuthenticationPollAuthSessionStatusResponse::decode(resp_bytes.as_slice())?;

        if let Some(refresh) = resp.refresh_token {
            if !refresh.is_empty() {
                return Ok(AuthTokens {
                    refresh_token: refresh,
                    access_token: resp.access_token.unwrap_or_default(),
                });
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs_f32(session.interval)).await;
    }
}

/// Login with a refresh token (the simple path for the CLI).
///
/// Follows the SteamKit2 pattern: sets the SteamID in the proto header
/// and `should_remember_password` alongside the access token.
pub async fn login_with_token(
    conn: &mut CmConnection,
    account_name: &str,
    refresh_token: &str,
) -> Result<SessionState> {
    // Extract SteamID from the JWT payload (sub claim) if possible.
    let steam_id = extract_steamid_from_jwt(refresh_token).unwrap_or(0);

    let header = CMsgProtoBufHeader {
        steamid: if steam_id != 0 { Some(steam_id) } else { None },
        ..Default::default()
    };

    let login_id = rand_login_id();
    let body = CMsgClientLogon {
        protocol_version: Some(65580),
        client_os_type: Some(20),
        obfuscated_private_ip: Some(CMsgIpAddress {
            ip: Some(c_msg_ip_address::Ip::V4(login_id ^ LOGIN_ID_XOR)),
        }),
        account_name: Some(account_name.to_string()),
        access_token: Some(refresh_token.to_string()),
        should_remember_password: Some(true),
        ..Default::default()
    };

    conn.send(EMsg::ClientLogon, &header, &body.encode_to_vec())
        .await?;

    let session = await_logon_response(conn).await?;
    // Mark as authenticated so downstream code knows this isn't anonymous.
    if let Some(s) = conn.session_mut() {
        s.authenticated = true;
    }
    Ok(session)
}

/// Extract the SteamID from a Steam JWT refresh token's `sub` claim.
///
/// Steam JWTs are base64url-encoded with three dot-separated parts.
/// The payload (middle part) contains `"sub": "<steamid>"`.
fn extract_steamid_from_jwt(token: &str) -> Option<u64> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    // Decode base64url payload (Steam uses standard base64 with spaces in JSON)
    let payload = parts[1];
    let padded = match payload.len() % 4 {
        2 => format!("{}==", payload),
        3 => format!("{}=", payload),
        _ => payload.to_string(),
    };
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &padded,
    ).ok()?;
    let text = std::str::from_utf8(&decoded).ok()?;
    // Simple extraction: find "sub" : "NNNNN"
    let sub_pos = text.find("\"sub\"")?;
    let after = &text[sub_pos + 5..];
    let colon = after.find(':')?;
    let after_colon = &after[colon + 1..];
    let quote_start = after_colon.find('"')? + 1;
    let rest = &after_colon[quote_start..];
    let quote_end = rest.find('"')?;
    rest[..quote_end].parse().ok()
}

// -------------------------------------------------------------------------
// Shared helpers
// -------------------------------------------------------------------------

async fn await_logon_response(conn: &mut CmConnection) -> Result<SessionState> {
    let msg = conn.recv().await?;

    if msg.emsg != EMsg::ClientLogOnResponse {
        return Err(Error::UnexpectedEMsg {
            expected: EMsg::ClientLogOnResponse,
            got: msg.emsg,
        });
    }

    let resp = CMsgClientLogonResponse::decode(msg.body.as_slice())?;

    let eresult = resp.eresult.unwrap_or(2);
    if eresult != 1 {
        return Err(Error::eresult(eresult, "logon failed"));
    }

    let session = SessionState {
        steam_id: msg.header.steamid.unwrap_or(0),
        session_id: msg.header.client_sessionid.unwrap_or(0),
        cell_id: resp.cell_id.unwrap_or(0),
        heartbeat_seconds: resp.heartbeat_seconds.unwrap_or(0),
        authenticated: false, // caller upgrades to true for authenticated logins
        licensed_appids: Default::default(),
    };

    conn.set_session(session);
    Ok(conn.session().unwrap().clone())
}
