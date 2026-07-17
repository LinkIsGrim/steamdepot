//! Convenience wrappers around the low-level login and connection APIs.
//!
//! ```ignore
//! use steamdepot::auth;
//! use steamdepot::login::GuardType;
//!
//! let (mut conn, session) = auth::begin("username", "password").await?;
//!
//! if session.needs_guard(GuardType::EmailCode) {
//!     let code = mail_server.recv_code().await?;
//!     auth::submit_guard(&mut conn, &session, &code, GuardType::EmailCode).await?;
//! }
//!
//! let tokens = auth::poll(&mut conn, &session).await?;
//! ```

use crate::connection::CmConnection;
use crate::error::{Error, Result};
use crate::login::{self, AuthSession, AuthTokens, GuardType};
use crate::steam_api::cm_list::{self, CmServerType};

/// Connect to a CM server and perform anonymous login.
///
/// This is the shared setup for all auth flows — the anonymous login
/// establishes the session required for service method calls.
/// Open a fresh CM connection for the auth-negotiation flow (RSA key,
/// begin auth session, poll). No login here -- those calls all go out
/// unauthenticated (`service_method_call_unauthed`), since they exist
/// specifically to establish a new session and shouldn't require one to
/// already be logged on. An anonymous ClientLogon used to happen here
/// first, which cost a full extra round-trip for no benefit -- the
/// account's actual session gets established afterward, over a *different*
/// connection, via `login::login_with_token` once auth negotiation hands
/// back a refresh token.
async fn connect_and_login() -> Result<CmConnection> {
    let client = reqwest::Client::new();
    let cm_list = cm_list::get_cm_list(&client).await?;

    let ws_server = cm_list
        .serverlist
        .iter()
        .find(|s| s.server_type == CmServerType::Websockets)
        .ok_or_else(|| Error::Other("no websocket CM server found".into()))?;

    CmConnection::connect(&ws_server.endpoint).await
}

/// Begin an authenticated session: resolve a CM server, connect, fetch the
/// RSA key, encrypt the password, and start the auth session.
pub async fn begin(username: &str, password: &str) -> Result<(CmConnection, AuthSession)> {
    let mut conn = connect_and_login().await?;

    let rsa_key = login::get_password_rsa_key(&mut conn, username).await?;
    let encrypted = login::encrypt_password(password, &rsa_key)?;
    let session =
        login::begin_auth_session(&mut conn, username, &encrypted, rsa_key.timestamp).await?;

    Ok((conn, session))
}

/// Begin a passwordless auth session for a newly created account.
///
/// Resolves a CM server, connects, and starts an auth session with just the
/// account name/email (no password). Steam will send a verification email.
pub async fn begin_passwordless(username: &str) -> Result<(CmConnection, AuthSession)> {
    let mut conn = connect_and_login().await?;

    let session = login::begin_auth_session_passwordless(&mut conn, username).await?;

    Ok((conn, session))
}

/// Submit a Steam Guard code for the given auth session.
pub async fn submit_guard(
    conn: &mut CmConnection,
    session: &AuthSession,
    code: &str,
    guard_type: GuardType,
) -> Result<()> {
    login::submit_guard_code(conn, session, code, guard_type).await
}

/// Poll until the auth session is confirmed and tokens are issued.
pub async fn poll(conn: &mut CmConnection, session: &AuthSession) -> Result<AuthTokens> {
    login::poll_auth_status(conn, session).await
}
