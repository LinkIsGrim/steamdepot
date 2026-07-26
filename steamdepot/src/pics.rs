use prost::Message;

use crate::connection::CmConnection;
use crate::emsg::EMsg;
use crate::error::{Error, Result};
use crate::proto::{
    c_msg_client_pics_product_info_request as req_types,
    CMsgClientGetDepotDecryptionKey, CMsgClientGetDepotDecryptionKeyResponse,
    CMsgClientPicsAccessTokenRequest, CMsgClientPicsAccessTokenResponse,
    CMsgClientPicsProductInfoRequest as PicsRequest,
    CMsgClientPicsProductInfoResponse as PicsResponse,
    CMsgClientRequestFreeLicense, CMsgClientRequestFreeLicenseResponse,
};

/// Returned product info for a single app.
#[derive(Debug, Clone)]
pub struct AppProductInfo {
    pub appid: u32,
    pub change_number: u32,
    pub buffer: Vec<u8>,
}

/// Returned product info for a single package.
#[derive(Debug, Clone)]
pub struct PackageProductInfo {
    pub packageid: u32,
    pub change_number: u32,
    pub buffer: Vec<u8>,
}

/// Result of a PICSGetProductInfo call.
#[derive(Debug, Default)]
pub struct ProductInfoResponse {
    pub apps: Vec<AppProductInfo>,
    pub unknown_appids: Vec<u32>,
    pub packages: Vec<PackageProductInfo>,
    pub unknown_packageids: Vec<u32>,
}

/// Fetch PICS access tokens for the given app and/or package IDs.
///
/// Access tokens are required by `get_product_info` — without them, Steam may
/// silently drop the PICS response (especially for anonymous sessions).
async fn get_access_tokens(
    conn: &mut CmConnection,
    app_ids: &[u32],
    package_ids: &[u32],
) -> Result<(Vec<(u32, u64)>, Vec<(u32, u64)>)> {
    let header = conn.session_header()?;

    let body = CMsgClientPicsAccessTokenRequest {
        appids: app_ids.to_vec(),
        packageids: package_ids.to_vec(),
    };

    conn.send(
        EMsg::ClientPICSAccessTokenRequest,
        &header,
        &body.encode_to_vec(),
    )
    .await?;

    loop {
        let msg = conn.recv().await?;
        if msg.emsg != EMsg::ClientPICSAccessTokenResponse {
            continue;
        }

        let resp = CMsgClientPicsAccessTokenResponse::decode(msg.body)?;

        let app_tokens: Vec<(u32, u64)> = resp
            .app_access_tokens
            .iter()
            .filter_map(|t| Some((t.appid?, t.access_token?)))
            .collect();

        let pkg_tokens: Vec<(u32, u64)> = resp
            .package_access_tokens
            .iter()
            .filter_map(|t| Some((t.packageid?, t.access_token?)))
            .collect();

        return Ok((app_tokens, pkg_tokens));
    }
}

/// Fetch product info for the given app and/or package IDs.
///
/// Automatically fetches PICS access tokens first (matching DepotDownloader
/// and SteamKit2 behavior). Handles multi-part responses (`response_pending`)
/// automatically, collecting all chunks before returning.
pub async fn get_product_info(
    conn: &mut CmConnection,
    app_ids: &[u32],
    package_ids: &[u32],
) -> Result<ProductInfoResponse> {
    // Step 1: Fetch access tokens (required for anonymous sessions)
    let (app_tokens, pkg_tokens) = get_access_tokens(conn, app_ids, package_ids).await?;

    let header = conn.session_header()?;

    let body = PicsRequest {
        apps: app_ids
            .iter()
            .map(|&id| {
                let token = app_tokens
                    .iter()
                    .find(|(aid, _)| *aid == id)
                    .map(|(_, t)| *t);
                req_types::AppInfo {
                    appid: Some(id),
                    access_token: token,
                    only_public_obsolete: None,
                }
            })
            .collect(),
        packages: package_ids
            .iter()
            .map(|&id| {
                let token = pkg_tokens
                    .iter()
                    .find(|(pid, _)| *pid == id)
                    .map(|(_, t)| *t);
                req_types::PackageInfo {
                    packageid: Some(id),
                    access_token: token,
                }
            })
            .collect(),
        meta_data_only: Some(false),
        single_response: Some(false),
        ..Default::default()
    };

    conn.send(
        EMsg::ClientPICSProductInfoRequest,
        &header,
        &body.encode_to_vec(),
    )
    .await?;

    let mut result = ProductInfoResponse::default();

    loop {
        let msg = conn.recv().await?;

        if msg.emsg != EMsg::ClientPICSProductInfoResponse {
            continue;
        }

        let resp = PicsResponse::decode(msg.body)?;

        for app in resp.apps {
            result.apps.push(AppProductInfo {
                appid: app.appid.unwrap_or(0),
                change_number: app.change_number.unwrap_or(0),
                buffer: app.buffer.unwrap_or_default(),
            });
        }
        result.unknown_appids.extend(resp.unknown_appids);

        for pkg in resp.packages {
            result.packages.push(PackageProductInfo {
                packageid: pkg.packageid.unwrap_or(0),
                change_number: pkg.change_number.unwrap_or(0),
                buffer: pkg.buffer.unwrap_or_default(),
            });
        }
        result.unknown_packageids.extend(resp.unknown_packageids);

        if !resp.response_pending.unwrap_or(false) {
            break;
        }
    }

    Ok(result)
}

/// Fetch the decryption key for a depot.
///
/// Returns the raw key bytes on success, or an error if the server refuses
/// (e.g. the account doesn't own the app).
pub async fn get_depot_decryption_key(
    conn: &mut CmConnection,
    depot_id: u32,
    app_id: u32,
) -> Result<Vec<u8>> {
    let header = conn.session_header()?;

    let body = CMsgClientGetDepotDecryptionKey {
        depot_id: Some(depot_id),
        app_id: Some(app_id),
    };

    conn.send(
        EMsg::ClientGetDepotDecryptionKey,
        &header,
        &body.encode_to_vec(),
    )
    .await?;

    loop {
        let msg = conn.recv().await?;

        if msg.emsg != EMsg::ClientGetDepotDecryptionKeyResponse {
            continue;
        }

        let resp = CMsgClientGetDepotDecryptionKeyResponse::decode(msg.body)?;

        let eresult = resp.eresult.unwrap_or(2);
        if eresult != 1 {
            let reason = match eresult {
                2 => "invalid depot/app combination",
                5 => "access denied — account doesn't own this app/depot",
                15 => "access denied — the account does not have a license for this app. \
                       If this is a free game, claim the free license on the Steam account first",
                9 => "file not found — depot does not exist",
                _ => "unexpected error",
            };
            return Err(Error::eresult(
                eresult,
                format!("depot {} (app {}) decryption key: {}", depot_id, app_id, reason),
            ));
        }

        return Ok(resp.depot_encryption_key.unwrap_or_default());
    }
}

/// Result of a free license request.
#[derive(Debug)]
pub struct FreeLicenseResponse {
    pub granted_appids: Vec<u32>,
    pub granted_packageids: Vec<u32>,
}

/// Request a free license for the given app IDs.
///
/// Steam grants free-to-play / free-to-download licenses on demand. This is
/// required for anonymous accounts to access dedicated server depots like
/// TF2 Classic (3557020).
pub async fn request_free_license(
    conn: &mut CmConnection,
    app_ids: &[u32],
) -> Result<FreeLicenseResponse> {
    let header = conn.session_header()?;

    let body = CMsgClientRequestFreeLicense {
        appids: app_ids.to_vec(),
    };

    conn.send(
        EMsg::ClientRequestFreeLicense,
        &header,
        &body.encode_to_vec(),
    )
    .await?;

    loop {
        let msg = conn.recv().await?;

        if msg.emsg != EMsg::ClientRequestFreeLicenseResponse {
            continue;
        }

        let resp = CMsgClientRequestFreeLicenseResponse::decode(msg.body)?;

        let eresult = resp.eresult.unwrap_or(2);
        if eresult != 1 {
            return Err(Error::eresult(
                eresult as i32,
                format!("free license request for {:?}", app_ids),
            ));
        }

        return Ok(FreeLicenseResponse {
            granted_appids: resp.granted_appids,
            granted_packageids: resp.granted_packageids,
        });
    }
}
