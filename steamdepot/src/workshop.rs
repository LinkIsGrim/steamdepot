//! Workshop item resolution via `IPublishedFileService.GetDetails`.
//!
//! Unlike app depots (resolved through PICS product info), workshop items
//! have no depot listing to walk — each item's current manifest is fetched
//! directly by published file ID. The resolved `(depot_id, manifest_id)`
//! pair then flows through the same [`crate::cdn`] / [`crate::download`]
//! pipeline used for app depots: `depot_id` is the item's `consumer_appid`
//! (Steam treats the whole workshop's content for an app as a single depot
//! keyed by that app's ID), and `manifest_id` is `hcontent_file`.

use prost::Message;

use crate::connection::CmConnection;
use crate::error::{Error, Result};
use crate::proto::{CPublishedFileGetDetailsRequest, CPublishedFileGetDetailsResponse};

/// A resolved workshop item, ready to feed into the depot download pipeline.
#[derive(Debug, Clone)]
pub struct WorkshopItem {
    pub published_file_id: u64,
    /// The app whose depot this item's content is stored under; also the
    /// `depot_id` to use for key/manifest-code requests.
    pub consumer_appid: u32,
    pub manifest_id: u64,
    pub filename: String,
    pub file_size: u64,
    pub time_updated: u32,
}

/// Fetch details for a batch of workshop items and resolve each into a
/// downloadable `(depot_id, manifest_id)` pair.
///
/// Items Steam reports an error for (unlisted, banned, deleted) are skipped
/// with a warning rather than failing the whole batch.
pub async fn get_details(
    conn: &mut CmConnection,
    published_file_ids: &[u64],
) -> Result<Vec<WorkshopItem>> {
    if published_file_ids.is_empty() {
        return Ok(Vec::new());
    }

    let req = CPublishedFileGetDetailsRequest {
        publishedfileids: published_file_ids.to_vec(),
        includemetadata: Some(true),
        ..Default::default()
    };

    let resp_bytes = conn
        .service_method_call("PublishedFile.GetDetails#1", &req.encode_to_vec())
        .await?;
    let resp = CPublishedFileGetDetailsResponse::decode(resp_bytes.as_slice())?;

    let mut items = Vec::new();
    for details in resp.publishedfiledetails {
        let id = details.publishedfileid.unwrap_or(0);
        let eresult = details.result.unwrap_or(0);
        if eresult != 1 {
            eprintln!(
                "warning: workshop item {} GetDetails returned eresult {} (skipping)",
                id, eresult
            );
            continue;
        }

        let consumer_appid = match details.consumer_appid {
            Some(id) if id != 0 => id,
            _ => {
                eprintln!("warning: workshop item {} has no consumer_appid (skipping)", id);
                continue;
            }
        };
        let manifest_id = match details.hcontent_file {
            Some(id) if id != 0 => id,
            _ => {
                eprintln!("warning: workshop item {} has no hcontent_file/manifest (skipping)", id);
                continue;
            }
        };

        items.push(WorkshopItem {
            published_file_id: id,
            consumer_appid,
            manifest_id,
            filename: details.filename.unwrap_or_default(),
            file_size: details.file_size.unwrap_or(0),
            time_updated: details.time_updated.unwrap_or(0),
        });
    }

    Ok(items)
}

/// Convenience wrapper for a single item, erroring instead of skipping if
/// Steam can't resolve it.
pub async fn get_item(conn: &mut CmConnection, published_file_id: u64) -> Result<WorkshopItem> {
    get_details(conn, &[published_file_id])
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            Error::Other(format!(
                "workshop item {} could not be resolved (unlisted, banned, or deleted?)",
                published_file_id
            ))
        })
}
