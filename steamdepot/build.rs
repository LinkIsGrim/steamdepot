fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Manifest types get serde derives so callers can cache a resolved
    // DepotManifest to disk (keyed by depot_id + manifest_id) instead of
    // refetching it from the CDN every run when nothing's changed.
    let mut config = prost_build::Config::new();
    for ty in [
        "ContentManifestPayload",
        "ContentManifestPayload.FileMapping",
        "ContentManifestPayload.FileMapping.ChunkData",
        "ContentManifestMetadata",
        "ContentManifestSignature",
    ] {
        config.type_attribute(ty, "#[derive(serde::Serialize, serde::Deserialize)]");
    }

    config.compile_protos(
        &[
            "proto/steam/steammessages_base.proto",
            "proto/steam/steammessages_clientserver_login.proto",
            "proto/steam/steammessages_clientserver_appinfo.proto",
            "proto/steam/steammessages_clientserver_2.proto",
            "proto/steam/steammessages_unified_base.steamclient.proto",
            "proto/steam/steammessages_contentsystem.steamclient.proto",
            "proto/steam/steammessages_auth.steamclient.proto",
            "proto/steam/content_manifest.proto",
            "proto/steam/steammessages_publishedfile.steamclient.proto",
        ],
        &["proto/steam", "proto"],
    )?;
    Ok(())
}
