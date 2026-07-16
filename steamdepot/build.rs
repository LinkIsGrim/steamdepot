fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(
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
