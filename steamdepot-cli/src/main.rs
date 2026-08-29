use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use clap::{Parser, ValueEnum};
use serde_json::json;
use steamdepot::cdn::CdnPool;
use steamdepot::connection::CmConnection;
use steamdepot::depot::{self, DownloadConfig, DownloadPlan};
use steamdepot::download::{self, DownloadProgress, PrepareResult};
use steamdepot::error::Result;
use steamdepot::login;
use steamdepot::pics;
use steamdepot::proto::{content_manifest_payload, ContentManifestMetadata};
use steamdepot::steam_api::cm_list::{self, CmServerType};

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
enum LogMode {
    Human,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "steamdepot", about = "Download Steam depot content")]
struct Cli {
    /// Log output format
    #[arg(long, default_value = "human")]
    logmode: LogMode,

    /// App IDs to fetch product info for
    #[arg(long = "app-id")]
    app_ids: Vec<u32>,

    /// Package IDs to fetch product info for
    #[arg(long = "package-id")]
    package_ids: Vec<u32>,

    /// Fetch decryption key for a depot (requires --depot-app-id)
    #[arg(long = "depot-id")]
    depot_id: Option<u32>,

    /// App ID that owns the depot (used with --depot-id)
    #[arg(long = "depot-app-id")]
    depot_app_id: Option<u32>,

    /// Prepare a full download plan for an app (resolve depots + fetch keys)
    #[arg(long = "download")]
    download: Option<u32>,

    /// Target OS for depot filtering
    #[arg(long, default_value = "linux")]
    os: String,

    /// Target branch for manifest resolution
    #[arg(long, default_value = "public")]
    branch: String,

    /// Also fetch manifests from CDN (requires --download)
    #[arg(long)]
    fetch_manifests: bool,

    /// Directory to install depot content into (requires --fetch-manifests)
    #[arg(long)]
    install_dir: Option<PathBuf>,

    /// Login ID for the anonymous session (default: random)
    #[arg(long)]
    login_id: Option<u32>,

    /// Steam account name (enables authenticated login)
    #[arg(long)]
    username: Option<String>,

    /// Refresh token for authenticated login
    #[arg(long)]
    token: Option<String>,
}

// ---------------------------------------------------------------------------
// Logging helpers — dual-mode (human / JSON) output, keeping main clean.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Log {
    mode: LogMode,
}

impl Log {
    fn new(mode: LogMode) -> Self {
        Self { mode }
    }

    fn json(&self) -> bool {
        self.mode == LogMode::Json
    }

    fn cm_servers(&self, count: usize) {
        if self.json() {
            Self::jline(json!({"type": "cm_servers", "count": count}));
        } else {
            println!("CM servers: {} found", count);
        }
    }

    fn connecting(&self, endpoint: &str) {
        if self.json() {
            Self::jline(json!({"type": "connecting", "endpoint": endpoint}));
        } else {
            println!("Connecting to {}...", endpoint);
        }
    }

    fn login(&self, mode: &str, steam_id: u64, session_id: i32, cell_id: u32, heartbeat: i32) {
        if self.json() {
            Self::jline(json!({
                "type": "login",
                "mode": mode,
                "steam_id": steam_id,
                "session_id": session_id,
                "cell_id": cell_id,
                "heartbeat_seconds": heartbeat
            }));
        } else {
            println!("Logged in {}!", mode);
            println!("  steam_id:          {}", steam_id);
            println!("  session_id:        {}", session_id);
            println!("  cell_id:           {}", cell_id);
            println!("  heartbeat_seconds: {}", heartbeat);
        }
    }

    fn app_info(&self, appid: u32, change_number: u32, buffer: &[u8]) {
        if self.json() {
            Self::jline(json!({
                "type": "app_info",
                "app_id": appid,
                "change_number": change_number,
                "buffer_len": buffer.len()
            }));
        } else {
            println!("\n[app {}] change_number={}", appid, change_number);
            match std::str::from_utf8(buffer) {
                Ok(text) => println!("{}", text),
                Err(_) => println!("  ({} bytes, non-utf8)", buffer.len()),
            }
        }
    }

    fn package_info(&self, packageid: u32, change_number: u32, buffer_len: usize) {
        if self.json() {
            Self::jline(json!({
                "type": "package_info",
                "package_id": packageid,
                "change_number": change_number,
                "buffer_len": buffer_len
            }));
        } else {
            println!(
                "\n[package {}] change_number={} ({} bytes)",
                packageid, change_number, buffer_len
            );
        }
    }

    fn depot_key(&self, depot_id: u32, app_id: u32, key: &[u8]) {
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        if self.json() {
            Self::jline(json!({"type": "depot_key", "depot_id": depot_id, "app_id": app_id, "key": hex}));
        } else {
            println!("  depot_encryption_key: {}", hex);
        }
    }

    fn plan_start(&self, app_id: u32, os: &str, branch: &str) {
        if self.json() {
            Self::jline(json!({"type": "plan_start", "app_id": app_id, "os": os, "branch": branch}));
        } else {
            println!(
                "\nPreparing download plan for app {} (os={}, branch={})...",
                app_id, os, branch
            );
        }
    }

    fn plan(&self, plan: &DownloadPlan) {
        if plan.plans.is_empty() {
            if self.json() {
                Self::jline(json!({"type": "plan_empty", "app_id": plan.app_id}));
            } else {
                println!("  No depots found");
            }
            return;
        }
        if !plan.granted_appids.is_empty() || !plan.granted_packageids.is_empty() {
            if self.json() {
                Self::jline(json!({
                    "type": "license_granted",
                    "app_id": plan.app_id,
                    "granted_appids": plan.granted_appids,
                    "granted_packageids": plan.granted_packageids
                }));
            } else {
                println!(
                    "  Free license granted: apps={:?} packages={:?}",
                    plan.granted_appids, plan.granted_packageids
                );
            }
        }
        if self.json() {
            let depots: Vec<_> = plan.plans.iter().map(|dp| {
                let hex: String = dp.key.iter().map(|b| format!("{:02x}", b)).collect();
                json!({
                    "depot_id": dp.depot.depot_id,
                    "manifest_id": dp.depot.manifest_id,
                    "key": hex,
                    "depot_from_app": dp.depot.depot_from_app
                })
            }).collect();
            Self::jline(json!({"type": "plan", "app_id": plan.app_id, "depots": depots}));
        } else {
            println!("  {} depot(s) resolved:\n", plan.plans.len());
            for dp in &plan.plans {
                let hex: String = dp.key.iter().map(|b| format!("{:02x}", b)).collect();
                print!(
                    "  depot {:>7}  manifest {:>20}  key={}",
                    dp.depot.depot_id, dp.depot.manifest_id, hex
                );
                if let Some(from) = dp.depot.depot_from_app {
                    print!("  (depotfromapp={})", from);
                }
                println!();
            }
        }
    }

    fn cdn_servers(&self, count: usize) {
        if self.json() {
            Self::jline(json!({"type": "cdn_servers", "count": count}));
        } else {
            println!("  CDN servers: {} available", count);
        }
    }

    fn manifest(
        &self,
        app_id: u32,
        depot_id: u32,
        request_code: u64,
        meta: &ContentManifestMetadata,
        file_count: usize,
    ) {
        if self.json() {
            Self::jline(json!({
                "type": "manifest",
                "app_id": app_id,
                "depot_id": depot_id,
                "gid_manifest": meta.gid_manifest.unwrap_or(0),
                "creation_time": meta.creation_time.unwrap_or(0),
                "files": file_count,
                "unique_chunks": meta.unique_chunks.unwrap_or(0),
                "bytes_original": meta.cb_disk_original.unwrap_or(0),
                "bytes_compressed": meta.cb_disk_compressed.unwrap_or(0)
            }));
        } else {
            println!(
                "\n  depot {}  request_code={}",
                depot_id, request_code
            );
            println!(
                "    depot_id={} gid_manifest={} creation_time={}",
                meta.depot_id.unwrap_or(0),
                meta.gid_manifest.unwrap_or(0),
                meta.creation_time.unwrap_or(0),
            );
            println!(
                "    files={} unique_chunks={}",
                file_count,
                meta.unique_chunks.unwrap_or(0),
            );
            println!(
                "    disk_original={} disk_compressed={}",
                meta.cb_disk_original.unwrap_or(0),
                meta.cb_disk_compressed.unwrap_or(0),
            );
        }
    }

    fn file_listing(
        &self,
        mappings: &[content_manifest_payload::FileMapping],
    ) {
        if self.json() {
            return;
        }
        let total = mappings.len();
        let show = if total <= 100 { total } else { 20 };
        if total > show {
            println!("    (showing first {} of {} files)", show, total);
        }
        for f in mappings.iter().take(show) {
            let name = f.filename.as_deref().unwrap_or("?");
            let size = f.size.unwrap_or(0);
            let chunks = f.chunks.len();
            let flags = f.flags.unwrap_or(0);
            println!(
                "      {:>12}  {:>3} chunk(s)  flags={:#06x}  {}",
                size, chunks, flags, name
            );
        }
        if total > show {
            println!("      ...");
        }
    }

    fn prepare(&self, app_id: u32, depot_id: u32, install_dir: &Path) {
        if self.json() {
            Self::jline(json!({
                "type": "prepare",
                "app_id": app_id,
                "depot_id": depot_id,
                "install_dir": install_dir.display().to_string()
            }));
        } else {
            println!("\n    Preparing directory tree in {}...", install_dir.display());
        }
    }

    fn prepared(&self, app_id: u32, depot_id: u32, r: &PrepareResult) {
        if self.json() {
            Self::jline(json!({
                "type": "prepared",
                "app_id": app_id,
                "depot_id": depot_id,
                "dirs_created": r.dirs_created,
                "files_created": r.files_created,
                "symlinks_created": r.symlinks_created,
                "bytes_total": r.total_bytes
            }));
        } else {
            println!(
                "    Created {} dirs, {} files, {} symlinks ({} bytes total)",
                r.dirs_created, r.files_created, r.symlinks_created, r.total_bytes,
            );
        }
    }

    fn download_start(&self, cdn_count: usize) {
        if !self.json() {
            println!(
                "    Downloading chunks ({} CDN servers in pool)...",
                cdn_count
            );
        }
    }

    fn progress(
        &self,
        app_id: u32,
        depot_id: u32,
        bytes_total: u64,
        p: &DownloadProgress,
        last_pct: &AtomicU32,
        last_human_time: &Mutex<Instant>,
    ) {
        let pct = if bytes_total > 0 {
            ((p.bytes_downloaded as f64 / bytes_total as f64) * 100.0).min(100.0) as u32
        } else {
            0
        };

        if self.json() {
            // Emit on whole-percent thresholds (sentinel u32::MAX = not yet started)
            let prev = last_pct.load(Ordering::Relaxed);
            if prev != u32::MAX && pct <= prev {
                return;
            }
            if last_pct.compare_exchange(prev, pct, Ordering::Relaxed, Ordering::Relaxed).is_err() {
                return; // another thread already emitted this threshold
            }
            Self::jline(json!({
                "type": "progress",
                "app_id": app_id,
                "depot_id": depot_id,
                "bytes_downloaded": p.bytes_downloaded,
                "bytes_total": bytes_total,
                "pct": pct
            }));
        } else {
            // Throttle human output to at most every 250ms
            let mut last = last_human_time.lock().unwrap();
            let now = Instant::now();
            let is_final = p.chunks_done == p.chunks_total;
            if !is_final && now.duration_since(*last).as_millis() < 250 {
                return;
            }
            *last = now;
            eprint!(
                "\r    chunks: {}/{}  bytes: {}",
                p.chunks_done, p.chunks_total, p.bytes_downloaded,
            );
        }
    }

    fn download_complete(&self, app_id: u32, depot_id: u32, r: &DownloadProgress) {
        if self.json() {
            Self::jline(json!({
                "type": "complete",
                "app_id": app_id,
                "depot_id": depot_id,
                "chunks_done": r.chunks_done,
                "bytes_downloaded": r.bytes_downloaded
            }));
        } else {
            eprintln!();
            println!(
                "    Download complete: {} chunks, {} bytes downloaded",
                r.chunks_done, r.bytes_downloaded,
            );
        }
    }

    fn disconnected(&self) {
        if self.json() {
            Self::jline(json!({"type": "disconnected"}));
        } else {
            println!("\nDisconnected.");
        }
    }

    fn error(&self, msg: &str) {
        if self.json() {
            Self::jline(json!({"type": "error", "msg": msg}));
        } else {
            println!("  Error: {}", msg);
        }
    }

    fn jline(v: serde_json::Value) {
        println!("{}", serde_json::to_string(&v).unwrap());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log = Log::new(cli.logmode);
    let client = reqwest::Client::new();

    let cm_list = cm_list::get_cm_list(&client).await?;
    log.cm_servers(cm_list.serverlist.len());

    let ws_server = cm_list
        .serverlist
        .iter()
        .find(|s| s.server_type == CmServerType::Websockets)
        .ok_or_else(|| steamdepot::error::Error::Other("no websocket CM server found".into()))?;

    log.connecting(&ws_server.endpoint);

    let mut conn = CmConnection::connect(&ws_server.endpoint).await?;

    let session = match (&cli.username, &cli.token) {
        (Some(username), Some(token)) => {
            login::login_with_token(&mut conn, username, token).await?
        }
        (Some(_), None) => {
            return Err(steamdepot::error::Error::Other(
                "--username requires --token".into(),
            ));
        }
        (None, Some(_)) => {
            return Err(steamdepot::error::Error::Other(
                "--token requires --username".into(),
            ));
        }
        (None, None) => {
            let login_id = cli.login_id.unwrap_or_else(login::rand_login_id);
            login::login_anonymous_with_id(&mut conn, login_id).await?
        }
    };

    let auth_mode = if cli.username.is_some() {
        "authenticated"
    } else {
        "anonymously"
    };
    log.login(
        auth_mode,
        session.steam_id,
        session.session_id,
        session.cell_id,
        session.heartbeat_seconds,
    );

    conn.start_heartbeat();

    if !cli.app_ids.is_empty() || !cli.package_ids.is_empty() {
        let info = pics::get_product_info(&mut conn, &cli.app_ids, &cli.package_ids).await?;

        for app in &info.apps {
            log.app_info(app.appid, app.change_number, &app.buffer);
        }
        for pkg in &info.packages {
            log.package_info(pkg.packageid, pkg.change_number, pkg.buffer.len());
        }
    }

    if let (Some(depot_id), Some(app_id)) = (cli.depot_id, cli.depot_app_id) {
        match pics::get_depot_decryption_key(&mut conn, depot_id, app_id).await {
            Ok(key) => log.depot_key(depot_id, app_id, &key),
            Err(e) => log.error(&e.to_string()),
        }
    }

    if let Some(app_id) = cli.download {
        log.plan_start(app_id, &cli.os, &cli.branch);

        let config = DownloadConfig {
            app_id,
            os: cli.os.clone(),
            branch: cli.branch.clone(),
        };

        let mut plan = depot::prepare_download(&mut conn, &config).await?;
        log.plan(&plan);

        if cli.fetch_manifests && !plan.plans.is_empty() {
            depot::fetch_manifests(&mut conn, &client, &mut plan, &cli.branch).await?;
            log.cdn_servers(plan.cdn_servers.len());

            for dp in &mut plan.plans {
                if let Some(manifest) = &mut dp.manifest {
                    download::decrypt_manifest_filenames(manifest, &dp.key)?;

                    let request_code = dp.manifest_request_code.unwrap_or(0);
                    log.manifest(
                        app_id,
                        dp.depot.depot_id,
                        request_code,
                        &manifest.metadata,
                        manifest.payload.mappings.len(),
                    );
                    log.file_listing(&manifest.payload.mappings);

                    if let Some(ref install_dir) = cli.install_dir {
                        log.prepare(app_id, dp.depot.depot_id, install_dir);

                        let result =
                            download::prepare_directory_tree(install_dir, manifest, download::PathOptions::preserve_case()).await?;
                        log.prepared(app_id, dp.depot.depot_id, &result);

                        let mut cdn_pool = CdnPool::new(plan.cdn_servers.clone());
                        for (depot_id, host, token) in &plan.cdn_auth_tokens {
                            cdn_pool.set_cdn_auth_token(*depot_id, host, token.clone());
                        }
                        let pool = Arc::new(Mutex::new(cdn_pool));
                        log.download_start(plan.cdn_servers.len());

                        let bytes_total =
                            manifest.metadata.cb_disk_compressed.unwrap_or(0);
                        let dl_depot_id = dp.depot.depot_id;
                        let last_pct = Arc::new(AtomicU32::new(u32::MAX));
                        let last_human_time = Arc::new(Mutex::new(Instant::now()));
                        let dl_result = download::download_depot(
                            &client,
                            pool,
                            dp.depot.depot_id,
                            manifest,
                            &dp.key,
                            install_dir,
                            8,
                            move |p| {
                                log.progress(
                                    app_id, dl_depot_id, bytes_total, p,
                                    &last_pct, &last_human_time,
                                );
                            },
                        )
                        .await?;
                        log.download_complete(app_id, dp.depot.depot_id, &dl_result);
                    }
                }
            }
        }
    }

    conn.shutdown().await?;
    log.disconnected();

    Ok(())
}
