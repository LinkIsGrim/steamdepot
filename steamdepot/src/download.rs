use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::cdn::{CdnPool, DepotManifest};
use crate::crypto;
use crate::error::{Error, Result};

#[cfg_attr(windows, allow(dead_code))] // only read inside the #[cfg(unix)] executable-bit block below
const FLAG_EXECUTABLE: u32 = 0x20;
const FLAG_DIRECTORY: u32 = 0x40;
const FLAG_SYMLINK: u32 = 0x200;

const MAX_RETRIES: u32 = 3;

/// Summary of what `prepare_directory_tree` created.
#[derive(Debug)]
pub struct PrepareResult {
    pub dirs_created: u64,
    pub files_created: u64,
    pub symlinks_created: u64,
    pub total_bytes: u64,
    /// Regular files that already existed at the manifest's target size,
    /// left untouched pending chunk-level verification.
    pub verify_candidates: Vec<PathBuf>,
}

/// How a manifest filename becomes a path on disk.
///
/// Depot content is authored on Windows, so manifests carry backslashes
/// and whatever casing the author used. Separators are always normalized;
/// casing is a choice, because some consumers need it folded and some
/// must not have it touched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathOptions {
    /// Write every path in lowercase.
    ///
    /// For Arma 3 (and other engines that build internal paths in
    /// lowercase), content on a case-sensitive filesystem is unusable
    /// otherwise -- the engine reports `The filename '...' is not
    /// lowercase. You have to convert it!` and skips the file.
    ///
    /// This belongs here, rather than in a pass that renames files after
    /// the fact, because the manifest is also what the *next* sync
    /// verifies against. A post-hoc rename leaves the tree no longer
    /// matching the manifest, so `prepare_directory_tree` (which only
    /// ever creates, never prunes) re-creates every renamed file under
    /// its original name on the next content update, and the folded
    /// copies are left beside them -- the engine then loads both. Folding
    /// at the point the path is derived keeps the mapping total and
    /// one-way, so that state can't arise and incremental chunk
    /// verification keeps working across updates.
    pub lowercase: bool,
}

impl PathOptions {
    /// Manifest casing, separators normalized. The default.
    pub fn preserve_case() -> Self {
        Self { lowercase: false }
    }

    /// Fold every path to lowercase -- see [`PathOptions::lowercase`].
    pub fn lowercase() -> Self {
        Self { lowercase: true }
    }

    /// A manifest filename as a depot-relative path.
    fn relative(&self, filename: &str) -> String {
        let normalized = filename.replace('\\', "/");
        if self.lowercase {
            normalized.to_lowercase()
        } else {
            normalized
        }
    }
}

/// Reject a manifest whose filenames would collide once folded.
///
/// Only possible with [`PathOptions::lowercase`], and only for content
/// shipping two names differing solely by case. Refusing up front is
/// deliberate: folding them would have one silently overwrite the other,
/// which loses content and is far harder to diagnose than a failed sync
/// naming both paths.
fn check_for_collisions(manifest: &DepotManifest, options: PathOptions) -> Result<()> {
    if !options.lowercase {
        return Ok(());
    }
    let mut seen: HashMap<String, &str> = HashMap::new();
    for mapping in &manifest.payload.mappings {
        let Some(filename) = mapping.filename.as_deref() else {
            continue;
        };
        let folded = options.relative(filename);
        if let Some(previous) = seen.insert(folded.clone(), filename) {
            if previous != filename {
                return Err(Error::Other(format!(
                    "cannot lowercase this depot: {previous:?} and {filename:?} both become \
                     {folded:?}, so one would overwrite the other"
                )));
            }
        }
    }
    Ok(())
}

/// Decrypt all encrypted filenames in a manifest in-place.
///
/// If `metadata.filenames_encrypted` is false (or absent), this is a no-op.
pub fn decrypt_manifest_filenames(manifest: &mut DepotManifest, key: &[u8]) -> Result<()> {
    if !manifest.metadata.filenames_encrypted.unwrap_or(false) {
        return Ok(());
    }

    for mapping in &mut manifest.payload.mappings {
        if let Some(ref encrypted) = mapping.filename {
            let decrypted = crypto::decrypt_filename(key, encrypted)?;
            mapping.filename = Some(decrypted);
        }
    }

    manifest.metadata.filenames_encrypted = Some(false);
    Ok(())
}

/// Create the directory tree and pre-allocate files at their final sizes.
///
/// Handles directories (flag 0x40), symlinks (flag 0x200), and regular files.
/// For regular files, sets executable permission when flag 0x20 is set.
///
/// A regular file that already exists on disk at exactly the manifest's
/// target size is left untouched (not truncated) and added to
/// `result.verify_candidates`, so its content can be checked chunk-by-chunk
/// against the manifest instead of being blindly redownloaded -- anything
/// else (missing, wrong size) is freshly created/truncated as before, since
/// there's nothing worth verifying.
pub async fn prepare_directory_tree(
    install_dir: &Path,
    manifest: &DepotManifest,
    options: PathOptions,
) -> Result<PrepareResult> {
    check_for_collisions(manifest, options)?;

    let mut result = PrepareResult {
        dirs_created: 0,
        files_created: 0,
        symlinks_created: 0,
        total_bytes: 0,
        verify_candidates: Vec::new(),
    };

    // Sort mappings by filename for deterministic creation order
    let mut mappings: Vec<_> = manifest.payload.mappings.iter().collect();
    mappings.sort_by(|a, b| {
        let a_name = a.filename.as_deref().unwrap_or("");
        let b_name = b.filename.as_deref().unwrap_or("");
        a_name.cmp(b_name)
    });

    for mapping in &mappings {
        let filename = match mapping.filename.as_deref() {
            Some(f) => f,
            None => continue,
        };
        let flags = mapping.flags.unwrap_or(0);
        let size = mapping.size.unwrap_or(0);

        let normalized = options.relative(filename);
        let path = install_dir.join(&normalized);

        if flags & FLAG_DIRECTORY != 0 {
            tokio::fs::create_dir_all(&path).await?;
            result.dirs_created += 1;
        } else if flags & FLAG_SYMLINK != 0 {
            let target = mapping.linktarget.as_deref().unwrap_or("");
            if target.is_empty() {
                return Err(Error::Other(format!(
                    "symlink {} has no linktarget",
                    filename
                )));
            }
            // The target names another path in this same depot, so it has
            // to go through the same mapping -- otherwise a folded tree
            // gets symlinks pointing at the unfolded names, which no
            // longer exist.
            let target = options.relative(target);
            let target = target.as_str();
            // Ensure parent dir exists
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            // Remove existing file/symlink if present
            let _ = tokio::fs::remove_file(&path).await;
            // Depot manifest symlinks are always file symlinks (game data,
            // never directories) -- Windows distinguishes the two at
            // creation time, unlike Unix, hence the separate call.
            #[cfg(unix)]
            tokio::fs::symlink(target, &path).await?;
            #[cfg(windows)]
            tokio::fs::symlink_file(target, &path).await?;
            result.symlinks_created += 1;
        } else {
            // Regular file
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            let existing_size = tokio::fs::metadata(&path).await.ok().map(|m| m.len());
            if existing_size == Some(size) {
                // Already the right size -- keep content as-is, verify later.
                result.verify_candidates.push(path.clone());
            } else {
                let file = tokio::fs::File::create(&path).await?;
                file.set_len(size).await?;
                result.files_created += 1;
            }
            result.total_bytes += size;

            // Set executable permission -- no equivalent on Windows (files
            // there are "executable" by extension, not a permission bit),
            // so this is a no-op there rather than something to translate.
            #[cfg(unix)]
            if flags & FLAG_EXECUTABLE != 0 {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o755);
                tokio::fs::set_permissions(&path, perms).await?;
            }
        }
    }

    Ok(result)
}

/// Hex-encode `bytes` in one allocation. Not `bytes.iter().map(|b|
/// format!("{:02x}", b)).collect()`, which heap-allocates a throwaway
/// `String` per byte -- confirmed live as real, avoidable allocator churn:
/// a 20-byte SHA1 was 20 small allocations, once per chunk verified *and*
/// once per chunk job built, across every chunk in every depot synced.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

thread_local! {
    // Reused across every chunk verified on this thread instead of a fresh
    // `vec![0u8; size]` per chunk -- this runs inside `spawn_blocking`,
    // whose pool is a small, bounded, *reused* set of OS threads, so a
    // thread-local buffer here genuinely gets reused across many chunks,
    // not allocated fresh per call. `resize` only grows the underlying
    // allocation when a chunk is larger than any seen so far on this
    // thread; it never shrinks the actual capacity back down, so this
    // stabilizes at the largest chunk size once warmed up.
    static VERIFY_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Read `size` bytes at `offset` from `path` and check them against the
/// chunk's expected (decompressed) SHA1, using a positioned read against an
/// already-open, shared file handle (see [`open_verify_files`]) instead of
/// opening the file itself -- `pread` is stateless (no seek, no shared
/// cursor), so many chunks belonging to the same file can safely verify
/// concurrently off one `File`. Any I/O error is treated as "not verified"
/// (falls back to redownloading that chunk).
fn verify_chunk_on_disk(file: &std::fs::File, offset: u64, size: u64, expected_sha_hex: &str) -> bool {
    VERIFY_BUF.with(|buf| {
        (|| -> Result<bool> {
            use sha1::{Digest, Sha1};

            let mut buf = buf.borrow_mut();
            buf.clear();
            buf.resize(size as usize, 0);
            read_exact_at(file, &mut buf, offset)?;

            let mut hasher = Sha1::new();
            hasher.update(&buf[..]);
            let actual_hex = hex_encode(&hasher.finalize());

            Ok(actual_hex.eq_ignore_ascii_case(expected_sha_hex))
        })()
        .unwrap_or(false)
    })
}

/// Positioned read (`pread` on Unix, `seek_read` on Windows) that doesn't
/// touch the file's shared cursor -- the two platforms' std APIs for this
/// happen to share an identical signature, so this is the only
/// OS-specific bit `read_exact_at` needs.
#[cfg(unix)]
fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

/// Like `Read::read_exact`, but as a positioned read (`pread`) that doesn't
/// touch the file's shared cursor -- stable `FileExt::read_at`/`seek_read`
/// don't guarantee filling the buffer in one call, so loop until it's full.
fn read_exact_at(file: &std::fs::File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        match read_at(file, buf, offset) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF during positioned read",
                ))
            }
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Open every verify-candidate file once, up front, so per-chunk
/// verification can share the handle via `pread` instead of each chunk
/// opening the file itself. Files that fail to open are simply left out --
/// their chunks fall back to `needs_verify: false` (redownload) in the
/// caller.
fn open_verify_files(candidates: &HashSet<PathBuf>) -> HashMap<PathBuf, Arc<std::fs::File>> {
    candidates
        .iter()
        .filter_map(|path| std::fs::File::open(path).ok().map(|f| (path.clone(), Arc::new(f))))
        .collect()
}

/// Progress report for chunk downloads/verification.
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    pub chunks_done: u64,
    pub chunks_total: u64,
    /// Chunks that turned out to already be correct on disk and were
    /// skipped rather than redownloaded (subset of `chunks_done`).
    pub chunks_verified: u64,
    pub bytes_downloaded: u64,
}

/// A single chunk's work: verify-then-maybe-download, or download outright.
struct ChunkJob {
    path: PathBuf,
    sha_hex: String,
    crc: u32,
    offset: u64,
    /// Decompressed size, needed to read the right range for verification.
    original_size: u64,
    /// Shared handle to this chunk's file, already open, if it's a verify
    /// candidate (see [`open_verify_files`]) -- `None` means either the
    /// file is freshly created (nothing to verify) or it failed to open.
    verify_file: Option<Arc<std::fs::File>>,
}

/// Prepare the directory tree, then verify and download a depot's chunks --
/// always in that order, so nothing gets downloaded without first checking
/// whether it's already correct on disk. Verification and downloading run
/// as a single pool of concurrent tasks (bounded by `max_concurrent`):
/// chunks needing verification and chunks needing a network fetch are
/// interleaved on the same executor rather than run as two back-to-back
/// phases, so disk I/O and network I/O overlap instead of one blocking
/// the other.
pub async fn sync_depot(
    client: &reqwest::Client,
    pool: Arc<Mutex<CdnPool>>,
    depot_id: u32,
    manifest: &DepotManifest,
    depot_key: &[u8],
    install_dir: &Path,
    max_concurrent: usize,
    options: PathOptions,
    on_progress: impl Fn(&DownloadProgress) + Send + Sync + 'static,
) -> Result<(PrepareResult, DownloadProgress)> {
    let prepared = prepare_directory_tree(install_dir, manifest, options).await?;
    let verify_candidates: HashSet<PathBuf> = prepared.verify_candidates.iter().cloned().collect();
    // Open each verify candidate exactly once, up front, instead of every
    // one of its chunks opening the file itself -- a depot's chunks are
    // typically spread across far fewer actual files, so this cuts
    // thousands of redundant open() calls down to one per file.
    let verify_files = open_verify_files(&verify_candidates);

    // Flatten all chunks into a work queue, tagging which ones are worth
    // verifying (their file already exists at the right size) vs. which
    // definitely need downloading (freshly (re)created, empty file).
    let mut jobs = Vec::new();
    for mapping in &manifest.payload.mappings {
        let flags = mapping.flags.unwrap_or(0);
        if flags & FLAG_DIRECTORY != 0 || flags & FLAG_SYMLINK != 0 {
            continue;
        }
        let filename = match mapping.filename.as_deref() {
            Some(f) => f,
            None => continue,
        };
        if mapping.chunks.is_empty() {
            continue;
        }

        // Same mapping prepare_directory_tree used, so verification and
        // download always address the file it actually created.
        let normalized = options.relative(filename);
        let path = install_dir.join(&normalized);
        let verify_file = verify_files.get(&path).cloned();

        for chunk in &mapping.chunks {
            let sha_bytes = chunk.sha.as_deref().unwrap_or(&[]);
            let sha_hex = hex_encode(sha_bytes);
            jobs.push(ChunkJob {
                path: path.clone(),
                sha_hex,
                crc: chunk.crc.unwrap_or(0),
                offset: chunk.offset.unwrap_or(0),
                original_size: chunk.cb_original.unwrap_or(0) as u64,
                verify_file: verify_file.clone(),
            });
        }
    }

    // Every job holding a verify_file now has its own Arc clone -- drop the
    // master map's references so each file's *last* referencing chunk task
    // actually closes it (Arc refcount hits zero) as soon as that file's
    // own chunks are done, instead of every verify candidate staying open
    // for the entire depot's sync_depot() call regardless of how early its
    // own chunks finished. With depots that can have 1000+ files, holding
    // them all open for the whole call was blowing through the process's
    // file descriptor limit under concurrent depot/mod syncs.
    drop(verify_files);

    let chunks_total = jobs.len() as u64;
    let chunks_done = Arc::new(AtomicU64::new(0));
    let chunks_verified = Arc::new(AtomicU64::new(0));
    let bytes_downloaded = Arc::new(AtomicU64::new(0));
    let on_progress = Arc::new(on_progress);

    // Verification (local disk read + SHA1) and downloading (network,
    // rate-limited by courtesy to the CDN) have very different ideal
    // concurrency levels -- gating both behind one `max_concurrent`
    // semaphore throttles cheap local verification down to network speed
    // for no reason. Each job spawns immediately and acquires whichever
    // semaphore its actual work needs, instead of the whole task waiting
    // on one shared permit before it can even start verifying.
    let verify_concurrency = std::thread::available_parallelism()
        .map(|n| n.get() * 4)
        .unwrap_or(16)
        .clamp(16, 128);
    let verify_semaphore = Arc::new(Semaphore::new(verify_concurrency));
    let download_semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut join_set = JoinSet::new();

    for job in jobs {
        let client = client.clone();
        let pool = pool.clone();
        let depot_key = depot_key.to_vec();
        let chunks_done = chunks_done.clone();
        let chunks_verified = chunks_verified.clone();
        let bytes_downloaded = bytes_downloaded.clone();
        let on_progress = on_progress.clone();
        let verify_semaphore = verify_semaphore.clone();
        let download_semaphore = download_semaphore.clone();

        join_set.spawn(async move {
            let mut verified = false;
            if let Some(file) = job.verify_file.clone() {
                let permit = verify_semaphore.acquire_owned().await.unwrap();
                let offset = job.offset;
                let size = job.original_size;
                let sha_hex = job.sha_hex.clone();
                verified = tokio::task::spawn_blocking(move || {
                    verify_chunk_on_disk(&file, offset, size, &sha_hex)
                })
                .await
                .unwrap_or(false);
                drop(permit);
            }

            let result = if verified {
                Ok(0)
            } else {
                let _permit = download_semaphore.acquire_owned().await.unwrap();
                download_chunk_with_retry(&client, &pool, depot_id, &job, &depot_key).await
            };

            match result {
                Ok(chunk_bytes) => {
                    bytes_downloaded.fetch_add(chunk_bytes, Ordering::Relaxed);
                    chunks_done.fetch_add(1, Ordering::Relaxed);
                    if verified {
                        chunks_verified.fetch_add(1, Ordering::Relaxed);
                    }
                    on_progress(&DownloadProgress {
                        chunks_done: chunks_done.load(Ordering::Relaxed),
                        chunks_total,
                        chunks_verified: chunks_verified.load(Ordering::Relaxed),
                        bytes_downloaded: bytes_downloaded.load(Ordering::Relaxed),
                    });
                    Ok(())
                }
                Err(e) => Err(e),
            }
        });
    }

    // Collect results, fail on first error
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                join_set.abort_all();
                return Err(e);
            }
            Err(e) => {
                join_set.abort_all();
                return Err(Error::Other(format!("chunk task panicked: {}", e)));
            }
        }
    }

    Ok((
        prepared,
        DownloadProgress {
            chunks_done: chunks_done.load(Ordering::Relaxed),
            chunks_total,
            chunks_verified: chunks_verified.load(Ordering::Relaxed),
            bytes_downloaded: bytes_downloaded.load(Ordering::Relaxed),
        },
    ))
}

/// Download, decrypt, decompress, verify, and write a single chunk with retries.
///
/// Returns the number of encrypted bytes downloaded on success.
async fn download_chunk_with_retry(
    client: &reqwest::Client,
    pool: &Arc<Mutex<CdnPool>>,
    depot_id: u32,
    job: &ChunkJob,
    depot_key: &[u8],
) -> Result<u64> {
    for attempt in 0..=MAX_RETRIES {
        let (server, cdn_token) = {
            let mut pool = pool.lock().unwrap();
            let server = pool.pick_server().clone();
            let token = pool
                .get_cdn_auth_token(depot_id, &server.host)
                .map(|t| t.token.clone());
            (server, token)
        };
        let mut url = format!(
            "https://{}/depot/{}/chunk/{}",
            server.vhost, depot_id, job.sha_hex
        );
        if let Some(ref token) = cdn_token {
            url.push_str(token);
        }

        match fetch_and_process(client, &url, depot_key, job).await {
            Ok(bytes) => return Ok(bytes),
            Err(e) if is_retryable(&e) && attempt < MAX_RETRIES => {
                pool.lock().unwrap().penalize(&server.host);
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// Fetch a chunk from CDN, decrypt, decompress, verify CRC, and write to file.
///
/// Returns the number of encrypted bytes downloaded.
async fn fetch_and_process(
    client: &reqwest::Client,
    url: &str,
    depot_key: &[u8],
    job: &ChunkJob,
) -> Result<u64> {
    let resp = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .map_err(|e| Error::Other(format!("chunk download {}: {}", job.sha_hex, e)))?;
    let encrypted = resp.bytes().await?;
    let encrypted_len = encrypted.len() as u64;

    // Decrypt in place on the buffer reqwest already gave us -- try_into_mut
    // is O(1) (no copy) since nothing else holds a clone of this Bytes at
    // this point; the rare Err case (unexpectedly shared) falls back to one
    // copy instead of failing outright.
    let buf = encrypted
        .try_into_mut()
        .unwrap_or_else(|shared| bytes::BytesMut::from(&shared[..]));
    let decrypted = crypto::symmetric_decrypt_mut(depot_key, buf)?;

    // Decompress
    let decompressed = decompress_chunk(&decrypted)?;

    // Verify Adler-32
    verify_adler32(&decompressed, job.crc)?;

    // Write at correct offset using spawn_blocking (sync file I/O)
    let path = job.path.clone();
    let offset = job.offset;
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| Error::Other(format!("open {}: {}", path.display(), e)))?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&decompressed)?;
        Ok::<(), Error>(())
    })
    .await
    .map_err(|e| Error::Other(format!("write task panicked: {}", e)))??;

    Ok(encrypted_len)
}

/// Check if an error is retryable (transient HTTP or network failures).
fn is_retryable(e: &Error) -> bool {
    match e {
        Error::Http(re) => {
            if let Some(status) = re.status() {
                matches!(status.as_u16(), 403 | 404 | 500 | 502 | 503 | 429)
            } else {
                // Connection/timeout errors
                re.is_connect() || re.is_timeout()
            }
        }
        Error::Other(msg) => {
            // Retryable HTTP status errors surfaced via error_for_status
            msg.contains("403") || msg.contains("500") || msg.contains("502")
                || msg.contains("503") || msg.contains("404") || msg.contains("429")
        }
        _ => false,
    }
}

/// Detect compression format from magic bytes and decompress.
///
/// SteamKit2 DepotChunk.cs checks for these magic prefixes after decryption:
/// - `VSZa` (4 bytes) → Zstd with VZstd envelope
/// - `VZa` (3 bytes) → LZMA with VZip envelope
/// - `PK\x03\x04` → ZIP
/// - Otherwise → uncompressed
fn decompress_chunk(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() >= 4 && &data[..4] == b"VSZa" {
        decompress_vzstd(data)
    } else if data.len() >= 3 && &data[..3] == b"VZa" {
        decompress_vzip_lzma(data)
    } else if data.len() >= 4 && &data[..4] == b"PK\x03\x04" {
        // ZIP-compressed chunk (rare)
        let cursor = std::io::Cursor::new(data);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| Error::Other(format!("chunk zip: {}", e)))?;
        let mut file = archive
            .by_index(0)
            .map_err(|e| Error::Other(format!("chunk zip entry: {}", e)))?;
        // Pre-sized from the ZIP entry's own uncompressed-size field --
        // authoritative archive-format metadata, not a guess (unlike the
        // VZstd case below, which is why that one's left alone).
        let mut buf = Vec::with_capacity(file.size() as usize);
        std::io::Read::read_to_end(&mut file, &mut buf)?;
        Ok(buf)
    } else {
        // Uncompressed
        Ok(data.to_vec())
    }
}

/// Decompress a VZstd chunk.
///
/// VZstdUtil.cs layout:
///   [0..4]   'V' 'S' 'Z' 'a' magic
///   [4..8]   CRC32
///   [8..-15] Zstd compressed stream
///   [-15..]  footer (CRC32 + decompressed size + "zsv")
fn decompress_vzstd(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 8 + 15 {
        return Err(Error::Other("VZstd data too short".into()));
    }
    let zstd_data = &data[8..data.len() - 15];
    let mut decoder = ruzstd::StreamingDecoder::new(zstd_data)
        .map_err(|e| Error::Other(format!("VZstd init: {}", e)))?;
    // Pre-sized from the footer's own decompressed-size field, verified
    // against SteamKit2's actual VZstdUtil.cs (not guessed): the footer is
    // CRC32(4) + decompressed_size(4, as a plain `int`) + 4 unused/
    // reserved bytes + "zsv"(3) = 15 bytes, with the size at the same
    // relative offset (footer[4..8]) as decompress_vzip_lzma's footer
    // below. ruzstd doesn't use this value for anything itself -- it's
    // purely a capacity hint here, same reasoning as the VZip case.
    let footer = &data[data.len() - 15..];
    let decompressed_size = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]);
    let mut output = Vec::with_capacity(decompressed_size as usize);
    std::io::Read::read_to_end(&mut decoder, &mut output)?;
    Ok(output)
}

/// Decompress a VZip (LZMA) chunk.
///
/// VZipUtil.cs layout:
///   [0..2]   'V' 'Z' magic
///   [2]      'a' version
///   [3..7]   CRC32 / timestamp
///   [7..12]  LZMA properties (1 byte props + 4 byte dict size)
///   [12..-10] LZMA compressed data
///   [-10..]  footer (CRC32 + decompressed size + "vz")
fn decompress_vzip_lzma(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 + 10 {
        return Err(Error::Other("VZip data too short".into()));
    }

    // lzma-rs expects a standard LZMA header: 5 property bytes + 8-byte little-endian size.
    // We have the 5 property bytes at data[7..12]. For the size, we can read it from
    // the footer or pass -1 (unknown).
    let props = &data[7..12];
    let compressed = &data[12..data.len() - 10];

    // Read decompressed size from footer: 4 bytes LE at offset -6 (before "vz" marker)
    let footer = &data[data.len() - 10..];
    let decompressed_size = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]) as u64;

    // Build standard LZMA header: 5 props + 8 byte LE size
    let mut lzma_stream = Vec::with_capacity(13 + compressed.len());
    lzma_stream.extend_from_slice(props);
    lzma_stream.extend_from_slice(&decompressed_size.to_le_bytes());
    lzma_stream.extend_from_slice(compressed);

    // Pre-sized, not Vec::new() -- the decompressed size is already known
    // right above (read from the chunk's own footer), so there's no reason
    // to pay for lzma_decompress's incremental grow-and-copy reallocations
    // as it writes output it could have had room for from the start.
    let mut output = Vec::with_capacity(decompressed_size as usize);
    lzma_rs::lzma_decompress(&mut std::io::Cursor::new(&lzma_stream), &mut output)
        .map_err(|e| Error::Other(format!("VZip LZMA decompress: {}", e)))?;

    Ok(output)
}

/// Verify Adler-32 checksum of decompressed chunk data.
///
/// Steam uses a non-standard Adler-32 with initial seed 0 instead of 1
/// (see SteamKit2's `Adler32.Calculate(0, data)`).
fn verify_adler32(data: &[u8], expected: u32) -> Result<()> {
    if expected == 0 {
        return Ok(());
    }
    let actual = adler32_steam(data);
    if actual != expected {
        return Err(Error::Other(format!(
            "Adler-32 mismatch: expected {:08x}, got {:08x}",
            expected, actual
        )));
    }
    Ok(())
}

/// Adler-32 with initial seed 0 (Steam's variant).
///
/// Standard Adler-32 starts with s1=1, s2=0. Steam starts with s1=0, s2=0.
fn adler32_steam(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut s1: u32 = 0;
    let mut s2: u32 = 0;

    for chunk in data.chunks(5552) {
        for &byte in chunk {
            s1 = s1.wrapping_add(byte as u32);
            s2 = s2.wrapping_add(s1);
        }
        s1 %= MOD_ADLER;
        s2 %= MOD_ADLER;
    }

    (s2 << 16) | s1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::content_manifest_payload::FileMapping;
    use crate::proto::ContentManifestPayload;

    fn mapping(filename: &str, flags: u32, size: u64) -> FileMapping {
        FileMapping {
            filename: Some(filename.to_string()),
            flags: Some(flags),
            size: Some(size),
            ..Default::default()
        }
    }

    fn manifest(mappings: Vec<FileMapping>) -> DepotManifest {
        DepotManifest {
            payload: ContentManifestPayload { mappings },
            metadata: Default::default(),
            signature: Default::default(),
        }
    }

    #[test]
    fn separators_are_normalized_in_both_modes() {
        for options in [PathOptions::preserve_case(), PathOptions::lowercase()] {
            assert!(!options.relative("addons\\sub\\x.pbo").contains('\\'));
        }
    }

    #[test]
    fn preserve_case_leaves_casing_alone() {
        assert_eq!(
            PathOptions::preserve_case().relative("Addons\\AIMEE_main.pbo"),
            "Addons/AIMEE_main.pbo"
        );
    }

    #[test]
    fn lowercase_folds_the_whole_path() {
        // The directory component matters as much as the basename: Arma
        // reports the full path, so a mixed-case directory is just as
        // unusable as a mixed-case file.
        assert_eq!(
            PathOptions::lowercase().relative("Addons\\AIMEE_main.pbo"),
            "addons/aimee_main.pbo"
        );
    }

    #[test]
    fn collisions_are_only_possible_when_folding() {
        let m = manifest(vec![
            mapping("addons/Foo.pbo", 0, 1),
            mapping("addons/foo.pbo", 0, 1),
        ]);
        // Preserving case, the two are simply different files.
        assert!(check_for_collisions(&m, PathOptions::preserve_case()).is_ok());

        // Folding, one would silently overwrite the other -- refuse, and
        // name both paths so the depot can be identified.
        let err = check_for_collisions(&m, PathOptions::lowercase()).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Foo.pbo"), "{message}");
        assert!(message.contains("foo.pbo"), "{message}");
    }

    #[test]
    fn an_ordinary_depot_has_no_collisions() {
        let m = manifest(vec![
            mapping("Addons/AIMEE_main.pbo", 0, 1),
            mapping("Addons/AIMEE_group.pbo", 0, 1),
        ]);
        assert!(check_for_collisions(&m, PathOptions::lowercase()).is_ok());
    }

    #[test]
    fn a_repeated_identical_filename_is_not_a_collision() {
        // Same name twice is not two files fighting over one path.
        let m = manifest(vec![
            mapping("addons/x.pbo", 0, 1),
            mapping("addons/x.pbo", 0, 1),
        ]);
        assert!(check_for_collisions(&m, PathOptions::lowercase()).is_ok());
    }

    #[tokio::test]
    async fn prepare_creates_folded_paths() {
        let dir = tempfile::TempDir::new().unwrap();
        let m = manifest(vec![
            mapping("Addons", FLAG_DIRECTORY, 0),
            mapping("Addons/AIMEE_main.pbo", 0, 4),
        ]);

        prepare_directory_tree(dir.path(), &m, PathOptions::lowercase())
            .await
            .unwrap();

        assert!(dir.path().join("addons").is_dir());
        assert!(dir.path().join("addons/aimee_main.pbo").is_file());
        // The name the manifest used must not also appear -- that is the
        // duplicate this option exists to prevent.
        assert!(!dir.path().join("Addons/AIMEE_main.pbo").exists());
    }

    #[tokio::test]
    async fn prepare_preserves_case_by_default() {
        let dir = tempfile::TempDir::new().unwrap();
        let m = manifest(vec![
            mapping("Addons", FLAG_DIRECTORY, 0),
            mapping("Addons/AIMEE_main.pbo", 0, 4),
        ]);

        prepare_directory_tree(dir.path(), &m, PathOptions::preserve_case())
            .await
            .unwrap();

        assert!(dir.path().join("Addons/AIMEE_main.pbo").is_file());
    }

    /// Re-preparing a folded tree must recognise what it already created,
    /// rather than making a second copy. This is what keeps incremental
    /// verification working across content updates.
    #[tokio::test]
    async fn preparing_a_folded_tree_twice_finds_the_existing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let m = manifest(vec![
            mapping("Addons", FLAG_DIRECTORY, 0),
            mapping("Addons/AIMEE_main.pbo", 0, 4),
        ]);
        let options = PathOptions::lowercase();

        prepare_directory_tree(dir.path(), &m, options).await.unwrap();
        let second = prepare_directory_tree(dir.path(), &m, options).await.unwrap();

        // Already at the manifest's size, so it is offered for chunk
        // verification instead of being recreated.
        assert_eq!(
            second.verify_candidates,
            vec![dir.path().join("addons/aimee_main.pbo")]
        );
        assert_eq!(second.files_created, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_target_is_folded_with_its_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut link = mapping("Addons/Link.pbo", FLAG_SYMLINK, 0);
        link.linktarget = Some("Addons\\AIMEE_main.pbo".to_string());
        let m = manifest(vec![
            mapping("Addons", FLAG_DIRECTORY, 0),
            mapping("Addons/AIMEE_main.pbo", 0, 4),
            link,
        ]);

        prepare_directory_tree(dir.path(), &m, PathOptions::lowercase())
            .await
            .unwrap();

        // Pointing at the unfolded name would dangle -- that file does
        // not exist in a folded tree.
        let target = std::fs::read_link(dir.path().join("addons/link.pbo")).unwrap();
        assert_eq!(target, Path::new("addons/aimee_main.pbo"));
    }
}
