//! "Check for updates" — fetches the latest tag from the GitHub Releases API
//! and compares it to the running version.
//!
//! Designed for the UI's **Check for updates** button (issue #15). Two-step
//! flow so users get a clear answer when something fails:
//!
//! 1. **Connectivity probe**: open a TCP connection to `github.com:443`. If
//!    that fails the user is offline (or GitHub is blocked from their
//!    network) — we say so explicitly instead of looking like the update
//!    check itself is broken.
//! 2. **Release lookup**: HTTPS GET `api.github.com/repos/.../releases/latest`,
//!    parse `tag_name` out of the JSON, strip any leading `v`, compare
//!    against `CARGO_PKG_VERSION` with a loose semver-ish compare (split
//!    on `.`, int-wise).
//!
//! No new crate deps — uses the tokio + rustls stack already in the tree,
//! same pattern as the Apps Script relay's hand-rolled HTTP.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const REPO_OWNER: &str = "therealaleph";
const REPO_NAME: &str = "MasterHttpRelayVPN-RUST";
const GITHUB_API_HOST: &str = "api.github.com";
const GITHUB_HOST: &str = "github.com";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The user-visible outcome of an update check.
#[derive(Clone, Debug)]
pub enum UpdateCheck {
    /// Could not reach github.com at all. Likely offline or github blocked.
    Offline(String),
    /// Reached github.com but the API call or JSON parse failed.
    Error(String),
    /// Current binary is already on the latest tag.
    UpToDate {
        current: String,
        latest: String,
    },
    /// A newer release is available.
    UpdateAvailable {
        current: String,
        latest: String,
        release_url: String,
    },
}

impl UpdateCheck {
    /// One-liner summary suitable for a status label.
    pub fn summary(&self) -> String {
        match self {
            UpdateCheck::Offline(msg) => {
                format!("Can't reach github.com: {}", msg)
            }
            UpdateCheck::Error(msg) => format!("Update check failed: {}", msg),
            UpdateCheck::UpToDate { current, .. } => {
                format!("Up to date (running v{}).", current)
            }
            UpdateCheck::UpdateAvailable {
                current,
                latest,
                release_url,
            } => format!(
                "Update available: v{} → v{}  ({})",
                current, latest, release_url
            ),
        }
    }
}

/// Run the full update check. Safe to call from any async context.
pub async fn check() -> UpdateCheck {
    // 1. Connectivity probe. Short timeout — either github.com is reachable
    //    or it isn't; no reason to wait long.
    if let Err(e) = probe_github().await {
        return UpdateCheck::Offline(e);
    }

    // 2. Release lookup.
    let latest_tag = match fetch_latest_tag().await {
        Ok(t) => t,
        Err(e) => return UpdateCheck::Error(e),
    };

    let latest = latest_tag.trim_start_matches('v').to_string();
    let current = CURRENT_VERSION.to_string();
    let release_url = format!(
        "https://github.com/{}/{}/releases/tag/{}",
        REPO_OWNER, REPO_NAME, latest_tag
    );

    if is_newer(&latest, &current) {
        UpdateCheck::UpdateAvailable {
            current,
            latest,
            release_url,
        }
    } else {
        UpdateCheck::UpToDate { current, latest }
    }
}

/// TCP-ping github.com:443 with a 5s budget. Returns Ok(()) if reachable.
async fn probe_github() -> Result<(), String> {
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((GITHUB_HOST, 443u16)),
    )
    .await;
    match res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("connect timeout".into()),
    }
}

async fn fetch_latest_tag() -> Result<String, String> {
    let body = https_get(
        GITHUB_API_HOST,
        &format!("/repos/{}/{}/releases/latest", REPO_OWNER, REPO_NAME),
    )
    .await?;

    // serde_json::Value avoids having to ship a full derive for this one field.
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("bad API JSON: {}", e))?;
    v.get("tag_name")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "API response missing tag_name".into())
}

/// Minimal HTTPS GET against a host. 10s total budget. Returns the response
/// body as a String. Follows one redirect (GitHub API sometimes 302s).
async fn https_get(host: &str, path: &str) -> Result<String, String> {
    let roots = {
        let mut r = RootCertStore::empty();
        r.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        r
    };
    let tls_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((host, 443u16)))
        .await
        .map_err(|_| "tcp connect timeout".to_string())?
        .map_err(|e| format!("tcp connect: {}", e))?;
    let _ = tcp.set_nodelay(true);

    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| format!("bad host: {}", e))?;
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .map_err(|_| "tls handshake timeout".to_string())?
        .map_err(|e| format!("tls: {}", e))?;

    // GitHub API requires a User-Agent header.
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: mhrv-rs/{ver} (update-check)\r\n\
         Accept: application/vnd.github+json\r\n\
         Connection: close\r\n\
         \r\n",
        path = path,
        host = host,
        ver = CURRENT_VERSION,
    );
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;
    tls.flush().await.ok();

    let mut buf = Vec::with_capacity(4096);
    let read_fut = async {
        let mut chunk = [0u8; 4096];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(format!("read: {}", e)),
            }
            if buf.len() > 512 * 1024 {
                return Err("response too large".into());
            }
        }
        Ok::<(), String>(())
    };
    tokio::time::timeout(Duration::from_secs(10), read_fut)
        .await
        .map_err(|_| "read timeout".to_string())??;

    parse_http_response(&buf, host).await
}

/// Parse an HTTP/1.1 response out of a raw byte buffer. Handles one level of
/// 301/302 redirect (the API occasionally redirects on rate-limit-adjacent
/// states). Returns the body as a String.
fn parse_http_response<'a>(
    buf: &'a [u8],
    host: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>> {
    Box::pin(async move {
        let sep = b"\r\n\r\n";
        let hdr_end = buf
            .windows(sep.len())
            .position(|w| w == sep)
            .ok_or_else(|| "no HTTP header terminator".to_string())?;
        let hdr = std::str::from_utf8(&buf[..hdr_end])
            .map_err(|_| "non-utf8 header".to_string())?;
        let body = &buf[hdr_end + sep.len()..];

        let first = hdr.lines().next().unwrap_or("");
        let status: u16 = first
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("bad status line: {}", first))?;

        match status {
            200 => Ok(String::from_utf8_lossy(body).into_owned()),
            301 | 302 | 307 | 308 => {
                // Follow one redirect. Look for `Location:`.
                let loc = hdr
                    .lines()
                    .find_map(|l| {
                        let lower = l.to_ascii_lowercase();
                        if lower.starts_with("location:") {
                            Some(l[l.find(':').unwrap() + 1..].trim().to_string())
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| "redirect without Location".to_string())?;
                let (new_host, new_path) = parse_url(&loc, host);
                https_get(&new_host, &new_path).await
            }
            other => Err(format!(
                "HTTP {}: {}",
                other,
                String::from_utf8_lossy(body)
                    .chars()
                    .take(120)
                    .collect::<String>()
            )),
        }
    })
}

/// Minimal URL -> (host, path) split for redirect handling.
fn parse_url(url: &str, default_host: &str) -> (String, String) {
    if let Some(rest) = url.strip_prefix("https://") {
        if let Some(slash) = rest.find('/') {
            (rest[..slash].to_string(), rest[slash..].to_string())
        } else {
            (rest.to_string(), "/".to_string())
        }
    } else if url.starts_with('/') {
        (default_host.to_string(), url.to_string())
    } else {
        (default_host.to_string(), format!("/{}", url))
    }
}

/// Very-loose semver compare: split on `.`, compare each component as u64
/// if possible else as a string. Returns true if `a` > `b`.
fn is_newer(a: &str, b: &str) -> bool {
    let parts_a: Vec<&str> = a.split(|c: char| c == '.' || c == '-').collect();
    let parts_b: Vec<&str> = b.split(|c: char| c == '.' || c == '-').collect();
    let n = parts_a.len().max(parts_b.len());
    for i in 0..n {
        let pa = parts_a.get(i).unwrap_or(&"0");
        let pb = parts_b.get(i).unwrap_or(&"0");
        match (pa.parse::<u64>(), pb.parse::<u64>()) {
            (Ok(na), Ok(nb)) if na != nb => return na > nb,
            (Ok(_), Ok(_)) => continue,
            _ => {
                if pa != pb {
                    return *pa > *pb;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_newer_basic() {
        assert!(is_newer("0.8.6", "0.8.5"));
        assert!(is_newer("0.9.0", "0.8.99"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.8.5", "0.8.5"));
        assert!(!is_newer("0.8.4", "0.8.5"));
    }

    #[test]
    fn is_newer_ignores_v_prefix_caller_side() {
        // Callers strip the `v`; we don't re-check here.
        assert!(is_newer("1.0.0", "0.9.9"));
    }

    #[test]
    fn is_newer_mixed_length() {
        assert!(is_newer("1.2.3.4", "1.2.3"));
        assert!(!is_newer("1.2.3", "1.2.3.0"));
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    // Gated by an env var so CI doesn't hit the GitHub API on every run.
    #[tokio::test(flavor = "multi_thread")]
    async fn live_hit_github_if_enabled() {
        if std::env::var("MHRV_LIVE_UPDATE_CHECK").is_err() {
            eprintln!("skipping live update check (set MHRV_LIVE_UPDATE_CHECK=1 to run)");
            return;
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let result = check().await;
        println!("live result: {:?}", result);
        // Any variant is fine — we're verifying the round-trip runs. Rate
        // limits / offline networks legitimately return Error/Offline.
        let _ = result.summary();
    }
}
