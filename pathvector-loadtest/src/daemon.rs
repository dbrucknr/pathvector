//! Running `pathvectord` as a child process and observing it from outside:
//! `/metrics` scrapes, a gRPC latency probe, and RSS sampling.

use std::{
    collections::BTreeSet,
    io,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use pathvector_client::{DaemonClient, PathvectorClient};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::{Child, Command},
    task::JoinHandle,
    time::{sleep, timeout},
};

use crate::{config::Topology, gaps::Probe, promtext::Snapshot};

/// A spawned `pathvectord`, killed when dropped.
pub struct Daemon {
    child: Child,
    pub pid: u32,
    pub log_path: PathBuf,
}

/// WARN/ERROR lines pathvectord logged during the run.
#[derive(Debug, Default)]
pub struct LogSummary {
    pub warnings: usize,
    pub errors: usize,
    /// First few distinct WARN/ERROR messages (timestamps stripped).
    pub samples: Vec<String>,
}

impl Daemon {
    /// Writes the generated config into `dir` and starts the daemon with its
    /// output captured to a log file. `rust_log` is passed as `RUST_LOG`.
    ///
    /// # Errors
    ///
    /// Fails if the files cannot be written or the process cannot start.
    pub fn spawn(bin: &Path, topo: &Topology, dir: &Path, rust_log: &str) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let cfg_path = dir.join("pathvectord.toml");
        std::fs::write(&cfg_path, topo.daemon_toml())?;
        let log_path = dir.join("pathvectord.log");
        let log = std::fs::File::create(&log_path)?;

        let child = Command::new(bin)
            .arg(&cfg_path)
            .env("RUST_LOG", rust_log)
            .env("NO_COLOR", "1")
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()?;
        let pid = child
            .id()
            .ok_or_else(|| io::Error::other("pathvectord exited immediately"))?;
        Ok(Self {
            child,
            pid,
            log_path,
        })
    }

    /// Whether the daemon process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Reads the captured log and tallies WARN/ERROR lines.
    #[must_use]
    pub fn log_summary(&self) -> LogSummary {
        let text = std::fs::read_to_string(&self.log_path).unwrap_or_default();
        summarize_log(&text)
    }

    /// Stops the daemon and waits for it to exit.
    pub async fn shutdown(mut self) {
        let _ = self.child.kill().await;
    }
}

fn summarize_log(text: &str) -> LogSummary {
    let mut s = LogSummary::default();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        let (is_err, idx) = match (line.find(" ERROR "), line.find(" WARN ")) {
            (Some(i), _) => (true, i),
            (None, Some(i)) => (false, i),
            (None, None) => continue,
        };
        if is_err {
            s.errors += 1;
        } else {
            s.warnings += 1;
        }
        let msg = line[idx..].trim().to_string();
        if s.samples.len() < 5 && seen.insert(msg.clone()) {
            s.samples.push(msg);
        }
    }
    s
}

/// Plain HTTP/1.0 GET against `127.0.0.1:port`, returning the body.
///
/// # Errors
///
/// Fails on connection/IO error, a non-200 status, or a 10 s timeout.
pub async fn http_get(port: u16, path: &str) -> io::Result<String> {
    let fut = async {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
        s.write_all(format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes())
            .await?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| io::Error::other("malformed HTTP response"))?;
        if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
            return Err(io::Error::other(format!(
                "unexpected status: {}",
                head.lines().next().unwrap_or("")
            )));
        }
        Ok(body.to_string())
    };
    timeout(Duration::from_secs(10), fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "metrics scrape timed out"))?
}

/// Waits until both `/metrics` and the gRPC API answer.
///
/// # Errors
///
/// Returns a message if the daemon is not ready within `limit`.
pub async fn wait_ready(topo: &Topology, limit: Duration) -> Result<(), String> {
    let deadline = Instant::now() + limit;
    loop {
        let metrics_ok = http_get(topo.metrics_port, "/metrics").await.is_ok();
        let grpc_ok = match PathvectorClient::connect(grpc_url(topo)) {
            // Bounded by what is left of `limit`: a server that accepts and
            // never answers must not hang startup.
            Ok(mut c) => timeout(
                deadline.saturating_duration_since(Instant::now()),
                c.list_peers(),
            )
            .await
            .is_ok_and(|r| r.is_ok()),
            Err(_) => false,
        };
        if metrics_ok && grpc_ok {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "pathvectord not ready after {limit:?} (metrics ok: {metrics_ok}, grpc ok: {grpc_ok})"
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}

#[must_use]
pub fn grpc_url(topo: &Topology) -> String {
    format!("http://127.0.0.1:{}", topo.grpc_port)
}

/// Resident set size of `pid` in KiB, via `ps` (works on macOS and Linux).
#[must_use]
pub fn rss_kb(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Background observers whose samples are windowed after the fact.
pub struct Monitor {
    pub probes: Arc<Mutex<Vec<Probe>>>,
    pub rss: Arc<Mutex<Vec<(Instant, u64)>>>,
    metrics_port: u16,
    tasks: Vec<JoinHandle<()>>,
}

impl Monitor {
    /// Starts the gRPC latency probe (a `list_peers` call every
    /// `probe_interval`, issued back to back so a slow call delays the next —
    /// the latency is what a management client would see; `None` disables it,
    /// removing the probe as a source of load) and the RSS sampler (every
    /// 500 ms).
    #[must_use]
    pub fn start(topo: &Topology, pid: u32, probe_interval: Option<Duration>) -> Self {
        let probes: Arc<Mutex<Vec<Probe>>> = Arc::default();
        let rss: Arc<Mutex<Vec<(Instant, u64)>>> = Arc::default();

        let probe_store = Arc::clone(&probes);
        let url = grpc_url(topo);
        let probe_task = probe_interval.map(|interval| {
            tokio::spawn(async move {
                let Ok(mut client) = PathvectorClient::connect(url) else {
                    return;
                };
                loop {
                    let at = Instant::now();
                    let res = timeout(Duration::from_secs(30), client.list_peers()).await;
                    let ok = matches!(res, Ok(Ok(_)));
                    probe_store.lock().unwrap().push(Probe {
                        at,
                        latency: at.elapsed(),
                        ok,
                    });
                    sleep(interval).await;
                }
            })
        });

        let rss_store = Arc::clone(&rss);
        let rss_task = tokio::spawn(async move {
            loop {
                if let Some(kb) = rss_kb(pid) {
                    rss_store.lock().unwrap().push((Instant::now(), kb));
                }
                sleep(Duration::from_millis(500)).await;
            }
        });

        Self {
            probes,
            rss,
            metrics_port: topo.metrics_port,
            tasks: probe_task.into_iter().chain([rss_task]).collect(),
        }
    }

    /// Scrapes `/metrics` now.
    ///
    /// # Errors
    ///
    /// Fails if the endpoint is unreachable.
    pub async fn scrape(&self) -> io::Result<(Instant, Snapshot)> {
        let body = http_get(self.metrics_port, "/metrics").await?;
        Ok((Instant::now(), Snapshot::parse(&body)))
    }

    /// Peak RSS (KiB) sampled inside `[start, end]`.
    #[must_use]
    pub fn peak_rss_kb(&self, start: Instant, end: Instant) -> Option<u64> {
        self.rss
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| *t >= start && *t <= end)
            .map(|&(_, kb)| kb)
            .max()
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_summary_counts_levels_and_dedups_samples() {
        let log = "\
2026-11-23T10:00:00Z  WARN pathvectord::daemon: slow thing
2026-11-23T10:00:01Z  WARN pathvectord::daemon: slow thing
2026-11-23T10:00:02Z ERROR pathvectord::daemon: closing session: outbound UPDATE channel overflowed
2026-11-23T10:00:03Z  INFO pathvectord::daemon: not counted
";
        let s = summarize_log(log);
        assert_eq!(s.warnings, 2);
        assert_eq!(s.errors, 1);
        assert_eq!(s.samples.len(), 2, "duplicate WARN message listed once");
        assert!(s.samples.iter().any(|m| m.contains("overflowed")));
    }

    /// A gRPC port that accepts connections and never answers must make
    /// startup fail at its limit rather than hang.
    #[tokio::test]
    async fn wait_ready_gives_up_on_a_silent_grpc_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut topo = Topology::from_addrs(&[std::net::Ipv4Addr::LOCALHOST; 2], 9);
        topo.grpc_port = listener.local_addr().unwrap().port();
        // Nothing listens on the metrics port, so only gRPC is left hanging.
        topo.metrics_port = {
            let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            free.local_addr().unwrap().port()
        };
        let held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let result = timeout(
            Duration::from_secs(30),
            wait_ready(&topo, Duration::from_millis(500)),
        )
        .await
        .expect("wait_ready hung");
        assert!(result.is_err(), "{result:?}");
        held.abort();
    }

    #[test]
    fn rss_of_this_process_is_readable() {
        assert!(rss_kb(std::process::id()).is_some_and(|kb| kb > 0));
    }
}
