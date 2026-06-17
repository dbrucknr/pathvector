/// GoBGP v4 benchmark phase.
///
/// Spawns gobgpd (v4.x), initialises it via StartBgp, then injects routes
/// using AddPathStream (client-streaming).  Mirrors the pathvectord stress
/// harness for a direct, apples-to-apples comparison.
use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{process::Command, time::sleep};
use tonic::transport::Channel;

use crate::{fmt_kb, prefix_for, reclaim_pct, rss_sampler, sample_rss_kb, stderr_logger};

// Generated from proto/api/gobgp.proto + attribute.proto + nlri.proto (GoBGP v4)
#[allow(
    clippy::all,
    clippy::pedantic,
    dead_code,
    unused_imports,
    non_camel_case_types
)]
mod api {
    include!(concat!(env!("OUT_DIR"), "/api.rs"));
}

use api::{
    AddPathStreamRequest, AsPathAttribute, Attribute, Family, Global, IpAddressPrefix,
    LocalPrefAttribute, Nlri, NextHopAttribute, OriginAttribute, Path, StartBgpRequest,
    attribute::Attr,
    go_bgp_service_client::GoBgpServiceClient,
    nlri::Nlri as NlriOneof,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const GOBGP_GRPC_PORT: u16 = 59_373;
const GOBGP_AS: u32 = 65_002;
const GOBGP_ROUTER_ID: &str = "127.0.0.2";

fn ipv4_unicast() -> Family {
    Family { afi: 1, safi: 1 }
}

// ── Route construction ────────────────────────────────────────────────────────

fn make_path(n: u32, nexthop: &str) -> Path {
    let prefix_str = prefix_for(n);
    let (net, len_str) = prefix_str.split_once('/').expect("prefix has /");
    let prefix_len: u32 = len_str.parse().unwrap();

    let nlri = Nlri {
        nlri: Some(NlriOneof::Prefix(IpAddressPrefix {
            prefix_len,
            prefix: net.to_owned(),
        })),
    };

    let pattrs = vec![
        Attribute { attr: Some(Attr::Origin(OriginAttribute { origin: 0 })) },
        Attribute { attr: Some(Attr::AsPath(AsPathAttribute { segments: vec![] })) },
        Attribute {
            attr: Some(Attr::NextHop(NextHopAttribute {
                next_hop: nexthop.to_owned(),
            })),
        },
        Attribute { attr: Some(Attr::LocalPref(LocalPrefAttribute { local_pref: 100 })) },
    ];

    Path {
        nlri: Some(nlri),
        pattrs,
        family: Some(ipv4_unicast()),
        ..Default::default()
    }
}

// ── Startup ───────────────────────────────────────────────────────────────────

async fn connect(pid: u32) -> Result<GoBgpServiceClient<Channel>, Box<dyn std::error::Error>> {
    let endpoint = format!("http://127.0.0.1:{GOBGP_GRPC_PORT}");
    let mut started = false;
    for _ in 0..80 {
        if sample_rss_kb(pid) == 0 {
            return Err(format!(
                "gobgpd (PID {pid}) exited — check for port conflicts: \
                 lsof -i :{GOBGP_GRPC_PORT}"
            )
            .into());
        }

        let ch = Channel::from_shared(endpoint.clone())
            .expect("valid endpoint")
            .connect_lazy();
        let mut c = GoBgpServiceClient::new(ch);

        if !started {
            let req = StartBgpRequest {
                global: Some(Global {
                    asn: GOBGP_AS,
                    router_id: GOBGP_ROUTER_ID.to_owned(),
                    listen_port: -1, // gRPC only — no BGP listener needed
                    ..Default::default()
                }),
            };
            match c.start_bgp(req).await {
                Ok(_) => {
                    started = true;
                    return Ok(c);
                }
                // Daemon already started (e.g. by a previous run that didn't clean up).
                Err(s) if s.code() == tonic::Code::AlreadyExists => return Ok(c),
                Err(_) => {}
            }
        } else {
            return Ok(c);
        }
        sleep(Duration::from_millis(200)).await;
    }
    Err("gobgpd did not become ready within 16 s".into())
}

fn which_gobgpd() -> Result<String, Box<dyn std::error::Error>> {
    let gopath = std::env::var("GOPATH")
        .unwrap_or_else(|_| format!("{}/go", std::env::var("HOME").unwrap_or_default()));
    let candidate = std::path::Path::new(&gopath).join("bin/gobgpd");
    if candidate.exists() {
        return Ok(candidate.to_string_lossy().into_owned());
    }
    let out = std::process::Command::new("which").arg("gobgpd").output()?;
    let path = String::from_utf8(out.stdout)?.trim().to_owned();
    if path.is_empty() {
        Err("gobgpd not found — install GoBGP 4.x".into())
    } else {
        Ok(path)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct PhaseResult {
    pub label: &'static str,
    pub elapsed_secs: f64,
    pub peak_rss: String,
}

#[allow(clippy::too_many_lines)]
pub async fn run(
    phases: &[(u32, &'static str)],
    batch_size: usize,
) -> Result<Vec<PhaseResult>, Box<dyn std::error::Error>> {
    let bin = which_gobgpd()?;
    println!("Starting gobgpd from {bin}");

    let mut child = Command::new(&bin)
        .args([
            "--api-hosts", &format!(":{GOBGP_GRPC_PORT}"),
            "--log-level", "panic",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = child.id().expect("child has a PID");
    let stderr = child.stderr.take().expect("stderr is piped");
    println!("gobgpd PID: {pid}");
    println!();

    let error_count = Arc::new(AtomicUsize::new(0));
    let warn_count  = Arc::new(AtomicUsize::new(0));
    let peak_kb     = Arc::new(AtomicU64::new(0));
    let rss_running = Arc::new(AtomicUsize::new(1));

    tokio::spawn(stderr_logger(stderr, Arc::clone(&error_count), Arc::clone(&warn_count)));
    tokio::spawn(rss_sampler(pid, Arc::clone(&peak_kb), Arc::clone(&rss_running)));

    let mut client = connect(pid).await?;

    let mut results = Vec::with_capacity(phases.len());
    let mut total_originated: u32 = 0;

    for &(target, label) in phases {
        let rss_before = sample_rss_kb(pid);
        peak_kb.store(rss_before, Ordering::Relaxed);

        let start = Instant::now();

        let mut stream_msgs: Vec<AddPathStreamRequest> = Vec::new();
        let mut batch: Vec<Path> = Vec::with_capacity(batch_size);
        for i in total_originated..target {
            batch.push(make_path(i, "192.0.2.1"));
            if batch.len() == batch_size {
                stream_msgs.push(AddPathStreamRequest {
                    table_type: 1, // TABLE_TYPE_GLOBAL
                    vrf_id: String::new(),
                    paths: std::mem::take(&mut batch),
                });
            }
        }
        if !batch.is_empty() {
            stream_msgs.push(AddPathStreamRequest {
                table_type: 0,
                vrf_id: String::new(),
                paths: std::mem::take(&mut batch),
            });
        }

        client
            .add_path_stream(tokio_stream::iter(stream_msgs))
            .await?;

        let elapsed = start.elapsed();
        let final_kb = sample_rss_kb(pid);
        sleep(Duration::from_millis(600)).await;
        let phase_peak = peak_kb.load(Ordering::Relaxed).max(final_kb);

        results.push(PhaseResult {
            label,
            elapsed_secs: elapsed.as_secs_f64(),
            peak_rss: fmt_kb(phase_peak),
        });

        total_originated = target;
    }

    rss_running.store(0, Ordering::Relaxed);
    child.kill().await?;
    Ok(results)
}

// Suppress unused-import lint for helpers imported for consistency.
const _: fn(u64, u64) -> f64 = reclaim_pct;
