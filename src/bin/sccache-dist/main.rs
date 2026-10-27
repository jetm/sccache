#[macro_use]
extern crate log;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::{RngCore, rngs::OsRng};
use sccache::config::{
    INSECURE_DIST_CLIENT_TOKEN, scheduler as scheduler_config, server as server_config,
};
use sccache::dist::{
    self, AllocJobResult, AssignJobResult, BuilderIncoming, CompileCommand, DeregisterServerResult,
    HeartbeatServerResult, InputsReader, JobAlloc, JobAuthorizer, JobComplete, JobId, JobState,
    RunJobResult, SchedulerIncoming, SchedulerOutgoing, SchedulerStatusResult, ServerId,
    ServerIncoming, ServerNonce, ServerOutgoing, ServerStatusResult, SubmitToolchainResult,
    TcCache, Toolchain, ToolchainReader, UpdateJobStateResult,
};
use sccache::util::BASE64_URL_SAFE_ENGINE;
use sccache::util::daemonize;
use sccache::util::num_cpus;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, btree_map};
use std::env;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg_attr(target_os = "freebsd", path = "build_freebsd.rs")]
mod build;

mod cmdline;
mod token_check;

use cmdline::{AuthSubcommand, Command};

pub const INSECURE_DIST_SERVER_TOKEN: &str = "dangerously_insecure_server";

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    target_os = "freebsd"
)))]
fn main() {
    compile_error!("Distributed compilation is only supported on Linux/x86_64 and FreeBSD!");
}

// Only supported on x86_64 Linux machines and on FreeBSD
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    target_os = "freebsd"
))]
fn main() {
    init_logging();

    let incr_env_strs = ["CARGO_BUILD_INCREMENTAL", "CARGO_INCREMENTAL"];
    incr_env_strs
        .iter()
        .for_each(|incr_str| match env::var(incr_str) {
            Ok(incr_val) if incr_val == "1" => {
                println!(
                    "sccache: incremental compilation is prohibited: Unset {} to continue.",
                    incr_str
                );
                std::process::exit(1);
            }
            _ => (),
        });

    let command = match cmdline::try_parse_from(env::args()) {
        Ok(cmd) => cmd,
        Err(e) => match e.downcast::<clap::error::Error>() {
            Ok(clap_err) => clap_err.exit(),
            Err(some_other_err) => {
                println!("sccache-dist: {some_other_err}");
                for source_err in some_other_err.chain().skip(1) {
                    println!("sccache-dist: caused by: {source_err}");
                }
                std::process::exit(1);
            }
        },
    };

    std::process::exit(match run(command) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sccache-dist: error: {}", e);

            for e in e.chain().skip(1) {
                eprintln!("sccache-dist: caused by: {}", e);
            }
            2
        }
    });
}

fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{} {}", server_id.addr(), auth_token)
}
fn check_server_token(server_token: &str, auth_token: &str) -> Option<ServerId> {
    let mut split = server_token.splitn(2, ' ');
    let server_addr = split.next().and_then(|addr| addr.parse().ok())?;
    match split.next() {
        Some(t) if t == auth_token => Some(ServerId::new(server_addr)),
        Some(_) | None => None,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerJwt {
    exp: u64,
    server_id: ServerId,
}
fn create_jwt_server_token(
    server_id: ServerId,
    header: &jwt::Header,
    key: &[u8],
) -> Result<String> {
    let key = jwt::EncodingKey::from_secret(key);
    jwt::encode(header, &ServerJwt { exp: 0, server_id }, &key).map_err(Into::into)
}
fn dangerous_insecure_extract_jwt_server_token(server_token: &str) -> Result<ServerId> {
    let validation = {
        let mut validation = jwt::Validation::default();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.insecure_disable_signature_validation();
        validation
    };
    let dummy_key = jwt::DecodingKey::from_secret(b"secret");
    jwt::decode::<ServerJwt>(server_token, &dummy_key, &validation)
        .map(|res| res.claims.server_id)
        .map_err(Into::into)
}
fn check_jwt_server_token(
    server_token: &str,
    key: &[u8],
    validation: &jwt::Validation,
) -> Option<ServerId> {
    let key = jwt::DecodingKey::from_secret(key);
    jwt::decode::<ServerJwt>(server_token, &key, validation)
        .map(|res| res.claims.server_id)
        .ok()
}

fn run(command: Command) -> Result<i32> {
    match command {
        Command::Auth(AuthSubcommand::Base64 { num_bytes }) => {
            let mut bytes = vec![0; num_bytes];
            OsRng.fill_bytes(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", BASE64_URL_SAFE_ENGINE.encode(bytes));
            Ok(0)
        }
        Command::Auth(AuthSubcommand::JwtHS256ServerToken {
            secret_key,
            server_id,
        }) => {
            let header = jwt::Header::new(jwt::Algorithm::HS256);
            let secret_key = BASE64_URL_SAFE_ENGINE.decode(secret_key)?;
            let token = create_jwt_server_token(server_id, &header, &secret_key)
                .context("Failed to create server token")?;
            println!("{}", token);
            Ok(0)
        }

        Command::Scheduler(scheduler_config::Config {
            public_addr,
            client_auth,
            server_auth,
        }) => {
            let check_client_auth: Box<dyn dist::http::ClientAuthCheck> = match client_auth {
                scheduler_config::ClientAuth::Insecure => Box::new(token_check::EqCheck::new(
                    INSECURE_DIST_CLIENT_TOKEN.to_owned(),
                )),
                scheduler_config::ClientAuth::Token { token } => {
                    Box::new(token_check::EqCheck::new(token))
                }
                scheduler_config::ClientAuth::JwtValidate {
                    audience,
                    issuer,
                    jwks_url,
                } => Box::new(
                    token_check::ValidJWTCheck::new(audience, issuer, &jwks_url)
                        .context("Failed to create a checker for valid JWTs")?,
                ),
                scheduler_config::ClientAuth::ProxyToken { url, cache_secs } => Box::new(
                    token_check::ProxyTokenCheck::new(url, cache_secs)
                        .context("failed to create proxy token checker")?,
                ),
            };

            let check_server_auth: dist::http::ServerAuthCheck = match server_auth {
                scheduler_config::ServerAuth::Insecure => {
                    warn!("Scheduler starting with DANGEROUSLY_INSECURE server authentication");
                    let token = INSECURE_DIST_SERVER_TOKEN;
                    Box::new(move |server_token| check_server_token(server_token, token))
                }
                scheduler_config::ServerAuth::Token { token } => {
                    Box::new(move |server_token| check_server_token(server_token, &token))
                }
                scheduler_config::ServerAuth::JwtHS256 { secret_key } => {
                    let secret_key = BASE64_URL_SAFE_ENGINE
                        .decode(secret_key)
                        .context("Secret key base64 invalid")?;
                    if secret_key.len() != 256 / 8 {
                        bail!("Size of secret key incorrect")
                    }
                    let validation = {
                        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
                        validation.leeway = 0;
                        validation.validate_exp = false;
                        validation.validate_nbf = false;
                        validation
                    };
                    Box::new(move |server_token| {
                        check_jwt_server_token(server_token, &secret_key, &validation)
                    })
                }
            };

            daemonize(&[])?;
            let scheduler = Scheduler::new();
            let http_scheduler = dist::http::Scheduler::new(
                public_addr,
                scheduler,
                check_client_auth,
                check_server_auth,
            );
            http_scheduler.start()?;
            unreachable!();
        }

        Command::Server(config) => {
            let server_config::Config {
                builder,
                cache_dir,
                public_addr,
                bind_address,
                scheduler_url,
                scheduler_auth,
                toolchain_cache_size,
                num_cpus: advertised_num_cpus,
                colocated_reserve_fraction,
            } = *config;
            let builder: Box<dyn dist::BuilderIncoming> = match builder {
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Docker => {
                    Box::new(build::DockerBuilder::new().context("Docker builder failed to start")?)
                }
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Overlay {
                    bwrap_path,
                    build_dir,
                } => Box::new(
                    build::OverlayBuilder::new(bwrap_path, build_dir)
                        .context("Overlay builder failed to start")?,
                ),
                #[cfg(target_os = "freebsd")]
                server_config::BuilderType::Pot {
                    pot_fs_root,
                    clone_from,
                    pot_cmd,
                    pot_clone_args,
                } => Box::new(
                    build::PotBuilder::new(pot_fs_root, clone_from, pot_cmd, pot_clone_args)
                        .context("Pot builder failed to start")?,
                ),
                _ => bail!(
                    "Builder type `{}` not supported on this platform",
                    format!("{:?}", builder)
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                ),
            };

            let server_id = ServerId::new(public_addr);
            let scheduler_auth = match scheduler_auth {
                server_config::SchedulerAuth::Insecure => {
                    warn!("Server starting with DANGEROUSLY_INSECURE scheduler authentication");
                    create_server_token(server_id, INSECURE_DIST_SERVER_TOKEN)
                }
                server_config::SchedulerAuth::Token { token } => {
                    create_server_token(server_id, &token)
                }
                server_config::SchedulerAuth::JwtToken { token } => {
                    let token_server_id: ServerId =
                        dangerous_insecure_extract_jwt_server_token(&token)
                            .context("Could not decode scheduler auth jwt")?;
                    if token_server_id != server_id {
                        bail!(
                            "JWT server id ({:?}) did not match configured server id ({:?})",
                            token_server_id,
                            server_id
                        )
                    }
                    token
                }
            };

            let server = Server::new(builder, &cache_dir, toolchain_cache_size)
                .context("Failed to create sccache server instance")?;
            let colocated = is_colocated(&scheduler_url.to_url(), public_addr.ip());
            let advertised_num_cpus = advertised_cores(
                advertised_num_cpus,
                num_cpus(),
                colocated,
                colocated_reserve_fraction,
            );
            let http_server = dist::http::Server::new(
                public_addr,
                bind_address,
                scheduler_url.to_url(),
                scheduler_auth,
                advertised_num_cpus,
                server,
            )
            .context("Failed to create sccache HTTP server instance")?;
            http_server.start()?;
            unreachable!();
        }
    }
}

fn init_logging() {
    if env::var(sccache::LOGGING_ENV).is_ok() {
        let mut builder = env_logger::Builder::from_env(sccache::LOGGING_ENV);

        // Enable millisecond precision timestamps if SCCACHE_LOG_MILLIS is set
        if env::var("SCCACHE_LOG_MILLIS").is_ok() {
            builder.format_timestamp_millis();
        }

        match builder.try_init() {
            Ok(_) => (),
            Err(e) => panic!("Failed to initialize logging: {:?}", e),
        }
    }
}

// Maximum number of jobs per core - only occurs for one core, usually less, see load_weight()
const MAX_PER_CORE_LOAD: f64 = 2f64;
const SERVER_REMEMBER_ERROR_TIMEOUT: Duration = Duration::from_secs(300);
// A server that just failed a job assignment is demoted so the scheduler
// prefers a healthy one. The demotion must not be absolute, though: a
// network-remote server takes transient assignment errors that a
// scheduler-colocated server never does, so a hard demotion strands the remote
// node's idle capacity while jobs pile onto a busy local one (measured: 1710
// idle-server skips in one build, all on the remote node). Treat a recent error
// as this much extra load instead, so a recently-errored server still wins when
// it is more than this margin less loaded than the healthy alternative - a
// repeat failure only costs one wasted round-trip and a local fallback.
const RECENT_ERROR_LOAD_PENALTY: f64 = 0.125;
// A failed assignment leaves the server idle, so the penalty alone keeps it the
// least-loaded candidate and a dead node would absorb every allocation. A
// recently-errored server is therefore only preferred over a healthy one once
// this long has passed since its last failure; each new failure restarts the wait.
const RECENT_ERROR_PROBE_INTERVAL: Duration = Duration::from_secs(1);
const UNCLAIMED_PENDING_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_READY_TIMEOUT: Duration = Duration::from_secs(60);
// A job that entered Started but never reported Complete leaks its
// jobs_assigned slot: the Ready->Started transition drops it from
// jobs_unclaimed, so the unclaimed reaper can never see it again, and
// prune_servers only reclaims a DEAD server's jobs. On a live server, such
// jobs accumulate until jobs_assigned hits admission_ceiling and load_weight
// stops routing to the node - the measured PC2-idle-at-37/37 lockout, its
// completion updates lost while it sat pinned. Reap a Started job the owning
// server has not completed within this timeout, mirroring prune_servers (dead
// servers) and the unclaimed reaper (stuck Ready/Pending). The value is far
// longer than any real remote single-TU compile (a heavy LLVM object is ~60s)
// yet short enough to reclaim a leaked slot briskly. Reaping only the
// scheduler's accounting never aborts the client's in-flight compile - that
// runs over a separate client<->server channel - so an over-eager reap at
// worst mildly oversubscribes, which admission_ceiling already tolerates.
const STARTED_COMPLETE_TIMEOUT: Duration = Duration::from_secs(180);
// Minimum time a job must have been in Started before the liveness lease may
// reap it for two consecutive absent heartbeats. Must exceed the 30s
// HEARTBEAT_INTERVAL (src/dist/http.rs) so a reapable job has been Started
// across at least one full beat period; otherwise a job that transitions to
// Started between two beats looks vacuously "absent from the prior beat" and
// could be reaped milliseconds after it starts.
const LIVENESS_GRACE: Duration = Duration::from_secs(45);
// A build server drops its per-job toolchain entry in handle_run_job. An
// assign whose run_job never arrives (client crash, scheduler restart) would
// otherwise leak the entry forever, so sweep entries older than this on each
// assign. Far longer than a legitimate assign->run_job gap. Must stay greater
// than UNCLAIMED_PENDING_TIMEOUT (300s) + UNCLAIMED_READY_TIMEOUT (60s) so the
// GC never evicts a still-in-flight job's toolchain entry.
const ABANDONED_TOOLCHAIN_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Copy, Clone)]
struct JobDetail {
    server_id: ServerId,
    state: JobState,
    // When the job entered its current state; used to reap Started jobs whose
    // Complete update was lost (see STARTED_COMPLETE_TIMEOUT).
    since: Instant,
}

// To avoid deadlicking, make sure to do all locking at once (i.e. no further locking in a downward scope),
// in alphabetical order
pub struct Scheduler {
    // Build servers may survive a scheduler restart and retain pending job IDs.
    // Start each scheduler instance in a different ID range so a restarted
    // scheduler does not immediately reuse IDs still known to surviving servers.
    job_id_base: u64,
    job_count: AtomicUsize,

    // Currently running jobs, can never be Complete
    jobs: Mutex<BTreeMap<JobId, JobDetail>>,

    servers: Mutex<HashMap<ServerId, ServerDetails>>,

    // Cumulative job-lifecycle counters for the between-nodes leak detector
    // logged once per heartbeat (see the dist-accounting line in
    // handle_heartbeat_server). Relaxed: diagnostic counters, not
    // synchronization. Two leak modes are separable from the balance:
    //   allocated - started - reaped_unclaimed - (unclaimed jobs still live)
    //     drifting up  => a feed/unclaimed leak (jobs allocated, never claimed).
    //   started - completed - reaped_started - (started jobs still live)
    //     drifting up  => a lost-completion leak (the Leak #1 class).
    jobs_started: AtomicUsize,
    jobs_completed: AtomicUsize,
    jobs_reaped_unclaimed: AtomicUsize,
    jobs_reaped_started: AtomicUsize,
    jobs_pruned: AtomicUsize,
}

struct ServerDetails {
    jobs_assigned: HashSet<JobId>,
    // Jobs assigned that haven't seen a state change. Can only be pending
    // or ready.
    jobs_unclaimed: HashMap<JobId, Instant>,
    // Job ids this server reported running in its previous heartbeat. A Started
    // job is reaped only when it is absent from both this set and the incoming
    // heartbeat's active_jobs (two consecutive misses), so a single dropped or
    // racing heartbeat never reaps a live compile.
    last_active_jobs: HashSet<JobId>,
    last_seen: Instant,
    last_error: Option<Instant>,
    num_cpus: usize,
    server_nonce: ServerNonce,
    job_authorizer: Box<dyn JobAuthorizer>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::with_job_id_base(OsRng.next_u64())
    }

    fn with_job_id_base(job_id_base: u64) -> Self {
        Scheduler {
            job_id_base,
            job_count: AtomicUsize::new(0),
            jobs: Mutex::new(BTreeMap::new()),
            servers: Mutex::new(HashMap::new()),
            jobs_started: AtomicUsize::new(0),
            jobs_completed: AtomicUsize::new(0),
            jobs_reaped_unclaimed: AtomicUsize::new(0),
            jobs_reaped_started: AtomicUsize::new(0),
            jobs_pruned: AtomicUsize::new(0),
        }
    }

    fn next_job_id(&self) -> JobId {
        let job_count = self.job_count.fetch_add(1, Ordering::SeqCst) as u64;
        JobId(self.job_id_base.wrapping_add(job_count))
    }

    fn prune_servers(
        &self,
        servers: &mut MutexGuard<HashMap<ServerId, ServerDetails>>,
        jobs: &mut MutexGuard<BTreeMap<JobId, JobDetail>>,
    ) {
        let now = Instant::now();

        let mut dead_servers = Vec::new();

        for (&server_id, details) in servers.iter_mut() {
            if now.duration_since(details.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
                dead_servers.push(server_id);
            }
        }

        for server_id in dead_servers {
            warn!(
                "Server {} appears to be dead, pruning it in the scheduler",
                server_id.addr()
            );
            let server_details = servers
                .remove(&server_id)
                .expect("server went missing from map");
            self.jobs_pruned
                .fetch_add(server_details.jobs_assigned.len(), Ordering::Relaxed);
            for job_id in server_details.jobs_assigned {
                warn!(
                    "Non-terminated job {} was cleaned up in server pruning",
                    job_id
                );
                // A job may be missing here if it failed to allocate
                // initially, so just warn if it's not present.
                if jobs.remove(&job_id).is_none() {
                    warn!(
                        "Non-terminated job {} assignment originally failed.",
                        job_id
                    );
                }
            }
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

fn admission_ceiling(core_count: usize) -> usize {
    // Oversubscribe cores just a little to make up for network and I/O latency. This formula is
    // not based on hard data but an extrapolation to high core counts of the conventional wisdom
    // that slightly more jobs than cores achieve the shortest compile time. Which is originally
    // about local compiles and this is over the network, so be slightly less conservative.
    core_count + 1 + core_count / 8
}

fn load_weight(job_count: usize, core_count: usize) -> f64 {
    // Note >=, not >, because the question is "can we add another job"?
    if job_count >= admission_ceiling(core_count) {
        MAX_PER_CORE_LOAD + 1f64 // no new jobs for now
    } else {
        job_count as f64 / core_count as f64
    }
}

/// Default fraction of its cores a colocated build server holds back from the
/// scheduler, reserving them for the local client's preprocessing and bitbake.
const DEFAULT_COLOCATED_RESERVE_FRACTION: f64 = 0.35;

/// Resolve the core count a build server advertises to the scheduler. An
/// explicit `num_cpus` wins; otherwise a server colocated with the scheduler
/// reserves `reserve_fraction` of its hardware (default
/// [`DEFAULT_COLOCATED_RESERVE_FRACTION`]) so the load model routes
/// proportionally more to the pure-remote nodes, while a remote server
/// advertises all its cores. Computed from the node's own `hw`, so the same
/// binary and config are portable across cluster topologies.
fn advertised_cores(
    explicit: Option<usize>,
    hw: usize,
    colocated: bool,
    reserve_fraction: Option<f64>,
) -> usize {
    // 0 cores is not a count the scheduler accepts, and NaN would clamp to NaN and
    // round to a single core, so both fall back to the computed value.
    if let Some(n) = explicit.filter(|&n| n > 0) {
        return n;
    }
    if colocated {
        let fraction = reserve_fraction
            .filter(|f| f.is_finite())
            .unwrap_or(DEFAULT_COLOCATED_RESERVE_FRACTION)
            .clamp(0.0, 0.9);
        std::cmp::max(1, (hw as f64 * (1.0 - fraction)).round() as usize)
    } else {
        hw
    }
}

/// Whether the scheduler runs on the machine this build server is on. The scheduler
/// URL may name the host by address, by IPv6 literal (`host_str` keeps the brackets),
/// by loopback or by DNS name, and comparing it to the server's public address as a
/// string only ever matched the plain-IPv4 spelling.
fn is_colocated(scheduler_url: &reqwest::Url, public_ip: IpAddr) -> bool {
    let Some(host) = scheduler_url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let resolved: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => (host, scheduler_url.port_or_known_default().unwrap_or(0))
            .to_socket_addrs()
            .map(|addrs| addrs.map(|addr| addr.ip()).collect())
            .unwrap_or_default(),
    };
    resolved
        .iter()
        .any(|ip| ip.is_loopback() || *ip == public_ip)
}

#[cfg(test)]
mod advertised_cores_tests {
    use super::{advertised_cores, is_colocated};
    use std::net::IpAddr;

    fn url(s: &str) -> reqwest::Url {
        s.parse().unwrap()
    }

    #[test]
    fn a_scheduler_at_the_servers_own_ipv4_address_is_colocated() {
        let ip: IpAddr = "10.42.0.1".parse().unwrap();
        assert!(is_colocated(&url("http://10.42.0.1:10600"), ip));
    }

    #[test]
    fn a_scheduler_at_another_address_is_not_colocated() {
        let ip: IpAddr = "10.42.0.2".parse().unwrap();
        assert!(!is_colocated(&url("http://10.42.0.1:10600"), ip));
    }

    #[test]
    fn a_loopback_scheduler_is_colocated_whatever_the_public_address() {
        let ip: IpAddr = "10.42.0.2".parse().unwrap();
        assert!(is_colocated(&url("http://127.0.0.1:10600"), ip));
        assert!(is_colocated(&url("http://[::1]:10600"), ip));
    }

    #[test]
    fn a_bracketed_ipv6_scheduler_matches_the_servers_ipv6_address() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_colocated(&url("http://[fd00::1]:10600"), ip));
        assert!(!is_colocated(&url("http://[fd00::2]:10600"), ip));
    }

    #[test]
    fn reserves_the_default_fraction_when_colocated() {
        // 32 cores, colocated, default 0.35 -> round(32 * 0.65) = 21.
        assert_eq!(advertised_cores(None, 32, true, None), 21);
    }

    #[test]
    fn a_remote_server_advertises_all_cores() {
        assert_eq!(advertised_cores(None, 32, false, None), 32);
    }

    #[test]
    fn an_explicit_count_overrides_the_fraction() {
        assert_eq!(advertised_cores(Some(16), 32, true, None), 16);
    }

    // The scheduler rejects a heartbeat advertising 0 cores, so a configured 0 would
    // leave the server unable to register at all.
    #[test]
    fn an_explicit_zero_falls_back_to_the_computed_count() {
        assert_eq!(advertised_cores(Some(0), 32, false, None), 32);
        assert_eq!(advertised_cores(Some(0), 32, true, None), 21);
    }

    #[test]
    fn a_non_finite_fraction_falls_back_to_the_default() {
        assert_eq!(advertised_cores(None, 32, true, Some(f64::NAN)), 21);
        assert_eq!(advertised_cores(None, 32, true, Some(f64::INFINITY)), 21);
    }

    #[test]
    fn a_custom_fraction_is_honoured() {
        assert_eq!(advertised_cores(None, 32, true, Some(0.5)), 16);
    }
}

impl SchedulerIncoming for Scheduler {
    fn handle_alloc_job(
        &self,
        requester: &dyn SchedulerOutgoing,
        tc: Toolchain,
    ) -> Result<AllocJobResult> {
        let (job_id, server_id, auth) = {
            // LOCKS
            let mut servers = self.servers.lock().unwrap();

            // R0 instrumentation: snapshot every candidate's load so the
            // allocation decision logged below exposes the load distribution
            // across nodes and any first-hashed-server tie bias.
            let mut candidate_loads: Vec<(ServerId, f64, usize, usize)> = Vec::new();

            let res = {
                let mut best = None;
                let mut best_err = None;
                let mut best_load: f64 = MAX_PER_CORE_LOAD;
                let mut best_free: usize = 0;
                let mut best_err_load: f64 = MAX_PER_CORE_LOAD;
                let mut best_err_probe_due = false;
                let now = Instant::now();
                for (&server_id, details) in servers.iter_mut() {
                    // A server silent past the heartbeat timeout is dead but
                    // is only removed by prune_servers (heartbeat / status
                    // paths), not here. Skip it so a job is never dispatched
                    // to a node that is gone - which would fail and fall back
                    // local, silently skewing dist measurements.
                    if now.duration_since(details.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
                        continue;
                    }
                    let load = load_weight(details.jobs_assigned.len(), details.num_cpus);
                    candidate_loads.push((
                        server_id,
                        load,
                        details.jobs_assigned.len(),
                        details.num_cpus,
                    ));

                    if let Some(last_error) = details.last_error {
                        if load < MAX_PER_CORE_LOAD {
                            if now.duration_since(last_error) > SERVER_REMEMBER_ERROR_TIMEOUT {
                                details.last_error = None;
                            }
                            match best_err {
                                Some((
                                    _,
                                    &mut ServerDetails {
                                        last_error: Some(best_last_err),
                                        ..
                                    },
                                )) => {
                                    if last_error < best_last_err {
                                        trace!(
                                            "Selected {:?}, its most recent error is {:?} ago",
                                            server_id,
                                            now - last_error
                                        );
                                        best_err = Some((server_id, details));
                                        best_err_load = load;
                                        best_err_probe_due = now.duration_since(last_error)
                                            >= RECENT_ERROR_PROBE_INTERVAL;
                                    }
                                }
                                _ => {
                                    trace!(
                                        "Selected {:?}, its most recent error is {:?} ago",
                                        server_id,
                                        now - last_error
                                    );
                                    best_err = Some((server_id, details));
                                    best_err_load = load;
                                    best_err_probe_due = now.duration_since(last_error)
                                        >= RECENT_ERROR_PROBE_INTERVAL;
                                }
                            }
                        }
                    } else {
                        // Deterministic, remote-preferring tie-break, and no early
                        // break: scan every server so the logged candidate list is
                        // complete (a truncated list can never expose a misroute) and
                        // hash-map order never silently decides a both-idle tie. On
                        // equal load prefer the server with more free admission slots -
                        // with A1's advertised-cores override the colocated node
                        // advertises fewer, so the remote node wins the tie and a
                        // compile burst starts off the already-busy local node.
                        let free = admission_ceiling(details.num_cpus)
                            .saturating_sub(details.jobs_assigned.len());
                        if load < best_load || (load == best_load && free > best_free) {
                            trace!("Selected {:?} as the server with the best load", server_id);
                            best = Some((server_id, details));
                            best_load = load;
                            best_free = free;
                        }
                    }
                }

                // Assign the job to our best choice. Prefer the least-loaded
                // healthy server, but fall to a recently-errored one when it is
                // more than RECENT_ERROR_LOAD_PENALTY less loaded - so a remote
                // node briefly demoted by a transient error is not stranded idle
                // while a busy healthy node absorbs the work. best_load /
                // best_err_load stay MAX_PER_CORE_LOAD while their bucket is
                // empty, so the comparison naturally keeps the populated one.
                let choice = match (best, best_err) {
                    (Some(clean), Some(errored)) => {
                        if best_err_probe_due
                            && best_err_load + RECENT_ERROR_LOAD_PENALTY < best_load
                        {
                            Some(errored)
                        } else {
                            Some(clean)
                        }
                    }
                    (Some(clean), None) => Some(clean),
                    (None, errored) => errored,
                };
                if let Some((server_id, server_details)) = choice {
                    let job_id = self.next_job_id();
                    assert!(server_details.jobs_assigned.insert(job_id));
                    assert!(
                        server_details
                            .jobs_unclaimed
                            .insert(job_id, Instant::now())
                            .is_none()
                    );

                    info!(
                        "Job {} created and will be assigned to server {:?}",
                        job_id, server_id
                    );
                    info!(
                        "dist-alloc: job {} -> {:?} (now {}/{} jobs, load {:.3}); candidates {:?}",
                        job_id,
                        server_id,
                        server_details.jobs_assigned.len(),
                        server_details.num_cpus,
                        load_weight(server_details.jobs_assigned.len(), server_details.num_cpus),
                        candidate_loads,
                    );
                    let auth = server_details
                        .job_authorizer
                        .generate_token(job_id)
                        .context("Could not create an auth token for this job")?;
                    Some((job_id, server_id, auth))
                } else {
                    None
                }
            };

            if let Some(res) = res {
                res
            } else {
                let msg = format!(
                    "Insufficient capacity across {} available servers",
                    servers.len()
                );
                warn!("dist-alloc: {}; candidates {:?}", msg, candidate_loads);
                return Ok(AllocJobResult::Fail { msg });
            }
        };
        let AssignJobResult {
            state,
            need_toolchain,
        } = requester
            .do_assign_job(server_id, job_id, tc, auth.clone())
            .with_context(|| {
                // LOCKS
                let mut servers = self.servers.lock().unwrap();
                if let Some(entry) = servers.get_mut(&server_id) {
                    entry.last_error = Some(Instant::now());
                    entry.jobs_unclaimed.remove(&job_id);
                    if !entry.jobs_assigned.remove(&job_id) {
                        "assign job failed and job not known to the server"
                    } else {
                        "assign job failed, job un-assigned from the server"
                    }
                } else {
                    "assign job failed and server not known"
                }
            })?;
        {
            // LOCKS
            let mut jobs = self.jobs.lock().unwrap();
            let servers = self.servers.lock().unwrap();

            if !servers
                .get(&server_id)
                .is_some_and(|details| details.jobs_assigned.contains(&job_id))
            {
                let msg = format!(
                    "Job {} assignment was cleaned up before allocation completed",
                    job_id
                );
                warn!("{}", msg);
                return Ok(AllocJobResult::Fail { msg });
            }

            info!(
                "Job {} successfully assigned and saved with state {:?}",
                job_id, state
            );
            assert!(
                jobs.insert(
                    job_id,
                    JobDetail {
                        server_id,
                        state,
                        since: Instant::now(),
                    }
                )
                .is_none()
            );
        }
        let job_alloc = JobAlloc {
            auth,
            job_id,
            server_id,
        };
        Ok(AllocJobResult::Success {
            job_alloc,
            need_toolchain,
        })
    }

    fn handle_heartbeat_server(
        &self,
        server_id: ServerId,
        server_nonce: ServerNonce,
        num_cpus: usize,
        job_authorizer: Box<dyn JobAuthorizer>,
        active_jobs: Vec<JobId>,
    ) -> Result<HeartbeatServerResult> {
        if num_cpus == 0 {
            bail!("Invalid number of CPUs (0) specified in heartbeat")
        }

        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

        match servers.get_mut(&server_id) {
            Some(ref mut details) if details.server_nonce == server_nonce => {
                let now = Instant::now();
                details.last_seen = now;

                let mut stale_jobs = Vec::new();
                for (&job_id, &last_seen) in details.jobs_unclaimed.iter() {
                    if now.duration_since(last_seen) < UNCLAIMED_READY_TIMEOUT {
                        continue;
                    }
                    if let Some(detail) = jobs.get(&job_id) {
                        match detail.state {
                            JobState::Ready => {
                                stale_jobs.push(job_id);
                            }
                            JobState::Pending => {
                                if now.duration_since(last_seen) > UNCLAIMED_PENDING_TIMEOUT {
                                    stale_jobs.push(job_id);
                                }
                            }
                            state => {
                                warn!("Invalid unclaimed job state for {}: {}", job_id, state);
                            }
                        }
                    } else {
                        warn!("Unknown stale job {}", job_id);
                        stale_jobs.push(job_id);
                    }
                }

                if !stale_jobs.is_empty() {
                    warn!(
                        "The following stale jobs will be de-allocated: {:?}",
                        stale_jobs
                    );
                    self.jobs_reaped_unclaimed
                        .fetch_add(stale_jobs.len(), Ordering::Relaxed);

                    for job_id in stale_jobs {
                        if !details.jobs_assigned.remove(&job_id) {
                            warn!(
                                "Stale job for server {} not assigned: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                        if details.jobs_unclaimed.remove(&job_id).is_none() {
                            warn!(
                                "Unknown stale job for server {}: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                        if jobs.remove(&job_id).is_none() {
                            warn!(
                                "Unknown stale job for server {}: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                    }
                }

                // Primary Started-reap mechanism: the liveness lease. Every
                // heartbeat carries the ids the server is actively running.
                // Reap a Started job only once it is absent from BOTH the
                // incoming active_jobs AND last_active_jobs (the prior beat) -
                // two consecutive misses - so a genuinely-slow live compile,
                // which the server reports every beat, is never reaped, and one
                // dropped or racing heartbeat cannot reap a live job. The
                // fixed-timeout sweep below stays only as a backstop for a
                // server that stops heartbeating its running set entirely.
                let active_set: HashSet<JobId> = active_jobs.into_iter().collect();
                let mut liveness_reap = Vec::new();
                for &job_id in details.jobs_assigned.iter() {
                    if let Some(detail) = jobs.get(&job_id)
                        && detail.state == JobState::Started
                        && !active_set.contains(&job_id)
                        && !details.last_active_jobs.contains(&job_id)
                        && now.duration_since(detail.since) > LIVENESS_GRACE
                    {
                        liveness_reap.push(job_id);
                    }
                }
                if !liveness_reap.is_empty() {
                    warn!(
                        "The following Started jobs were absent from two consecutive heartbeats and will be de-allocated: {:?}",
                        liveness_reap
                    );
                    self.jobs_reaped_started
                        .fetch_add(liveness_reap.len(), Ordering::Relaxed);
                    for job_id in liveness_reap {
                        details.jobs_assigned.remove(&job_id);
                        jobs.remove(&job_id);
                    }
                }
                details.last_active_jobs = active_set;

                // Backstop for jobs stuck in Started (see STARTED_COMPLETE_TIMEOUT):
                // the unclaimed sweep above cannot see them because Ready->Started
                // drops them from jobs_unclaimed. Reap any this server has held in
                // Started past the timeout so a lost Complete update cannot leak the
                // slot forever and eventually lock the node out at its ceiling.
                // Never reap a job the server just reported active (now stored in
                // last_active_jobs): a genuinely-slow live compile must survive at
                // any duration, so the backstop only fires once the server has
                // stopped naming the job in its heartbeats.
                let mut stale_started = Vec::new();
                for &job_id in details.jobs_assigned.iter() {
                    if let Some(detail) = jobs.get(&job_id)
                        && detail.state == JobState::Started
                        && now.duration_since(detail.since) > STARTED_COMPLETE_TIMEOUT
                    {
                        if details.last_active_jobs.contains(&job_id) {
                            // Still reported active past the backstop timeout:
                            // not reaped (a genuinely-slow live compile must
                            // survive) but likely a wedged build the server
                            // names forever. Surface it so it is visible in
                            // logs rather than silently accumulating.
                            warn!(
                                "Started job {} on server {} still reported active past {:?}; possible wedged build",
                                job_id,
                                server_id.addr(),
                                STARTED_COMPLETE_TIMEOUT
                            );
                        } else {
                            stale_started.push(job_id);
                        }
                    }
                }
                if !stale_started.is_empty() {
                    warn!(
                        "The following Started jobs had no Complete within {:?} and will be de-allocated: {:?}",
                        STARTED_COMPLETE_TIMEOUT, stale_started
                    );
                    self.jobs_reaped_started
                        .fetch_add(stale_started.len(), Ordering::Relaxed);
                    for job_id in stale_started {
                        details.jobs_assigned.remove(&job_id);
                        jobs.remove(&job_id);
                    }
                }

                // Between-nodes leak detector: one cumulative accounting line
                // per heartbeat (cheap - ~per-30s per server, NOT per compile).
                // A rising (allocated - started - reaped_unclaimed - unclaimed
                // still live) points to a feed/unclaimed leak; a rising (started
                // - completed - reaped_started - started still live) points to a
                // lost-completion leak. `live` = current jobs-map size.
                info!(
                    "dist-accounting: allocated={} started={} completed={} reaped_unclaimed={} reaped_started={} pruned={} live={}",
                    self.job_count.load(Ordering::Relaxed),
                    self.jobs_started.load(Ordering::Relaxed),
                    self.jobs_completed.load(Ordering::Relaxed),
                    self.jobs_reaped_unclaimed.load(Ordering::Relaxed),
                    self.jobs_reaped_started.load(Ordering::Relaxed),
                    self.jobs_pruned.load(Ordering::Relaxed),
                    jobs.len(),
                );

                return Ok(HeartbeatServerResult { is_new: false });
            }
            Some(ref mut details) if details.server_nonce != server_nonce => {
                for job_id in details.jobs_assigned.iter() {
                    if jobs.remove(job_id).is_none() {
                        warn!(
                            "Unknown job found when replacing server {}: {}",
                            server_id.addr(),
                            job_id
                        );
                    }
                }
            }
            _ => (),
        }
        info!("Registered new server {:?}", server_id);
        servers.insert(
            server_id,
            ServerDetails {
                last_seen: Instant::now(),
                last_error: None,
                jobs_assigned: HashSet::new(),
                jobs_unclaimed: HashMap::new(),
                last_active_jobs: HashSet::new(),
                num_cpus,
                server_nonce,
                job_authorizer,
            },
        );
        Ok(HeartbeatServerResult { is_new: true })
    }

    fn handle_deregister_server(&self, server_id: ServerId) -> Result<DeregisterServerResult> {
        // LOCKS (jobs before servers, matching the alphabetical lock order
        // used across the scheduler to avoid deadlock).
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        if let Some(details) = servers.remove(&server_id) {
            info!(
                "Server {} deregistered on graceful shutdown",
                server_id.addr()
            );
            // Drop any jobs the departing server still held, as prune_servers
            // does, so the scheduler does not track work no node will finish.
            self.jobs_pruned
                .fetch_add(details.jobs_assigned.len(), Ordering::Relaxed);
            for job_id in details.jobs_assigned {
                jobs.remove(&job_id);
            }
        }
        Ok(DeregisterServerResult { success: true })
    }

    fn handle_update_job_state(
        &self,
        job_id: JobId,
        server_id: ServerId,
        job_state: JobState,
    ) -> Result<UpdateJobStateResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        if let btree_map::Entry::Occupied(mut entry) = jobs.entry(job_id) {
            let job_detail = entry.get();
            if job_detail.server_id != server_id {
                bail!(
                    "Job id {} is not registered on server {:?}",
                    job_id,
                    server_id
                )
            }

            let now = Instant::now();
            let mut server_details = servers.get_mut(&server_id);
            if let Some(ref mut details) = server_details {
                details.last_seen = now;
            }

            match (job_detail.state, job_state) {
                (JobState::Pending, JobState::Ready) => {
                    // Reset the unclaimed-reservation clock to Ready time rather
                    // than allocation time, so time spent uploading a toolchain
                    // (Pending) does not consume the claim budget and a job that
                    // is still uploading is not reaped as a no-show.
                    if let Some(details) = server_details
                        && let Some(t) = details.jobs_unclaimed.get_mut(&job_id)
                    {
                        *t = now;
                    }
                    let detail = entry.get_mut();
                    detail.state = job_state;
                    detail.since = now;
                }
                (JobState::Ready, JobState::Started) => {
                    if let Some(details) = server_details {
                        details.jobs_unclaimed.remove(&job_id);
                    } else {
                        warn!("Job state updated, but server is not known to scheduler");
                    }
                    let detail = entry.get_mut();
                    detail.state = job_state;
                    detail.since = now;
                    self.jobs_started.fetch_add(1, Ordering::Relaxed);
                }
                (JobState::Started, JobState::Complete) => {
                    let (job_id, _) = entry.remove_entry();
                    if let Some(entry) = server_details {
                        assert!(entry.jobs_assigned.remove(&job_id));
                    } else {
                        bail!("Job was marked as finished, but server is not known to scheduler")
                    }
                    self.jobs_completed.fetch_add(1, Ordering::Relaxed);
                }
                (from, to) => bail!("Invalid job state transition from {} to {}", from, to),
            }
            info!("Job {} updated state to {:?}", job_id, job_state);
        } else {
            // Idempotent late update: a Started/Complete update for a job the
            // scheduler no longer tracks (already reaped, or reclaimed by a
            // liveness sweep) is a logged no-op success, never an error. Erroring
            // here fails the server's run_job (which propagates the terminal
            // update), so the client would discard finished objects and recompile
            // locally - the reap-then-complete hazard.
            match job_state {
                JobState::Started | JobState::Complete => {
                    info!(
                        "Late {:?} update for untracked job {} (already reaped); no-op success",
                        job_state, job_id
                    );
                }
                // A Pending/Ready update for an untracked job is a real anomaly,
                // not a benign late terminal update, so keep erroring on it.
                _ => bail!("Unknown job"),
            }
        }
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_status(&self) -> Result<SchedulerStatusResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

        // R0 instrumentation: one-line status snapshot per poll so the
        // in-progress cadence across nodes is recoverable from the log.
        let status_snapshot: Vec<(String, usize, usize)> = servers
            .iter()
            .map(|(id, d)| (id.addr().to_string(), d.jobs_assigned.len(), d.num_cpus))
            .collect();
        info!(
            "dist-status poll: {} in-progress jobs; servers {:?}",
            jobs.len(),
            status_snapshot
        );

        Ok(SchedulerStatusResult {
            num_servers: servers.len(),
            num_cpus: servers.values().map(|v| v.num_cpus).sum(),
            in_progress: jobs.len(),
            servers: servers
                .iter()
                .map(|(server_id, details)| ServerStatusResult {
                    id: server_id.addr().to_string(),
                    num_cpus: details.num_cpus,
                    in_progress: details.jobs_assigned.len(),
                })
                .collect(),
        })
    }
}

pub struct Server {
    builder: Box<dyn BuilderIncoming>,
    cache: Mutex<TcCache>,
    job_toolchains: Mutex<HashMap<JobId, (Toolchain, Instant)>>,
    // Jobs currently executing a build. Reported in every heartbeat so the
    // scheduler's liveness lease never reaps a compile still in flight here.
    running_jobs: Mutex<HashSet<JobId>>,
    // One lock per toolchain being uploaded; see store_toolchain.
    upload_locks: UploadLocks,
}

impl Server {
    pub fn new(
        builder: Box<dyn BuilderIncoming>,
        cache_dir: &Path,
        toolchain_cache_size: u64,
    ) -> Result<Server> {
        let cache = TcCache::new(&cache_dir.join("tc"), toolchain_cache_size)
            .context("Failed to create toolchain cache")?;
        Ok(Server {
            builder,
            cache: Mutex::new(cache),
            job_toolchains: Mutex::new(HashMap::new()),
            running_jobs: Mutex::new(HashSet::new()),
            upload_locks: Mutex::new(HashMap::new()),
        })
    }
}

// Removes a job id from the running set no matter how handle_run_job returns
// (normal completion, build error, or panic), so a failed build can never
// leave a phantom entry that makes the scheduler believe the job is still live.
struct RunningJobGuard<'a> {
    running_jobs: &'a Mutex<HashSet<JobId>>,
    job_id: JobId,
}

impl Drop for RunningJobGuard<'_> {
    fn drop(&mut self) {
        self.running_jobs.lock().unwrap().remove(&self.job_id);
    }
}

type UploadLocks = Mutex<HashMap<Toolchain, Arc<Mutex<()>>>>;

// Receive one toolchain upload into the cache. Uploads of the same toolchain take
// turns on a per-toolchain lock, so a second client submitting it while the first is
// still transferring waits and then finds it cached, instead of streaming a second
// copy to disk and grafting it a second time. Uploads of different toolchains still
// run in parallel, and the transfer itself never holds the global cache mutex.
fn store_toolchain(
    cache: &Mutex<TcCache>,
    upload_locks: &UploadLocks,
    tc: &Toolchain,
    tc_rdr: &mut dyn io::Read,
) -> SubmitToolchainResult {
    let upload_lock = build::get_toolchain_lock(upload_locks, tc);
    let result = {
        let _upload_guard = upload_lock.lock().unwrap();
        receive_toolchain(cache, tc, tc_rdr)
    };
    build::prune_toolchain_lock(upload_locks, tc, &upload_lock);
    result
}

fn receive_toolchain(
    cache: &Mutex<TcCache>,
    tc: &Toolchain,
    tc_rdr: &mut dyn io::Read,
) -> SubmitToolchainResult {
    // Skip the transfer entirely if the toolchain is already cached. Grab the cache
    // directory while we hold the lock so the temp file lands on the same
    // filesystem and the final insert is a rename.
    let tc_cache_dir = {
        let cache = cache.lock().unwrap();
        // TODO: this returns before reading all the data, is that valid?
        if cache.contains_toolchain(tc) {
            return SubmitToolchainResult::Success;
        }
        cache.path().to_path_buf()
    };
    let Ok(mut tmpfile) = tempfile::NamedTempFile::new_in(&tc_cache_dir) else {
        return SubmitToolchainResult::CannotCache;
    };
    if io::copy(tc_rdr, tmpfile.as_file_mut()).is_err() {
        return SubmitToolchainResult::CannotCache;
    }
    let temp_path = tmpfile.into_temp_path();
    // Re-acquire the cache lock ONLY to graft the finished file into the cache.
    cache
        .lock()
        .unwrap()
        .insert_at(tc, &temp_path)
        .map(|_| SubmitToolchainResult::Success)
        .unwrap_or(SubmitToolchainResult::CannotCache)
}

impl ServerIncoming for Server {
    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = !self.cache.lock().unwrap().contains_toolchain(&tc);
        {
            let now = Instant::now();
            let mut toolchains = self.job_toolchains.lock().unwrap();
            // GC abandoned entries (assigns whose run_job never arrived) so the
            // map cannot grow without bound.
            toolchains
                .retain(|_, (_, since)| now.duration_since(*since) < ABANDONED_TOOLCHAIN_TIMEOUT);
            // Overwrite rather than assert: a surviving server can still hold a
            // stale entry for a reused id (e.g. a scheduler restart or a retried
            // assign). Warn and overwrite instead of panicking the worker.
            if toolchains.insert(job_id, (tc, now)).is_some() {
                warn!(
                    "Overwrote a stale toolchain entry for reused job id {}",
                    job_id
                );
            }
        }
        let state = if need_toolchain {
            JobState::Pending
        } else {
            // TODO: can start prepping the build environment now
            JobState::Ready
        };
        Ok(AssignJobResult {
            state,
            need_toolchain,
        })
    }
    fn handle_submit_toolchain(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        tc_rdr: ToolchainReader,
    ) -> Result<SubmitToolchainResult> {
        requester
            .do_update_job_state(job_id, JobState::Ready)
            .context("Updating job state failed")?;
        // TODO: need to lock the toolchain until the container has started
        // TODO: can start prepping container
        let tc = match self
            .job_toolchains
            .lock()
            .unwrap()
            .get(&job_id)
            .map(|(tc, _)| tc.clone())
        {
            Some(tc) => tc,
            None => return Ok(SubmitToolchainResult::JobNotFound),
        };
        Ok(store_toolchain(
            &self.cache,
            &self.upload_locks,
            &tc,
            &mut { tc_rdr },
        ))
    }
    fn handle_run_job(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_rdr: InputsReader,
    ) -> Result<RunJobResult> {
        // Register the job and arm the cleanup guard BEFORE telling the
        // scheduler the job started, so the id is tracked before the scheduler
        // acts on the Started update (shrinking the vacuous liveness-reap
        // window). De-registers on every exit path (success, build error,
        // panic), and the guard's Drop still cleans up if the update fails.
        self.running_jobs.lock().unwrap().insert(job_id);
        let _running_guard = RunningJobGuard {
            running_jobs: &self.running_jobs,
            job_id,
        };
        requester
            .do_update_job_state(job_id, JobState::Started)
            .context("Updating job state failed")?;
        let tc = self
            .job_toolchains
            .lock()
            .unwrap()
            .remove(&job_id)
            .map(|(tc, _)| tc);
        let res = match tc {
            None => Ok(RunJobResult::JobNotFound),
            Some(tc) => {
                match self
                    .builder
                    .run_build(tc, command, outputs, inputs_rdr, &self.cache)
                {
                    Err(e) => Err(e.context("run build failed")),
                    Ok(res) => Ok(RunJobResult::Complete(JobComplete {
                        output: res.output,
                        outputs: res.outputs,
                    })),
                }
            }
        };
        if let Err(e) = requester.do_update_job_state(job_id, JobState::Complete) {
            // Do not fail the compile because the scheduler rejected the terminal
            // update (e.g. the job was reaped mid-compile): the objects are built
            // and must reach the client rather than being discarded for a local
            // recompile.
            warn!(
                "Completing job {} with the scheduler failed ({:#}); returning results anyway",
                job_id, e
            );
        }
        res
    }
    fn active_jobs(&self) -> Vec<JobId> {
        self.running_jobs.lock().unwrap().iter().copied().collect()
    }
}

#[cfg(test)]
mod scheduler_tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn scheduler_instances_namespace_job_ids() {
        let scheduler0 = Scheduler::with_job_id_base(0x1000);
        let scheduler1 = Scheduler::with_job_id_base(0x2000);

        assert_eq!(scheduler0.next_job_id(), JobId(0x1000));
        assert_eq!(scheduler0.next_job_id(), JobId(0x1001));
        assert_eq!(scheduler1.next_job_id(), JobId(0x2000));

        let wrapping = Scheduler::with_job_id_base(u64::MAX - 1);
        assert_eq!(wrapping.next_job_id(), JobId(u64::MAX - 1));
        assert_eq!(wrapping.next_job_id(), JobId(u64::MAX));
        assert_eq!(wrapping.next_job_id(), JobId(0));
    }

    struct TestJobAuthorizer;

    impl JobAuthorizer for TestJobAuthorizer {
        fn generate_token(&self, _job_id: JobId) -> Result<String> {
            Ok(String::new())
        }

        fn verify_token(&self, _job_id: JobId, _token: &str) -> Result<()> {
            Ok(())
        }
    }

    struct ReapDuringAssign<'a> {
        scheduler: &'a Scheduler,
        server_id: ServerId,
        server_nonce: ServerNonce,
    }

    impl SchedulerOutgoing for ReapDuringAssign<'_> {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            _tc: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            assert_eq!(server_id, self.server_id);

            {
                let mut servers = self.scheduler.servers.lock().unwrap();
                let details = servers.get_mut(&server_id).unwrap();
                *details.jobs_unclaimed.get_mut(&job_id).unwrap() = Instant::now()
                    .checked_sub(UNCLAIMED_PENDING_TIMEOUT + Duration::from_secs(1))
                    .unwrap();
            }

            let heartbeat = self.scheduler.handle_heartbeat_server(
                server_id,
                self.server_nonce.clone(),
                1,
                Box::new(TestJobAuthorizer),
                Vec::new(),
            )?;
            assert!(!heartbeat.is_new);

            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    #[test]
    fn allocation_fails_if_assignment_is_cleaned_up() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let server_nonce = ServerNonce::new();

        scheduler
            .handle_heartbeat_server(
                server_id,
                server_nonce.clone(),
                1,
                Box::new(TestJobAuthorizer),
                Vec::new(),
            )
            .unwrap();

        let requester = ReapDuringAssign {
            scheduler: &scheduler,
            server_id,
            server_nonce,
        };
        let allocation = scheduler
            .handle_alloc_job(
                &requester,
                Toolchain {
                    archive_id: "test-toolchain".to_owned(),
                },
            )
            .unwrap();

        assert!(matches!(allocation, AllocJobResult::Fail { .. }));
        assert!(scheduler.jobs.lock().unwrap().is_empty());

        let servers = scheduler.servers.lock().unwrap();
        let details = servers.get(&server_id).unwrap();
        assert!(details.jobs_assigned.is_empty());
        assert!(details.jobs_unclaimed.is_empty());
    }

    struct PanicOnAssign;

    impl SchedulerOutgoing for PanicOnAssign {
        fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _tc: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            panic!("a job must never be assigned to a stale server");
        }
    }

    struct AssignOk;

    impl SchedulerOutgoing for AssignOk {
        fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _tc: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            Ok(AssignJobResult {
                state: JobState::Ready,
                need_toolchain: false,
            })
        }
    }

    fn insert_server(scheduler: &Scheduler, addr: &str, last_seen: Instant) {
        let server_id = ServerId::new(addr.parse::<SocketAddr>().unwrap());
        let mut servers = scheduler.servers.lock().unwrap();
        servers.insert(
            server_id,
            ServerDetails {
                last_seen,
                last_error: None,
                jobs_assigned: HashSet::new(),
                jobs_unclaimed: HashMap::new(),
                last_active_jobs: HashSet::new(),
                num_cpus: 32,
                server_nonce: ServerNonce::new(),
                job_authorizer: Box::new(TestJobAuthorizer),
            },
        );
    }

    fn a_toolchain() -> Toolchain {
        Toolchain {
            archive_id: "deadbeef".to_owned(),
        }
    }

    /// Fails every assignment to one address and records which addresses were tried.
    struct FailAssignTo {
        dead: &'static str,
        tried: std::sync::Mutex<Vec<String>>,
    }

    impl SchedulerOutgoing for FailAssignTo {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            _job_id: JobId,
            _tc: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            let addr = server_id.addr().to_string();
            self.tried.lock().unwrap().push(addr.clone());
            if addr == self.dead {
                bail!("connection refused");
            }
            Ok(AssignJobResult {
                state: JobState::Ready,
                need_toolchain: false,
            })
        }
    }

    fn dead_picks(scheduler: &Scheduler, dead: &'static str, allocs: usize) -> usize {
        let requester = FailAssignTo {
            dead,
            tried: Default::default(),
        };
        for _ in 0..allocs {
            let _ = scheduler.handle_alloc_job(&requester, a_toolchain());
        }
        let tried = requester.tried.lock().unwrap();
        tried.iter().filter(|a| a.as_str() == dead).count()
    }

    // A server that just refused an assignment stays idle, so with a flat error
    // penalty it looks the least loaded on every allocation and absorbs each one
    // while a healthy busy node waits. Right after a failure it must be skipped.
    #[test]
    fn test_alloc_job_skips_a_server_that_just_failed_an_assignment() {
        let scheduler = Scheduler::new();
        insert_busy_server(&scheduler, "10.42.0.1:10501", 5, None);
        insert_busy_server(&scheduler, "10.42.0.2:10501", 0, Some(Instant::now()));

        assert_eq!(0, dead_picks(&scheduler, "10.42.0.2:10501", 20));
    }

    // The skip is a probe interval, not a ban: a transiently failed node is tried
    // again once the interval has passed, and its next failure restarts the wait.
    #[test]
    fn test_alloc_job_probes_a_failed_server_once_per_interval() {
        let scheduler = Scheduler::new();
        insert_busy_server(&scheduler, "10.42.0.1:10501", 5, None);
        let past_interval = Instant::now() - (RECENT_ERROR_PROBE_INTERVAL + Duration::from_secs(1));
        insert_busy_server(&scheduler, "10.42.0.2:10501", 0, Some(past_interval));

        assert_eq!(1, dead_picks(&scheduler, "10.42.0.2:10501", 20));
    }

    // With no healthy alternative the failed server is still used, so a one-node
    // cluster is not stranded by a transient error.
    #[test]
    fn test_alloc_job_still_uses_a_failed_server_when_it_is_the_only_one() {
        let scheduler = Scheduler::new();
        insert_busy_server(&scheduler, "10.42.0.2:10501", 0, Some(Instant::now()));

        assert_eq!(3, dead_picks(&scheduler, "10.42.0.2:10501", 3));
    }

    // A server silent past HEARTBEAT_TIMEOUT is dead but is only removed by
    // prune_servers, which runs on the heartbeat and status paths - not on
    // alloc_job. Until then it must never receive a job, or the scheduler
    // dispatches to a node that is gone and the compile falls back local,
    // silently skewing a dist measurement.
    #[test]
    fn test_alloc_job_skips_server_stale_beyond_heartbeat_timeout() {
        let scheduler = Scheduler::new();
        let stale = Instant::now() - (dist::http::HEARTBEAT_TIMEOUT + Duration::from_secs(10));
        insert_server(&scheduler, "10.42.0.2:10501", stale);

        let res = scheduler
            .handle_alloc_job(&PanicOnAssign, a_toolchain())
            .expect("handle_alloc_job should not error");

        assert!(
            matches!(res, AllocJobResult::Fail { .. }),
            "a stale server must not be selected for assignment"
        );
    }

    // Guard against over-filtering: a server seen within the timeout is alive
    // and must remain a valid assignment target.
    #[test]
    fn test_alloc_job_uses_fresh_server() {
        let scheduler = Scheduler::new();
        insert_server(&scheduler, "10.42.0.1:10501", Instant::now());

        let res = scheduler
            .handle_alloc_job(&AssignOk, a_toolchain())
            .expect("handle_alloc_job should not error");

        assert!(
            matches!(res, AllocJobResult::Success { .. }),
            "a fresh server must be selected for assignment"
        );
    }

    // A graceful deregister must drop the server at once, without waiting for
    // the heartbeat timeout - even though its last_seen is current.
    #[test]
    fn test_deregister_server_removes_it_immediately() {
        let scheduler = Scheduler::new();
        insert_server(&scheduler, "10.42.0.2:10501", Instant::now());

        let server_id = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());
        let res = scheduler
            .handle_deregister_server(server_id)
            .expect("handle_deregister_server should not error");
        assert!(res.success);

        let status = scheduler.handle_status().expect("status");
        assert_eq!(
            status.num_servers, 0,
            "a deregistered server must be gone immediately"
        );
    }

    // Insert a live server carrying `num_jobs` assigned jobs and an optional
    // recent error. Job ids start high so they never collide with the ids the
    // scheduler mints from job_count (which starts at 0) during the alloc.
    fn insert_busy_server(
        scheduler: &Scheduler,
        addr: &str,
        num_jobs: usize,
        last_error: Option<Instant>,
    ) {
        let server_id = ServerId::new(addr.parse::<SocketAddr>().unwrap());
        let mut jobs_assigned = HashSet::new();
        for i in 0..num_jobs {
            jobs_assigned.insert(JobId(1000 + i as u64));
        }
        let mut servers = scheduler.servers.lock().unwrap();
        servers.insert(
            server_id,
            ServerDetails {
                last_seen: Instant::now(),
                last_error,
                jobs_assigned,
                jobs_unclaimed: HashMap::new(),
                last_active_jobs: HashSet::new(),
                num_cpus: 32,
                server_nonce: ServerNonce::new(),
                job_authorizer: Box::new(TestJobAuthorizer),
            },
        );
    }

    // A recently-errored but idle server must still win over a healthy but
    // heavily-loaded one. A network-remote node takes transient assignment
    // errors a colocated node never does; stranding its idle capacity while a
    // busy node absorbs the work was the dominant misroute (measured 1710x, all
    // on the remote node). Here the 12/32-vs-0 load gap clears the error
    // penalty, so the idle errored node wins.
    #[test]
    fn test_alloc_job_prefers_idle_errored_server_over_loaded_healthy_server() {
        let scheduler = Scheduler::new();
        insert_busy_server(&scheduler, "10.42.0.1:10501", 12, None);
        let probe_due = Instant::now() - (RECENT_ERROR_PROBE_INTERVAL + Duration::from_secs(1));
        insert_busy_server(&scheduler, "10.42.0.2:10501", 0, Some(probe_due));

        let res = scheduler
            .handle_alloc_job(&AssignOk, a_toolchain())
            .expect("handle_alloc_job should not error");

        match res {
            AllocJobResult::Success { job_alloc, .. } => assert_eq!(
                job_alloc.server_id.addr().to_string(),
                "10.42.0.2:10501",
                "the idle recently-errored server must win over the loaded healthy one"
            ),
            _ => panic!("expected a successful allocation"),
        }
    }

    // The error demotion is not abandoned: when the healthy server is only
    // marginally busier (within the penalty), the recently-errored server stays
    // demoted, so a flaky node is not chosen for a negligible capacity gain.
    #[test]
    fn test_alloc_job_keeps_healthy_server_when_error_penalty_outweighs_gap() {
        let scheduler = Scheduler::new();
        insert_busy_server(&scheduler, "10.42.0.1:10501", 2, None);
        insert_busy_server(&scheduler, "10.42.0.2:10501", 0, Some(Instant::now()));

        let res = scheduler
            .handle_alloc_job(&AssignOk, a_toolchain())
            .expect("handle_alloc_job should not error");

        match res {
            AllocJobResult::Success { job_alloc, .. } => assert_eq!(
                job_alloc.server_id.addr().to_string(),
                "10.42.0.1:10501",
                "a marginally-busier healthy server must be kept over a flaky one"
            ),
            _ => panic!("expected a successful allocation"),
        }
    }

    // Register `job_id` on `server_id` as an in-flight Started job whose state
    // was entered `age` ago, exactly as it sits after a Ready->Started update:
    // present in jobs_assigned and the jobs map, absent from jobs_unclaimed.
    fn insert_started_job(
        scheduler: &Scheduler,
        server_id: ServerId,
        job_id: JobId,
        age: Duration,
    ) {
        let mut servers = scheduler.servers.lock().unwrap();
        let mut jobs_assigned = HashSet::new();
        jobs_assigned.insert(job_id);
        servers.insert(
            server_id,
            ServerDetails {
                last_seen: Instant::now(),
                last_error: None,
                jobs_assigned,
                jobs_unclaimed: HashMap::new(),
                last_active_jobs: HashSet::new(),
                num_cpus: 32,
                server_nonce: ServerNonce::new(),
                job_authorizer: Box::new(TestJobAuthorizer),
            },
        );
        let mut jobs = scheduler.jobs.lock().unwrap();
        jobs.insert(
            job_id,
            JobDetail {
                server_id,
                state: JobState::Started,
                since: Instant::now() - age,
            },
        );
    }

    // A job stuck in Started (its Complete update lost) must be reaped on the
    // owning server's next heartbeat, or its jobs_assigned slot leaks until the
    // node hits admission_ceiling and load_weight locks it out - the measured
    // PC2-idle-at-37/37 failure. prune_servers reclaims only dead servers and
    // the unclaimed reaper sees only Ready/Pending, so without a Started
    // backstop the slot never frees on a live server. Falsifier: dropping the
    // Started sweep leaves the job assigned after the heartbeat.
    #[test]
    fn test_heartbeat_reaps_started_job_past_completion_timeout() {
        let scheduler = Scheduler::new();
        let server_id = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());
        let job_id = JobId(1000);
        insert_started_job(
            &scheduler,
            server_id,
            job_id,
            STARTED_COMPLETE_TIMEOUT + Duration::from_secs(10),
        );
        // Seed the prior-beat active set so the liveness lease grants this job
        // its grace beat: with the job absent from active_jobs but present in
        // last_active_jobs, the liveness path skips it, so the reap here can
        // only come from the age-based backstop this test exercises.
        scheduler
            .servers
            .lock()
            .unwrap()
            .get_mut(&server_id)
            .unwrap()
            .last_active_jobs
            .insert(job_id);
        let nonce = scheduler
            .servers
            .lock()
            .unwrap()
            .get(&server_id)
            .unwrap()
            .server_nonce
            .clone();

        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce,
                32,
                Box::new(TestJobAuthorizer),
                Vec::new(),
            )
            .expect("handle_heartbeat_server should not error");

        let servers = scheduler.servers.lock().unwrap();
        let details = servers.get(&server_id).expect("server still registered");
        assert!(
            !details.jobs_assigned.contains(&job_id),
            "a Started job past the completion timeout must be de-allocated from jobs_assigned"
        );
        let jobs = scheduler.jobs.lock().unwrap();
        assert!(
            !jobs.contains_key(&job_id),
            "the stale Started job must be removed from the jobs map"
        );
        assert_eq!(
            scheduler.jobs_reaped_started.load(Ordering::Relaxed),
            1,
            "reaping a stale Started job must increment the leak-detector counter"
        );
    }

    // Guard against over-reaping: a Started job within the timeout is a compile
    // in flight, so it must stay assigned and keep counting toward the server's
    // load.
    #[test]
    fn test_heartbeat_keeps_started_job_within_completion_timeout() {
        let scheduler = Scheduler::new();
        let server_id = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());
        let job_id = JobId(1000);
        insert_started_job(&scheduler, server_id, job_id, Duration::from_secs(0));
        let nonce = scheduler
            .servers
            .lock()
            .unwrap()
            .get(&server_id)
            .unwrap()
            .server_nonce
            .clone();

        // The server reports the job still running, so both the liveness path
        // (present in active_jobs) and the age-based backstop (within timeout)
        // must leave it assigned.
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce,
                32,
                Box::new(TestJobAuthorizer),
                vec![job_id],
            )
            .expect("handle_heartbeat_server should not error");

        let servers = scheduler.servers.lock().unwrap();
        let details = servers.get(&server_id).expect("server still registered");
        assert!(
            details.jobs_assigned.contains(&job_id),
            "a Started job within the completion timeout must stay assigned"
        );
    }

    // A late Complete (or Started) update for a job the scheduler no longer
    // tracks must be a no-op success, not an error. If it errors, the build
    // server's run_job (which propagates the terminal update) fails, and the
    // client discards the finished objects and recompiles locally - the
    // reap-then-complete hazard that a fixed-timeout reaper can trigger on a
    // slow-but-successful remote compile.
    #[test]
    fn test_late_update_for_reaped_job_is_ok() {
        let scheduler = Scheduler::new();
        let server_id = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());

        // No job was ever inserted, so job 1000 is "unknown" to the scheduler,
        // exactly as it would be after a reap.
        let res = scheduler.handle_update_job_state(JobId(1000), server_id, JobState::Complete);

        assert!(
            res.is_ok(),
            "a Complete update for an untracked (reaped) job must be a logged no-op success, not an error"
        );
    }

    // The unclaimed-reservation clock must be reset when a job becomes claimable
    // (Pending->Ready), so time spent uploading a toolchain does not eat the
    // claim budget and cause a no-show reap of a job that is still arriving.
    #[test]
    fn test_pending_to_ready_resets_unclaimed_clock() {
        let scheduler = Scheduler::new();
        let server_id = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());
        let job_id = JobId(1000);
        let old = Instant::now() - Duration::from_secs(120);
        {
            let mut servers = scheduler.servers.lock().unwrap();
            let mut jobs_unclaimed = HashMap::new();
            jobs_unclaimed.insert(job_id, old);
            let mut jobs_assigned = HashSet::new();
            jobs_assigned.insert(job_id);
            servers.insert(
                server_id,
                ServerDetails {
                    last_seen: Instant::now(),
                    last_error: None,
                    jobs_assigned,
                    jobs_unclaimed,
                    last_active_jobs: HashSet::new(),
                    num_cpus: 32,
                    server_nonce: ServerNonce::new(),
                    job_authorizer: Box::new(TestJobAuthorizer),
                },
            );
            let mut jobs = scheduler.jobs.lock().unwrap();
            jobs.insert(
                job_id,
                JobDetail {
                    server_id,
                    state: JobState::Pending,
                    since: old,
                },
            );
        }

        scheduler
            .handle_update_job_state(job_id, server_id, JobState::Ready)
            .expect("Pending->Ready update should succeed");

        let servers = scheduler.servers.lock().unwrap();
        let t = servers
            .get(&server_id)
            .unwrap()
            .jobs_unclaimed
            .get(&job_id)
            .copied()
            .expect("job must still be unclaimed after reaching Ready");
        assert!(
            t.elapsed() < Duration::from_secs(60),
            "the unclaimed clock must be reset to Ready time, not left at the ~120s-old allocation time"
        );
    }

    struct NoBuild;

    impl BuilderIncoming for NoBuild {
        fn run_build(
            &self,
            _tc: Toolchain,
            _command: CompileCommand,
            _outputs: Vec<String>,
            _inputs_rdr: InputsReader<'_>,
            _tccache: &Mutex<TcCache>,
        ) -> Result<dist::BuildResult> {
            unreachable!("assign tests never run a build");
        }
    }

    // A build server that outlives a scheduler restart can be handed a job id
    // it still holds a toolchain entry for; that must overwrite, not panic.
    #[test]
    fn test_assign_job_overwrites_stale_toolchain_entry() {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::new(Box::new(NoBuild), dir.path(), 1024).unwrap();
        let job_id = JobId(7);

        server.handle_assign_job(job_id, a_toolchain()).unwrap();
        server.handle_assign_job(job_id, a_toolchain()).unwrap();

        assert_eq!(server.job_toolchains.lock().unwrap().len(), 1);
    }

    // An assign whose run_job never arrives must not stay in the map forever.
    #[test]
    fn test_assign_job_collects_abandoned_toolchain_entries() {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::new(Box::new(NoBuild), dir.path(), 1024).unwrap();
        let stale = Instant::now() - (ABANDONED_TOOLCHAIN_TIMEOUT + Duration::from_secs(1));
        server
            .job_toolchains
            .lock()
            .unwrap()
            .insert(JobId(1), (a_toolchain(), stale));

        server.handle_assign_job(JobId(2), a_toolchain()).unwrap();

        let toolchains = server.job_toolchains.lock().unwrap();
        assert!(!toolchains.contains_key(&JobId(1)));
        assert!(toolchains.contains_key(&JobId(2)));
    }

    // The liveness lease is the primary Started-reap mechanism: a Started job is
    // reaped only after it is absent from two consecutive heartbeats of the
    // owning server. A job the server keeps reporting active is never reaped (no
    // matter how long the compile runs), and a single missed heartbeat is not
    // enough - guarding both the slow-live-compile false reap the old fixed
    // timeout caused and an over-eager one-beat reap. Job age is seeded past the
    // LIVENESS_GRACE floor (45s) but below the STARTED_COMPLETE_TIMEOUT backstop
    // (180s), so the backstop never fires and every reap decision here is the
    // liveness path.
    #[test]
    fn test_liveness_lease_reap() {
        let scheduler = Scheduler::new();
        let server_id = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());
        let job_id = JobId(1000);
        insert_started_job(&scheduler, server_id, job_id, Duration::from_secs(60));
        let nonce = scheduler
            .servers
            .lock()
            .unwrap()
            .get(&server_id)
            .unwrap()
            .server_nonce
            .clone();

        // Reported active across many heartbeats: never reaped.
        for _ in 0..5 {
            scheduler
                .handle_heartbeat_server(
                    server_id,
                    nonce.clone(),
                    32,
                    Box::new(TestJobAuthorizer),
                    vec![job_id],
                )
                .expect("handle_heartbeat_server should not error");
            let servers = scheduler.servers.lock().unwrap();
            assert!(
                servers
                    .get(&server_id)
                    .unwrap()
                    .jobs_assigned
                    .contains(&job_id),
                "a job reported active must never be reaped"
            );
        }

        // First absent heartbeat: one miss alone must not reap (needs two).
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                32,
                Box::new(TestJobAuthorizer),
                Vec::new(),
            )
            .expect("handle_heartbeat_server should not error");
        assert!(
            scheduler
                .servers
                .lock()
                .unwrap()
                .get(&server_id)
                .unwrap()
                .jobs_assigned
                .contains(&job_id),
            "a single absent heartbeat must not reap - the lease needs two consecutive misses"
        );

        // Second consecutive absent heartbeat: now the job is reaped.
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce,
                32,
                Box::new(TestJobAuthorizer),
                Vec::new(),
            )
            .expect("handle_heartbeat_server should not error");
        {
            let servers = scheduler.servers.lock().unwrap();
            let details = servers.get(&server_id).expect("server still registered");
            assert!(
                !details.jobs_assigned.contains(&job_id),
                "two consecutive absent heartbeats must reap the Started job"
            );
        }
        assert!(
            !scheduler.jobs.lock().unwrap().contains_key(&job_id),
            "the liveness-reaped job must be removed from the jobs map"
        );
        assert_eq!(
            scheduler.jobs_reaped_started.load(Ordering::Relaxed),
            1,
            "the liveness reap must increment the Started-reap counter exactly once"
        );
    }

    // The LIVENESS_GRACE floor protects a just-started job: a job that has been
    // Started for less than the grace must NOT be reaped even after two absent
    // heartbeats, because a job that transitioned to Started between two beats
    // is vacuously "absent from the prior beat" and would otherwise be reaped
    // milliseconds after it started. Falsifier: dropping the grace clause reaps
    // this job on the second absent heartbeat.
    #[test]
    fn test_liveness_lease_does_not_reap_within_grace() {
        let scheduler = Scheduler::new();
        let server_id = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());
        let job_id = JobId(1000);
        // Aged below LIVENESS_GRACE (45s): a fresh Started job.
        insert_started_job(&scheduler, server_id, job_id, Duration::from_secs(10));
        let nonce = scheduler
            .servers
            .lock()
            .unwrap()
            .get(&server_id)
            .unwrap()
            .server_nonce
            .clone();

        // Two consecutive absent heartbeats: the two-miss condition is met, but
        // the grace floor must still protect the just-started job.
        for _ in 0..2 {
            scheduler
                .handle_heartbeat_server(
                    server_id,
                    nonce.clone(),
                    32,
                    Box::new(TestJobAuthorizer),
                    Vec::new(),
                )
                .expect("handle_heartbeat_server should not error");
        }

        {
            let servers = scheduler.servers.lock().unwrap();
            let details = servers.get(&server_id).expect("server still registered");
            assert!(
                details.jobs_assigned.contains(&job_id),
                "a job Started within LIVENESS_GRACE must not be reaped even after two absent heartbeats"
            );
        }
        assert!(
            scheduler.jobs.lock().unwrap().contains_key(&job_id),
            "a job Started within the grace must remain in the jobs map"
        );
        assert_eq!(
            scheduler.jobs_reaped_started.load(Ordering::Relaxed),
            0,
            "no Started reap must occur within the grace floor"
        );
    }

    // The upload transfer in handle_submit_toolchain streams to a temp file
    // with the cache lock released; only the final graft reacquires the lock.
    // Drive that graft path directly: a materialized temp file inserts under
    // its toolchain key, and a file whose contents do not hash to the key is
    // refused rather than served as a corrupt entry.
    #[test]
    fn test_submit_toolchain_no_lock_across_transfer() {
        use sccache::util::Digest;
        use std::io::Write;

        let cache_dir = tempfile::TempDir::new().unwrap();
        let mut cache = TcCache::new(cache_dir.path(), u64::MAX).unwrap();

        // Materialize the upload exactly as the handler does after io::copy.
        let mut tmpfile = tempfile::NamedTempFile::new_in(cache.path()).unwrap();
        tmpfile.write_all(b"toolchain-bytes").unwrap();
        tmpfile.flush().unwrap();
        let archive_id = Digest::reader_sync(std::fs::File::open(tmpfile.path()).unwrap()).unwrap();
        let tc = Toolchain { archive_id };
        let temp_path = tmpfile.into_temp_path();

        assert!(!cache.contains_toolchain(&tc));
        cache.insert_at(&tc, &temp_path).unwrap();
        assert!(cache.contains_toolchain(&tc));

        // A temp file that does not hash to the requested key is refused.
        let mut bad = tempfile::NamedTempFile::new_in(cache.path()).unwrap();
        bad.write_all(b"not-the-right-bytes").unwrap();
        bad.flush().unwrap();
        let wrong_tc = Toolchain {
            archive_id: "deadbeefcafe".to_owned(),
        };
        let bad_path = bad.into_temp_path();
        assert!(cache.insert_at(&wrong_tc, &bad_path).is_err());
    }

    fn nonce_of(scheduler: &Scheduler, server_id: ServerId) -> ServerNonce {
        scheduler
            .servers
            .lock()
            .unwrap()
            .get(&server_id)
            .unwrap()
            .server_nonce
            .clone()
    }

    // The fixed-timeout backstop must not reap a job the server still names in its
    // heartbeats, however old: a genuinely slow compile has to survive. Dropping the
    // "reported active" guard would reap every long compile at the timeout.
    #[test]
    fn test_backstop_keeps_a_started_job_the_server_still_reports_active() {
        let scheduler = Scheduler::new();
        let server_id = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());
        let job_id = JobId(1000);
        insert_started_job(
            &scheduler,
            server_id,
            job_id,
            STARTED_COMPLETE_TIMEOUT + Duration::from_secs(10),
        );
        let nonce = nonce_of(&scheduler, server_id);

        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce,
                32,
                Box::new(TestJobAuthorizer),
                vec![job_id],
            )
            .unwrap();

        assert!(scheduler.jobs.lock().unwrap().contains_key(&job_id));
        assert!(
            scheduler
                .servers
                .lock()
                .unwrap()
                .get(&server_id)
                .unwrap()
                .jobs_assigned
                .contains(&job_id)
        );
        assert_eq!(0, scheduler.jobs_reaped_started.load(Ordering::Relaxed));
    }

    // A graceful deregister must drop the departing server's jobs from the
    // scheduler, or they count as in progress forever.
    #[test]
    fn test_deregister_drops_the_servers_jobs_and_counts_them() {
        let scheduler = Scheduler::new();
        let server_id = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());
        let job_id = JobId(1000);
        insert_started_job(&scheduler, server_id, job_id, Duration::from_secs(1));

        let res = scheduler.handle_deregister_server(server_id).unwrap();

        assert!(res.success);
        assert!(scheduler.servers.lock().unwrap().is_empty());
        assert!(scheduler.jobs.lock().unwrap().is_empty());
        assert_eq!(1, scheduler.jobs_pruned.load(Ordering::Relaxed));
    }

    #[test]
    fn test_deregister_of_an_unknown_server_is_a_successful_no_op() {
        let scheduler = Scheduler::new();
        let known = ServerId::new("10.42.0.2:10501".parse::<SocketAddr>().unwrap());
        insert_started_job(&scheduler, known, JobId(1000), Duration::from_secs(1));
        let unknown = ServerId::new("10.42.0.9:10501".parse::<SocketAddr>().unwrap());

        let res = scheduler.handle_deregister_server(unknown).unwrap();

        assert!(res.success);
        assert_eq!(1, scheduler.servers.lock().unwrap().len());
        assert_eq!(1, scheduler.jobs.lock().unwrap().len());
        assert_eq!(0, scheduler.jobs_pruned.load(Ordering::Relaxed));
    }

    // The status response carries one entry per server with its own core count and
    // assigned-job count, alongside the aggregates.
    #[test]
    fn test_status_reports_each_server_with_its_load() {
        let scheduler = Scheduler::new();
        insert_busy_server(&scheduler, "10.42.0.1:10501", 3, None);
        insert_busy_server(&scheduler, "10.42.0.2:10501", 0, None);

        let status = scheduler.handle_status().unwrap();

        assert_eq!(2, status.num_servers);
        assert_eq!(64, status.num_cpus);
        let mut servers = status.servers.clone();
        servers.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!("10.42.0.1:10501", servers[0].id);
        assert_eq!(32, servers[0].num_cpus);
        assert_eq!(3, servers[0].in_progress);
        assert_eq!("10.42.0.2:10501", servers[1].id);
        assert_eq!(0, servers[1].in_progress);
    }

    /// Blocks inside its first read until released, so an upload stays in flight.
    struct GatedReader {
        data: std::io::Cursor<Vec<u8>>,
        started: Option<std::sync::mpsc::Sender<()>>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl io::Read for GatedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(started) = self.started.take() {
                started.send(()).unwrap();
                self.release.recv().unwrap();
            }
            self.data.read(buf)
        }
    }

    /// Counts the bytes taken from it.
    struct CountingReader {
        data: std::io::Cursor<Vec<u8>>,
        read: Arc<AtomicUsize>,
    }

    impl io::Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.data.read(buf)?;
            self.read.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        }
    }

    // Two clients submitting the same uncached toolchain used to both stream it to
    // disk and both graft it into the cache: duplicate transfers, temp files outside
    // the cache's size bound, and a double-counted entry. The second submit has to
    // wait for the first and then find the toolchain cached without reading a byte.
    #[test]
    fn test_store_toolchain_is_single_flight_per_toolchain() {
        use sccache::util::Digest;

        let bytes = b"toolchain-bytes".to_vec();
        let archive_id = Digest::reader_sync(io::Cursor::new(bytes.clone())).unwrap();
        let tc = Toolchain { archive_id };
        let cache_dir = tempfile::TempDir::new().unwrap();
        let cache = Mutex::new(TcCache::new(cache_dir.path(), u64::MAX).unwrap());
        let locks = Mutex::new(HashMap::new());
        let second_read = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                let mut rdr = GatedReader {
                    data: io::Cursor::new(bytes.clone()),
                    started: Some(started_tx),
                    release: release_rx,
                };
                store_toolchain(&cache, &locks, &tc, &mut rdr)
            });
            started_rx.recv().unwrap();

            let second = scope.spawn(|| {
                let mut rdr = CountingReader {
                    data: io::Cursor::new(bytes.clone()),
                    read: second_read.clone(),
                };
                store_toolchain(&cache, &locks, &tc, &mut rdr)
            });
            // The first upload is still in flight; give the second time to start
            // transferring if nothing stops it. Release the first before asserting,
            // so a failure here fails the test instead of leaving the scope hung.
            std::thread::sleep(Duration::from_millis(300));
            let read_while_first_in_flight = second_read.load(Ordering::SeqCst);
            release_tx.send(()).unwrap();
            let first = first.join().unwrap();
            let second = second.join().unwrap();

            assert_eq!(
                0, read_while_first_in_flight,
                "the second submit of the same toolchain must wait for the first"
            );
            assert!(matches!(first, SubmitToolchainResult::Success));
            assert!(matches!(second, SubmitToolchainResult::Success));
        });

        assert_eq!(0, second_read.load(Ordering::SeqCst));
        assert!(cache.lock().unwrap().contains_toolchain(&tc));
        assert!(locks.lock().unwrap().is_empty());
    }
}
