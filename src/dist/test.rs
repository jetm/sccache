use crate::dist::{ProcessOutput, SchedulerStatusResult, ServerStatusResult, Toolchain};
use crate::util::Digest;

fn roundtrip(archive_id: &str) -> bincode::Result<Toolchain> {
    let tc = Toolchain {
        archive_id: archive_id.to_owned(),
    };
    bincode::deserialize(&bincode::serialize(&tc).unwrap())
}

#[test]
fn test_toolchain_archive_id_digest_accepted() {
    let archive_id = Digest::reader_sync(&b"toolchain archive"[..]).unwrap();
    assert_eq!(roundtrip(&archive_id).unwrap().archive_id, archive_id);
    assert_eq!(
        roundtrip(&archive_id.to_uppercase()).unwrap().archive_id,
        archive_id
    );
}

#[test]
fn test_toolchain_archive_id_non_digest_rejected() {
    let digest = Digest::reader_sync(&b"toolchain archive"[..]).unwrap();
    for archive_id in [
        "",
        "a",
        "/tmp/toolchain",
        "../toolchain",
        &digest[1..],
        &format!("{digest}0"),
        &format!("/{}", &digest[1..]),
    ] {
        assert!(roundtrip(archive_id).is_err(), "accepted {archive_id:?}");
    }
}

#[test]
fn test_process_output_exit_code_is_kept() {
    let output: std::process::Output =
        ProcessOutput::fake_output(1, b"out".to_vec(), b"err".to_vec()).into();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(output.status.signal(), None);
    }
}

// A remote compile that fails with an exit code reached the client as "killed by signal <code>".
#[cfg(unix)]
#[test]
fn test_process_output_roundtrip_is_not_a_signal() {
    use std::os::unix::process::ExitStatusExt;
    for code in [0, 1, 2, 127] {
        let compiled = std::process::Output {
            status: crate::util::exit_status_from_code(code),
            stdout: vec![],
            stderr: vec![],
        };
        let received: std::process::Output = ProcessOutput::try_from(compiled).unwrap().into();
        assert_eq!(received.status.code(), Some(code), "exit code {code}");
        assert_eq!(received.status.signal(), None, "exit code {code}");
    }
}

/// A stock scheduler sends only the three aggregate counts, positionally. A client
/// that insisted on the per-server list would fail to decode that and never
/// distribute against it, so the missing list decodes as empty.
#[test]
fn scheduler_status_decodes_a_stock_schedulers_aggregate_only_payload() {
    let stock = bincode::serialize(&(2usize, 64usize, 3usize)).unwrap();

    let status = SchedulerStatusResult::from_bincode(&stock).unwrap();

    assert_eq!(status.num_servers, 2);
    assert_eq!(status.num_cpus, 64);
    assert_eq!(status.in_progress, 3);
    assert!(status.servers.is_empty());
}

#[test]
fn scheduler_status_decodes_the_per_server_payload_in_full() {
    let sent = SchedulerStatusResult {
        num_servers: 1,
        num_cpus: 32,
        in_progress: 1,
        servers: vec![ServerStatusResult {
            id: "10.42.0.1:10501".to_string(),
            num_cpus: 32,
            in_progress: 1,
        }],
    };
    let bytes = bincode::serialize(&sent).unwrap();

    let status = SchedulerStatusResult::from_bincode(&bytes).unwrap();

    assert_eq!(status.servers.len(), 1);
    assert_eq!(status.servers[0].id, "10.42.0.1:10501");
}

/// The status route needs no credentials, and the per-server list names every
/// build server's address, so an unauthenticated caller gets the aggregate counts
/// only.
#[test]
fn scheduler_status_without_server_list_keeps_only_the_aggregate_counts() {
    let full = SchedulerStatusResult {
        num_servers: 1,
        num_cpus: 32,
        in_progress: 1,
        servers: vec![ServerStatusResult {
            id: "10.42.0.1:10501".to_string(),
            num_cpus: 32,
            in_progress: 1,
        }],
    };

    let redacted = full.without_server_list();

    assert_eq!(redacted.num_servers, 1);
    assert_eq!(redacted.num_cpus, 32);
    assert_eq!(redacted.in_progress, 1);
    assert!(redacted.servers.is_empty());
}

#[test]
fn scheduler_status_rejects_a_truncated_payload() {
    let truncated = bincode::serialize(&(2usize, 64usize)).unwrap();

    assert!(SchedulerStatusResult::from_bincode(&truncated).is_err());
}

/// The JSON shape emitted by `sccache --dist-status` is a contract consumed by
/// the bakar cluster-info preflight (`_parse_cluster_status`): a top-level
/// `servers` array of `{id, num_cpus, in_progress}` objects alongside the
/// aggregate counts.
#[test]
fn scheduler_status_serializes_per_server_breakdown() {
    let status = SchedulerStatusResult {
        num_servers: 2,
        num_cpus: 64,
        in_progress: 3,
        servers: vec![
            ServerStatusResult {
                id: "10.42.0.1:10501".to_string(),
                num_cpus: 32,
                in_progress: 2,
            },
            ServerStatusResult {
                id: "10.42.0.2:10501".to_string(),
                num_cpus: 32,
                in_progress: 1,
            },
        ],
    };

    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json["num_servers"], 2);
    assert_eq!(json["num_cpus"], 64);
    assert_eq!(json["in_progress"], 3);
    let servers = json["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0]["id"], "10.42.0.1:10501");
    assert_eq!(servers[0]["num_cpus"], 32);
    assert_eq!(servers[0]["in_progress"], 2);
    assert_eq!(servers[1]["id"], "10.42.0.2:10501");
    assert_eq!(servers[1]["in_progress"], 1);

    // The aggregate in_progress is independent of the per-server sum: a job
    // can be queued at the scheduler before assignment to any server.
    let round: SchedulerStatusResult = serde_json::from_value(json).unwrap();
    assert_eq!(round.servers.len(), 2);
    assert_eq!(round.servers[0].id, "10.42.0.1:10501");
}
