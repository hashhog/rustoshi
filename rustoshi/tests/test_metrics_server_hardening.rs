//! Security audit C4 (`audits/security/rustoshi-2026-10-28.md`): the
//! Prometheus metrics listener bound `0.0.0.0` with no auth, no read timeout
//! and no connection cap, so idle sockets pinned one fd each until the process
//! hit EMFILE and RPC/REST stopped answering.
//!
//! Core has no unauthenticated listener and its HTTP server drops idle clients
//! after `-rpcservertimeout` (30 s). These tests drive the real binary on a
//! fresh regtest datadir and attack the metrics port from this process.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    child: Child,
    rpc_port: u16,
    metrics_port: u16,
    _tmp: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start rustoshi on regtest. `nofile` wraps the binary in `prlimit` so the
/// fd limit is small enough to exhaust from a test.
fn start_node(extra: &[String], nofile: Option<u32>) -> Node {
    let tmp = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let metrics_port = free_port();
    let mut cmd = match nofile {
        Some(n) => {
            let mut c = Command::new("prlimit");
            c.arg(format!("--nofile={n}:{n}"))
                .arg("--")
                .arg(env!("CARGO_BIN_EXE_rustoshi"));
            c
        }
        None => Command::new(env!("CARGO_BIN_EXE_rustoshi")),
    };
    cmd.arg("--network=regtest")
        .arg(format!("--datadir={}", tmp.path().join("node").display()))
        .arg(format!("--rpcbind=127.0.0.1:{rpc_port}"))
        .arg("--rpcuser=test")
        .arg("--rpcpassword=test")
        .arg(format!("--port={}", free_port()))
        .arg("--nodnsseed")
        .arg("--nofixedseeds")
        .arg("--maxconnections=0")
        .arg(format!("--metrics-port={metrics_port}"))
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn().expect("spawn rustoshi");
    let mut node = Node {
        child,
        rpc_port,
        metrics_port,
        _tmp: tmp,
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(s) = node.child.try_wait().unwrap() {
            panic!("rustoshi exited during startup: {s}");
        }
        if rpc_getblockcount(rpc_port, Duration::from_secs(2)).is_some()
            && listen_addr(node.child.id(), metrics_port).is_some()
        {
            return node;
        }
        assert!(Instant::now() < deadline, "rustoshi did not come up in 60s");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn rpc_getblockcount(port: u16, timeout: Duration) -> Option<u64> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut s = TcpStream::connect_timeout(&addr, timeout).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    let body = r#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}"#;
    // test:test
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    let i = resp.find("\"result\":")? + "\"result\":".len();
    let digits: String = resp[i..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Local address of the LISTEN socket on `port` in the process's network
/// namespace, from /proc/<pid>/net/tcp{,6}, as the hex `addr` field.
fn listen_addr(pid: u32, port: u16) -> Option<String> {
    let want_port = format!("{port:04X}");
    for f in ["tcp", "tcp6"] {
        let Ok(t) = std::fs::read_to_string(format!("/proc/{pid}/net/{f}")) else {
            continue;
        };
        for line in t.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // st == 0A is TCP_LISTEN
            if cols.len() > 3 && cols[3] == "0A" {
                if let Some((a, p)) = cols[1].split_once(':') {
                    if p == want_port {
                        return Some(a.to_string());
                    }
                }
            }
        }
    }
    None
}

fn open_fds(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|d| d.count())
        .unwrap_or(0)
}

#[test]
fn metrics_listener_binds_loopback_by_default() {
    let node = start_node(&[], None);
    let addr = listen_addr(node.child.id(), node.metrics_port).unwrap();
    assert_eq!(
        addr, "0100007F",
        "metrics port is listening on {addr} (0100007F is 127.0.0.1, 00000000 is 0.0.0.0)"
    );
}

#[test]
fn metrics_listener_honours_explicit_metricsbind() {
    let node = start_node(&["--metricsbind=0.0.0.0".to_string()], None);
    let addr = listen_addr(node.child.id(), node.metrics_port).unwrap();
    assert_eq!(addr, "00000000", "--metricsbind=0.0.0.0 must still be honoured");
}

#[test]
fn metrics_server_drops_idle_connection() {
    let node = start_node(&[], None);
    let mut s = TcpStream::connect(("127.0.0.1", node.metrics_port)).unwrap();
    // Send nothing. Core's HTTP server closes after -rpcservertimeout (30s).
    s.set_read_timeout(Some(Duration::from_secs(45))).unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 64];
    let r = s.read(&mut buf);
    let waited = start.elapsed();
    assert!(
        matches!(r, Ok(0)) || matches!(&r, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset),
        "idle metrics connection still open after {waited:?}: {r:?}"
    );
    // A normal request still works afterwards.
    let mut s = TcpStream::connect(("127.0.0.1", node.metrics_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "metrics response: {resp:?}");
    assert!(resp.contains("bitcoin_blocks_total"), "metrics response: {resp:?}");
}

#[test]
fn metrics_idle_flood_does_not_exhaust_fds_or_take_down_rpc() {
    // The audit's repro: a small fd limit, then more idle sockets than fds.
    const NOFILE: u32 = 1024;
    const FLOOD: usize = 1200;
    let node = start_node(&[], Some(NOFILE));
    // prlimit execs the node, so the child pid is the node.
    let pid = node.child.id();
    let fds_before = open_fds(pid);

    let addr: SocketAddr = format!("127.0.0.1:{}", node.metrics_port).parse().unwrap();
    let mut held = Vec::with_capacity(FLOOD);
    for _ in 0..FLOOD {
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            held.push(s);
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    let fds_during = open_fds(pid);
    let rpc = rpc_getblockcount(node.rpc_port, Duration::from_secs(10));
    drop(held);

    assert_eq!(
        rpc,
        Some(0),
        "RPC getblockcount failed while {FLOOD} idle metrics sockets were open \
         (fds {fds_before} -> {fds_during}, limit {NOFILE})"
    );
    assert!(
        fds_during < fds_before + 100,
        "idle metrics sockets pinned node fds: {fds_before} -> {fds_during} (limit {NOFILE})"
    );
}
