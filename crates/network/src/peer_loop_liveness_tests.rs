//! Liveness tests for the post-handshake peer message loops
//! (`run_message_loop_tracked` / `run_message_loop_v2_tracked`).
//!
//! The 2026-09-26 mainnet stall: rustoshi sat one block behind Core for
//! 12+ minutes with every thread parked, and the P2P watchdog had been
//! exit(1)-restarting it every one to two hours. The main event loop is the
//! only consumer of the shared 1024-slot `PeerEvent` channel, and it pushes
//! outgoing messages into each peer's bounded command channel with a blocking
//! `send().await`. A peer task, in turn, blocked on `event_tx.send().await`
//! while holding its command receiver and not draining it. Once the event
//! channel filled (main loop lagging) and one peer's command channel filled
//! (main loop sending to that peer), each side waited on the other forever:
//!
//!   main loop  --send_to_peer(X).await-->  X.command_rx (full, not drained)
//!   peer X     --event_tx.send().await-->  event_rx     (full, not drained)
//!
//! These tests hold the event channel full on purpose and assert that the
//! peer task keeps accepting commands, so the main loop can never block on a
//! peer that is itself waiting for the main loop.
//!
//! A second, independent defect lives in the v2 loop: `v2_recv_message`
//! was dropped by `select!` whenever a command arrived mid-packet. The bytes
//! it had already consumed (and the length-cipher step it had already taken)
//! went with it, so the next read took the middle of the packet as a length —
//! "v2 packet too large: <random>" — and the peer was dropped. On mainnet
//! that is 1,616 disconnects in the log for 2026-09-23..26; any block the
//! peer was delivering at the time was abandoned with it.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::message::{serialize_message, InvType, InvVector, NetworkMessage};
use crate::peer::{
    read_message, run_message_loop_tracked, run_message_loop_v2_tracked, v2_recv_message,
    v2_send_message, DisconnectReason, PeerCommand, PeerEvent, PeerId, PeerStats,
};
use crate::v2_transport::Bip324Cipher;
use rustoshi_primitives::Hash256;

const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

/// Per-send ceiling. A healthy peer task accepts a command within
/// microseconds; the deadlock never accepts it at all.
const SEND_DEADLINE: Duration = Duration::from_secs(3);

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (client.unwrap(), server.unwrap().0)
}

fn split_buffered(s: TcpStream) -> (BufReader<OwnedReadHalf>, BufWriter<OwnedWriteHalf>) {
    let (r, w) = s.into_split();
    (BufReader::new(r), BufWriter::new(w))
}

/// An event channel that is already full and that nobody reads — the state
/// the main loop's backlog leaves it in. The returned receiver must be kept
/// alive (dropping it would make sends fail fast instead of blocking).
fn full_event_channel() -> (mpsc::Sender<PeerEvent>, mpsc::Receiver<PeerEvent>) {
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(PeerEvent::Disconnected(
        PeerId(999),
        DisconnectReason::Timeout,
    ))
    .unwrap();
    (tx, rx)
}

fn getdata(n: u8) -> NetworkMessage {
    NetworkMessage::GetData(vec![InvVector {
        inv_type: InvType::MsgWitnessBlock,
        hash: Hash256([n; 32]),
    }])
}

/// Send `count` commands, each bounded by SEND_DEADLINE. Returns how many
/// were accepted before a send blocked past the deadline (== the deadlock).
async fn send_commands(cmd_tx: &mpsc::Sender<PeerCommand>, count: u8) -> u8 {
    for i in 0..count {
        let r = tokio::time::timeout(
            SEND_DEADLINE,
            cmd_tx.send(PeerCommand::SendMessage(getdata(i))),
        )
        .await;
        match r {
            Ok(_) => {}
            Err(_) => return i,
        }
    }
    count
}

/// v1: with the event channel full and one undelivered inbound message in
/// hand, the peer task must keep draining its command channel onto the wire.
#[tokio::test]
async fn v1_loop_keeps_draining_commands_while_event_channel_full() {
    let (ours, theirs) = tcp_pair().await;
    let (reader, writer) = split_buffered(ours);
    let (mut their_r, mut their_w) = split_buffered(theirs);

    let (event_tx, _event_rx) = full_event_channel();
    let (cmd_tx, cmd_rx) = mpsc::channel(2);
    let task = tokio::spawn(async move {
        run_message_loop_tracked(
            PeerId(1),
            &MAGIC,
            reader,
            writer,
            event_tx,
            cmd_rx,
            Arc::new(PeerStats::new()),
        )
        .await
    });

    // The remote sends one message; the task reads it and cannot deliver it.
    their_w
        .write_all(&serialize_message(&MAGIC, &NetworkMessage::SendHeaders))
        .await
        .unwrap();
    their_w.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    const N: u8 = 20;
    let accepted = send_commands(&cmd_tx, N).await;
    assert_eq!(
        accepted, N,
        "main-loop send blocked after {accepted} commands: the peer task stopped draining \
         its command channel while waiting on the full event channel (the 2026-09-26 deadlock)"
    );

    // And they really went out on the wire, in order.
    for i in 0..N {
        let got = tokio::time::timeout(SEND_DEADLINE, read_message(&mut their_r, &MAGIC))
            .await
            .expect("remote read timed out")
            .unwrap();
        assert_eq!(got.serialize_payload(), getdata(i).serialize_payload());
    }
    task.abort();
}

/// v2 twin of the test above.
#[tokio::test]
async fn v2_loop_keeps_draining_commands_while_event_channel_full() {
    let (ours, theirs) = tcp_pair().await;
    let (reader, writer) = split_buffered(ours);
    let (mut their_r, mut their_w) = split_buffered(theirs);
    let (mut remote, local) = Bip324Cipher::pair_for_test();

    let (event_tx, _event_rx) = full_event_channel();
    let (cmd_tx, cmd_rx) = mpsc::channel(2);
    let task = tokio::spawn(async move {
        run_message_loop_v2_tracked(
            PeerId(1),
            &MAGIC,
            local,
            reader,
            writer,
            event_tx,
            cmd_rx,
            Arc::new(PeerStats::new()),
        )
        .await
    });

    v2_send_message(&mut remote, &mut their_w, &NetworkMessage::SendHeaders)
        .await
        .unwrap();
    their_w.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    const N: u8 = 20;
    let accepted = send_commands(&cmd_tx, N).await;
    assert_eq!(
        accepted, N,
        "main-loop send blocked after {accepted} commands: the v2 peer task stopped draining \
         its command channel while waiting on the full event channel"
    );
    for i in 0..N {
        let got = tokio::time::timeout(SEND_DEADLINE, v2_recv_message(&mut remote, &mut their_r))
            .await
            .expect("remote read timed out")
            .unwrap();
        assert_eq!(got.serialize_payload(), getdata(i).serialize_payload());
    }
    task.abort();
}

/// Exit path: the connection dies while the event channel is full. The task
/// cannot hand over its Disconnected event yet, but it must not keep a live
/// command receiver while it waits — otherwise the main loop, which still
/// thinks the peer is connected, blocks sending to it. Every send must
/// resolve promptly (and once the receiver is gone, fail as "closed", which
/// is what `send_to_peer`'s callers use to requeue in-flight blocks).
#[tokio::test]
async fn v1_loop_releases_command_channel_before_blocking_on_final_event() {
    let (ours, theirs) = tcp_pair().await;
    let (reader, writer) = split_buffered(ours);

    let (event_tx, mut event_rx) = full_event_channel();
    let (cmd_tx, cmd_rx) = mpsc::channel(2);
    let task = tokio::spawn(async move {
        run_message_loop_tracked(
            PeerId(1),
            &MAGIC,
            reader,
            writer,
            event_tx,
            cmd_rx,
            Arc::new(PeerStats::new()),
        )
        .await
    });

    // Remote hangs up; the task reads EOF and wants to report it.
    drop(theirs);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut closed = false;
    for i in 0..20u8 {
        match tokio::time::timeout(
            SEND_DEADLINE,
            cmd_tx.send(PeerCommand::SendMessage(getdata(i))),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                closed = true;
                break;
            }
            Err(_) => panic!(
                "main-loop send #{i} blocked: the exiting peer task held its command \
                 receiver while waiting to deliver Disconnected into a full event channel"
            ),
        }
    }
    assert!(
        closed,
        "command channel never reported closed after the peer died"
    );

    // Once the main loop drains, the Disconnected event is still delivered.
    let _prefill = event_rx.recv().await.unwrap();
    let ev = tokio::time::timeout(SEND_DEADLINE, event_rx.recv())
        .await
        .expect("Disconnected never delivered")
        .unwrap();
    assert!(
        matches!(ev, PeerEvent::Disconnected(PeerId(1), _)),
        "expected Disconnected, got {ev:?}"
    );
    let _ = task.await;
}

/// v2 read cancellation: a command arriving while an inbound packet is
/// half-read must not corrupt the stream. The remote writes the first half
/// of one encrypted packet, we issue a command (so `select!` takes the
/// command arm), then the remote writes the rest. The message must arrive
/// intact and the peer must stay connected.
#[tokio::test]
async fn v2_loop_command_mid_packet_does_not_desync_stream() {
    let (ours, theirs) = tcp_pair().await;
    let (reader, writer) = split_buffered(ours);
    let (mut their_r, mut their_w) = split_buffered(theirs);
    let (mut remote, local) = Bip324Cipher::pair_for_test();

    let (event_tx, mut event_rx) = mpsc::channel(64);
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let task = tokio::spawn(async move {
        run_message_loop_v2_tracked(
            PeerId(1),
            &MAGIC,
            local,
            reader,
            writer,
            event_tx,
            cmd_rx,
            Arc::new(PeerStats::new()),
        )
        .await
    });

    // A ~64 KB message so a partial write is genuinely mid-packet.
    let big = NetworkMessage::GetData(
        (0..2000u32)
            .map(|i| InvVector {
                inv_type: InvType::MsgWitnessBlock,
                hash: Hash256([(i % 251) as u8; 32]),
            })
            .collect(),
    );
    let mut frame: Vec<u8> = Vec::new();
    v2_send_message(&mut remote, &mut frame, &big)
        .await
        .unwrap();
    let cut = frame.len() / 2;

    // First half: 3-byte length + part of the AEAD body.
    their_w.write_all(&frame[..cut]).await.unwrap();
    their_w.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Command lands while the packet is half-read.
    cmd_tx
        .send(PeerCommand::SendMessage(getdata(7)))
        .await
        .unwrap();
    let echoed = tokio::time::timeout(SEND_DEADLINE, v2_recv_message(&mut remote, &mut their_r))
        .await
        .expect("command never reached the wire")
        .unwrap();
    assert_eq!(echoed.serialize_payload(), getdata(7).serialize_payload());

    // Rest of the packet.
    their_w.write_all(&frame[cut..]).await.unwrap();
    their_w.flush().await.unwrap();

    let ev = tokio::time::timeout(SEND_DEADLINE, event_rx.recv())
        .await
        .expect("no event after the packet completed")
        .unwrap();
    match ev {
        PeerEvent::Message(PeerId(1), msg) => {
            assert_eq!(msg.serialize_payload(), big.serialize_payload());
        }
        other => panic!(
            "expected the intact getdata, got {other:?} — the half-read packet was dropped \
             by select! cancellation and the stream desynchronised"
        ),
    }
    task.abort();
}
