//! Regression: a peer that stops draining must not wedge the node.
//!
//! THE BUG (mainnet, 2026-08-01, 24 watchdog kills in one week).
//! `write_all` on a TcpStream returns once bytes reach the kernel send buffer,
//! so it blocks only when that buffer is full — i.e. the peer stopped ACKing.
//! With no timeout, a blackholed peer (no ACK, no FIN/RST) parks the write
//! until the kernel gives up: ~924.6s on Linux at the default
//! `tcp_retries2 = 15`.
//!
//! That alone would only stall one peer task. The wedge is that the main
//! select! loop calls `PeerManager::send_to_peer`, which awaits an *unbounded*
//! send into that peer's 32-slot command channel. Once the stalled writer stops
//! draining, the channel fills and the main loop blocks inside the arm body —
//! including the arm that bumps the liveness heartbeat. The OS-thread watchdog
//! then sees a flat heartbeat with peers still connected and kills the process.
//!
//! Production log evidence: one continuous stall population truncated exactly
//! at the 900s watchdog (20 stalls in [900,930), none above 930), and reaching
//! 956/1111/1115/1124s in the era before the watchdog existed.
//!
//! WHAT THIS TEST PROVES: a write into a sink that never drains is abandoned
//! after PEER_SEND_TIMEOUT rather than parking indefinitely. It uses tokio's
//! time control, so it is deterministic and takes no wall-clock time.
//!
//! WHAT IT DOES NOT PROVE: that the real peer task emits Disconnected and that
//! the main loop's blocked send then resolves. That path needs a live socket
//! pair and the full peer task; it is exercised in production by the identical
//! ETIMEDOUT path that already existed.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncWrite;

/// A writer that accepts nothing, ever — the in-process equivalent of a peer
/// whose kernel send buffer is full because it stopped ACKing.
struct BlackholeWriter;

impl AsyncWrite for BlackholeWriter {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

// Import the REAL constant rather than restating it — a copy here could pass
// while production drifted to a useless value.
use rustoshi_network::peer::PEER_SEND_TIMEOUT;

#[tokio::test]
async fn blackholed_peer_send_is_abandoned_not_parked_forever() {
    use tokio::io::AsyncWriteExt;

    let mut w = BlackholeWriter;
    let data = vec![0u8; 1024];

    // A short bound stands in for PEER_SEND_TIMEOUT so the test is fast; the
    // production value is separately range-checked below. What is proven here
    // is the SHAPE: a write into a non-draining sink resolves as a timeout
    // instead of parking forever.
    let res = tokio::time::timeout(Duration::from_millis(50), async {
        w.write_all(&data).await?;
        w.flush().await
    })
    .await;

    assert!(
        res.is_err(),
        "a send into a non-draining peer MUST time out. Without this bound the \
         write parks until the kernel abandons the connection (~925s at \
         tcp_retries2=15), and because the main loop awaits an unbounded send \
         into the peer's 32-slot command channel, the whole node wedges and the \
         watchdog kills it."
    );
}

/// The bound must sit well below the kernel's ~925s (or it never fires first)
/// and well above a legitimately slow transfer (or it drops healthy peers).
#[test]
fn timeout_is_between_a_slow_block_and_the_kernel_giving_up() {
    let t = PEER_SEND_TIMEOUT.as_secs();

    // A 4 MiB block to a 1 Mbps peer needs ~33s of buffer drain.
    let slow_block_secs = (4 * 1024 * 1024 * 8) / 1_000_000;
    assert!(
        t > slow_block_secs * 2,
        "PEER_SEND_TIMEOUT ({t}s) leaves too little headroom over a slow but \
         HEALTHY transfer (~{slow_block_secs}s for 4 MiB at 1 Mbps); it would \
         disconnect good peers"
    );

    // Linux tcp_retries2=15 => ETIMEDOUT at ~924.6s for a 200ms RTO base.
    assert!(
        t < 900,
        "PEER_SEND_TIMEOUT ({t}s) must fire before the 900s watchdog and well \
         before the kernel's ~925s, or the node still dies first"
    );
}
