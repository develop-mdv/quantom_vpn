//! Transparent TLS proxy fallback for REALITY.
//!
//! When `handshake::server_handshake` returns `HandshakeOutcome::Foreign` we
//! land here. The captured ClientHello record bytes are replayed verbatim to
//! the configured upstream destination (e.g. `gosuslugi.ru:443`) and then we
//! splice the two TCP halves together with `tokio::io::copy_bidirectional`.
//!
//! From a DPI vantage point this is indistinguishable from a normal TLS 1.3
//! session to the real upstream site: we never touched the bytes between
//! the active client and the real server.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn splice_to_upstream(
    mut client: TcpStream,
    dest_host: &str,
    dest_port: u16,
    captured_chlo_record: Vec<u8>,
) -> Result<()> {
    let target = format!("{dest_host}:{dest_port}");
    let mut upstream = timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(&target))
        .await
        .map_err(|_| anyhow!("REALITY proxy: connect to {target} timed out"))?
        .with_context(|| format!("REALITY proxy: tcp connect to {target}"))?;

    // Replay the original CHLO record verbatim — the upstream sees exactly
    // the same handshake start it would have seen if the client had reached
    // it directly.
    upstream
        .write_all(&captured_chlo_record)
        .await
        .with_context(|| format!("REALITY proxy: replay CHLO to {target}"))?;

    // From now on, we are just a TCP pipe in both directions.
    let (from_client_to_upstream, from_upstream_to_client) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .with_context(|| format!("REALITY proxy: bidirectional copy with {target}"))?;
    crate::metrics::record_reality_proxy_bytes(
        "client_to_upstream",
        from_client_to_upstream + captured_chlo_record.len() as u64,
    );
    crate::metrics::record_reality_proxy_bytes("upstream_to_client", from_upstream_to_client);
    Ok(())
}
