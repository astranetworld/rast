// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block bodies between members over plain TCP.
//!
//! The libp2p push hands a 19 MB body to each member over a Noise-encrypted
//! yamux stream, written and read from the swarm, which this fleet polls on
//! its consensus loop. Measured at the 163,000-transaction tier as 250-300 ms
//! from the leader finishing the body to a member holding it -- about
//! 50 MB/s across loopback, three orders of magnitude under the wire.
//!
//! This is the same bytes over a socket of their own: one persistent
//! connection per peer, a length-prefixed frame per body, written by a task
//! per peer and read by a task per connection, so neither end's consensus
//! loop touches the transfer. A body is self-authenticating -- the receiver
//! decodes it and files it under the hash of the header it decodes to, as it
//! does for a pushed or gossiped one -- so the channel carries nothing a
//! peer could not already send, and needs no handshake. It is for a static
//! fleet on one host or one LAN; a member it cannot reach still gets the
//! libp2p push.
//!
//! ```text
//! frame := u32 len (little-endian), len bytes of gov5 block RLP
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// How many received buffers the listener keeps for reuse. A body is 13-15
/// MB at the bench tier; a fresh `Vec` per block meant the kernel zeroed and
/// mapped ~3,800 pages for every block on every follower, and those first
/// touches were most of the runtime threads' page faults in round gate5.
const POOLED_BUFFERS: usize = 8;

/// Buffers handed out by [`listen`] and returned when a [`BodyBuf`] drops.
#[derive(Debug, Default)]
pub struct BufPool {
    free: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl BufPool {
    fn take(&self) -> Vec<u8> {
        self.free.lock().unwrap_or_else(|p| p.into_inner()).pop().unwrap_or_default()
    }

    fn give(&self, mut buf: Vec<u8>) {
        buf.clear();
        let mut free = self.free.lock().unwrap_or_else(|p| p.into_inner());
        if free.len() < POOLED_BUFFERS {
            free.push(buf);
        }
    }
}

/// A block body's bytes. From the channel they sit in a pooled buffer that
/// goes back to the pool when this drops; from anywhere else they are a
/// plain `Vec`. Dereferences to the bytes.
#[derive(Debug)]
pub struct BodyBuf {
    buf: Vec<u8>,
    pool: Option<Arc<BufPool>>,
}

impl BodyBuf {
    /// The bytes as an owned `Vec`, copied.
    pub fn to_vec(&self) -> Vec<u8> {
        self.buf.clone()
    }
}

impl std::ops::Deref for BodyBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl From<Vec<u8>> for BodyBuf {
    fn from(buf: Vec<u8>) -> Self {
        Self { buf, pool: None }
    }
}

impl Drop for BodyBuf {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.give(std::mem::take(&mut self.buf));
        }
    }
}

/// Largest body accepted, so a stray connection cannot make this node
/// allocate without bound.
const MAX_BODY_BYTES: u32 = 256 << 20;

/// Frames a peer may have queued before the leader stops offering it more.
const PER_PEER_QUEUE: usize = 4;

/// Listens on `addr` and hands every body received to `sink`.
///
/// Returns once bound; the accept loop runs on its own task. A body is
/// delivered as the bytes that arrived, for the same decode a pushed body
/// gets.
pub async fn listen(addr: SocketAddr, sink: mpsc::Sender<BodyBuf>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(target: "n42.h2.node", %addr, "body channel listening");
    let pool = Arc::new(BufPool::default());
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    warn!(target: "n42.h2.node", %err, "body channel accept failed");
                    continue;
                }
            };
            let sink = sink.clone();
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                if let Err(err) = receive(stream, sink, pool).await {
                    debug!(target: "n42.h2.node", %peer, %err, "body channel connection ended");
                }
            });
        }
    });
    Ok(())
}

async fn receive(mut stream: TcpStream, sink: mpsc::Sender<BodyBuf>, pool: Arc<BufPool>) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    loop {
        let len = match stream.read_u32_le().await {
            Ok(len) => len,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        if len == 0 || len > MAX_BODY_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("body of {len} bytes")));
        }
        let mut body = pool.take();
        body.resize(len as usize, 0);
        stream.read_exact(&mut body).await?;
        let body = BodyBuf { buf: body, pool: Some(Arc::clone(&pool)) };
        if sink.send(body).await.is_err() {
            return Ok(());
        }
    }
}

/// The leader's side: one queue per peer, drained to that peer's socket by
/// its own task.
#[derive(Debug, Clone)]
pub struct BodyPushers {
    peers: Vec<(SocketAddr, mpsc::Sender<Arc<Vec<u8>>>)>,
}

impl BodyPushers {
    /// A pusher per address. Connections are made lazily and remade after
    /// any error, so a member that is down or not yet up costs nothing but
    /// the frames it missed.
    pub fn connect(addrs: Vec<SocketAddr>) -> Self {
        let peers = addrs
            .into_iter()
            .map(|addr| {
                let (tx, rx) = mpsc::channel(PER_PEER_QUEUE);
                tokio::spawn(push_loop(addr, rx));
                (addr, tx)
            })
            .collect();
        Self { peers }
    }

    /// How many peers this pushes to.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether there are no peers.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Offers `body` to every peer's queue without waiting. Returns how many
    /// queues took it; a full queue means that peer is behind and gets the
    /// libp2p push instead.
    pub fn push(&self, body: Arc<Vec<u8>>) -> usize {
        self.peers.iter().filter(|(_, tx)| tx.try_send(Arc::clone(&body)).is_ok()).count()
    }
}

async fn push_loop(addr: SocketAddr, mut rx: mpsc::Receiver<Arc<Vec<u8>>>) {
    let mut stream: Option<TcpStream> = None;
    while let Some(body) = rx.recv().await {
        if stream.is_none() {
            match tokio::time::timeout(std::time::Duration::from_secs(1), TcpStream::connect(addr)).await {
                Ok(Ok(connected)) => {
                    let _ = connected.set_nodelay(true);
                    stream = Some(connected);
                }
                Ok(Err(err)) => {
                    debug!(target: "n42.h2.node", %addr, %err, "body channel: cannot connect; body not sent this way");
                    continue;
                }
                Err(_) => {
                    debug!(target: "n42.h2.node", %addr, "body channel: connect timed out; body not sent this way");
                    continue;
                }
            }
        }
        let sock = stream.as_mut().expect("connected above");
        let started = std::time::Instant::now();
        let result = async {
            sock.write_u32_le(body.len() as u32).await?;
            sock.write_all(&body).await?;
            sock.flush().await
        }
        .await;
        match result {
            Ok(()) => {
                if body.len() > 1_000_000 {
                    debug!(target: "n42.h2.node", %addr, bytes = body.len(), ms = started.elapsed().as_millis() as u64, "body sent over the channel");
                }
            }
            Err(err) => {
                debug!(target: "n42.h2.node", %addr, %err, "body channel write failed; reconnecting next time");
                stream = None;
            }
        }
    }
}

/// The body-channel address that goes with a libp2p `/ip4/<a>/tcp/<p>`
/// multiaddr: the same host, the port plus `offset`.
pub fn address_for(multiaddr: &str, offset: u16) -> Option<SocketAddr> {
    let mut parts = multiaddr.trim_start_matches('/').split('/');
    let (mut ip, mut port) = (None, None);
    while let Some(key) = parts.next() {
        let value = parts.next()?;
        match key {
            "ip4" | "ip6" => ip = value.parse::<std::net::IpAddr>().ok(),
            "tcp" => port = value.parse::<u16>().ok(),
            _ => {}
        }
    }
    Some(SocketAddr::new(ip?, port?.checked_add(offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_channel_address_follows_the_libp2p_one() {
        assert_eq!(
            address_for("/ip4/127.0.0.1/tcp/19003/p2p/12D3KooWabc", 1000),
            Some("127.0.0.1:20003".parse().unwrap())
        );
        assert_eq!(address_for("/ip4/127.0.0.1/tcp/19003", 0), Some("127.0.0.1:19003".parse().unwrap()));
        assert_eq!(address_for("/dns4/x/tcp/1", 1), None);
    }

    /// A body offered to the pushers arrives at the listener, whole and once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_body_crosses_the_channel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (tx, mut rx) = mpsc::channel(4);
        listen(addr, tx).await.unwrap();
        let pushers = BodyPushers::connect(vec![addr]);
        let body: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(pushers.push(Arc::new(body.clone())), 1);
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert_eq!(&got[..], &body[..]);
        assert_eq!(pushers.push(Arc::new(vec![7u8; 10])), 1);
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert_eq!(&got[..], &[7u8; 10][..]);
    }
}
