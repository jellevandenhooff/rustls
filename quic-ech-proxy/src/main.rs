//! QUIC ECH split-mode proxy demo.
//!
//! Listens on a frontend UDP port, decrypts ECH from client Initial packets,
//! and forwards the inner ClientHello to a backend server. All non-Initial
//! packets and backend responses are forwarded unchanged.
//!
//! Each client gets a dedicated backend socket (unique ephemeral port), so
//! return traffic is naturally demuxed without parsing response packets.
//! Client state is cleaned up after an idle timeout (default 30s).
//!
//! Usage:
//!   cargo run -p quic-ech-proxy -- --port 4433 --backend 127.0.0.1:4434
//!
//! The proxy writes `ech-config.bin` for clients to use.

mod quic_packet;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use pki_types::DnsName;
use rustls::server::{EchProxy, EchProxyResult, EchServerKey, generate_ech_config};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use quic_packet::{CryptoAssembler, DecryptedInitial, InitialHeader};

/// How long a client can be idle before its state is cleaned up.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often to sweep for idle clients.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(about = "QUIC ECH split-mode proxy")]
struct Args {
    /// Frontend UDP port to listen on.
    #[arg(long, default_value = "4433")]
    port: u16,

    /// Backend server address (host:port).
    #[arg(long, default_value = "127.0.0.1:4434")]
    backend: SocketAddr,

    /// Public name for the ECH config (outer SNI).
    #[arg(long, default_value = "public.example.com")]
    public_name: String,

    /// Path to write the ECH config binary.
    #[arg(long, default_value = "ech-config.bin")]
    ech_config_path: String,

    /// Idle timeout in seconds before cleaning up client state.
    #[arg(long, default_value = "30")]
    idle_timeout: u64,
}

/// Per-client proxy state.
struct ClientState {
    ech_proxy: EchProxy,
    assembler: CryptoAssembler,
    /// Saved header from first Initial (for re-encryption).
    initial_header: Option<InitialHeader>,
    /// Dedicated socket for this client's traffic to/from backend.
    /// Each client gets a unique ephemeral source port so backend
    /// responses are naturally routed back to the right client.
    backend_socket: Arc<UdpSocket>,
    /// Last time we saw activity (client or backend packet) for this client.
    last_active: Instant,
    /// Handle to the relay task so we can abort it on cleanup.
    relay_task: tokio::task::JoinHandle<()>,
}

/// Message from a backend relay task back to the main loop.
struct BackendResponse {
    client_addr: SocketAddr,
    data: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let idle_timeout = Duration::from_secs(args.idle_timeout);

    // Generate ECH config + key
    let public_name = DnsName::try_from(args.public_name.clone())
        .map_err(|e| anyhow::anyhow!("invalid public name: {e}"))?
        .to_owned();
    let (ech_key, ech_config_bytes) = generate_ech_config(
        rustls_aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128,
        42, // config_id
        public_name,
        0, // maximum_name_length (0 = let server decide)
    )
    .context("generating ECH config")?;

    // Write ECH config for clients
    std::fs::write(&args.ech_config_path, &ech_config_bytes).context("writing ECH config")?;
    log::info!(
        "wrote ECH config to {} ({} bytes)",
        args.ech_config_path,
        ech_config_bytes.len()
    );

    let ech_keys: Arc<[EchServerKey]> = Arc::from(vec![ech_key]);

    // Bind frontend socket
    let frontend = Arc::new(
        UdpSocket::bind(("0.0.0.0", args.port))
            .await
            .context("binding frontend socket")?,
    );
    log::info!("QUIC ECH proxy listening on :{}", args.port);
    log::info!("forwarding to backend {}", args.backend);

    // Channel for backend relay tasks to send responses back to the main loop.
    let (response_tx, mut response_rx) = mpsc::channel::<BackendResponse>(256);

    let mut buf = [0u8; 65535];
    let mut clients: HashMap<SocketAddr, ClientState> = HashMap::new();
    let mut sweep_interval = tokio::time::interval(SWEEP_INTERVAL);

    loop {
        tokio::select! {
            // Frontend: receive from clients
            result = frontend.recv_from(&mut buf) => {
                let (len, client_addr) = result?;
                let packet = &buf[..len];

                let state = if let Some(state) = clients.get_mut(&client_addr) {
                    state.last_active = Instant::now();
                    state
                } else {
                    // New client: create dedicated backend socket + relay task
                    let backend_socket = Arc::new(
                        UdpSocket::bind("0.0.0.0:0").await
                            .context("binding backend socket")?
                    );
                    backend_socket.connect(args.backend).await
                        .context("connecting backend socket")?;

                    let local_port = backend_socket.local_addr()?.port();
                    log::info!(
                        "new client {client_addr} → backend via :{local_port}"
                    );

                    // Spawn relay task: backend → frontend (for this client)
                    let relay_task = spawn_backend_relay(
                        client_addr,
                        backend_socket.clone(),
                        response_tx.clone(),
                    );

                    clients.entry(client_addr).or_insert(ClientState {
                        ech_proxy: EchProxy::new(ech_keys.clone()),
                        assembler: CryptoAssembler::new(),
                        initial_header: None,
                        backend_socket,
                        last_active: Instant::now(),
                        relay_task,
                    })
                };

                handle_client_packet(state, client_addr, packet).await?;
            }

            // Backend responses relayed back to clients
            Some(response) = response_rx.recv() => {
                if let Some(state) = clients.get_mut(&response.client_addr) {
                    state.last_active = Instant::now();
                }
                frontend.send_to(&response.data, response.client_addr).await?;
                log::trace!(
                    "backend → client ({}): {} bytes",
                    response.client_addr,
                    response.data.len()
                );
            }

            // Periodic sweep for idle clients
            _ = sweep_interval.tick() => {
                let now = Instant::now();
                let before = clients.len();
                clients.retain(|addr, state| {
                    if now.duration_since(state.last_active) > idle_timeout {
                        log::info!("cleaning up idle client {addr}");
                        state.relay_task.abort();
                        false
                    } else {
                        true
                    }
                });
                let removed = before - clients.len();
                if removed > 0 {
                    log::info!("swept {removed} idle client(s), {len} remaining", len = clients.len());
                }
            }
        }
    }
}

/// Spawn a task that reads from a client's dedicated backend socket and
/// forwards responses back through the channel. Returns the task handle
/// so it can be aborted on cleanup.
fn spawn_backend_relay(
    client_addr: SocketAddr,
    backend_socket: Arc<UdpSocket>,
    response_tx: mpsc::Sender<BackendResponse>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let len = match backend_socket.recv(&mut buf).await {
                Ok(len) => len,
                Err(e) => {
                    // ECANCELED / connection refused after abort is expected
                    log::debug!("backend relay for {client_addr}: recv error: {e}");
                    break;
                }
            };

            let response = BackendResponse {
                client_addr,
                data: buf[..len].to_vec(),
            };

            if response_tx.send(response).await.is_err() {
                break; // Main loop shut down
            }
        }
    })
}

/// Process a single client packet: ECH-decrypt if Initial, otherwise forward.
async fn handle_client_packet(
    state: &mut ClientState,
    client_addr: SocketAddr,
    packet: &[u8],
) -> Result<()> {
    if state.ech_proxy.is_done() {
        // ECH processing complete, forward unchanged.
        state.backend_socket.send(packet).await?;
        log::trace!(
            "client ({client_addr}) → backend: {} bytes (passthrough)",
            packet.len()
        );
        return Ok(());
    }

    match quic_packet::decrypt_initial(packet) {
        Ok(Some(decrypted)) => {
            match process_initial(
                &mut state.ech_proxy,
                &mut state.assembler,
                &mut state.initial_header,
                decrypted,
            )? {
                ProcessResult::Forward(new_packet) => {
                    log::info!(
                        "client ({client_addr}) → backend: rewrote Initial ({} → {} bytes)",
                        packet.len(),
                        new_packet.len()
                    );
                    state.backend_socket.send(&new_packet).await?;
                }
                ProcessResult::NeedMoreData => {
                    log::debug!(
                        "client ({client_addr}) → backend: partial ClientHello, forwarding original"
                    );
                    state.backend_socket.send(packet).await?;
                }
                ProcessResult::Passthrough => {
                    log::debug!("client ({client_addr}) → backend: no ECH, passthrough");
                    state.backend_socket.send(packet).await?;
                }
            }
        }
        Ok(None) => {
            // Not an Initial packet, forward unchanged.
            state.backend_socket.send(packet).await?;
            log::trace!(
                "client ({client_addr}) → backend: non-Initial, {} bytes",
                packet.len()
            );
        }
        Err(e) => {
            log::warn!("client ({client_addr}): failed to decrypt Initial: {e}");
            // Forward anyway — might be a valid packet we can't parse.
            state.backend_socket.send(packet).await?;
        }
    }

    Ok(())
}

enum ProcessResult {
    /// Forward this rewritten Initial packet to the backend.
    Forward(Vec<u8>),
    /// Need more Initial packets to complete the ClientHello.
    NeedMoreData,
    /// No ECH; forward original packet unchanged.
    Passthrough,
}

fn process_initial(
    ech_proxy: &mut EchProxy,
    assembler: &mut CryptoAssembler,
    saved_header: &mut Option<InitialHeader>,
    decrypted: DecryptedInitial,
) -> Result<ProcessResult> {
    // Save header from first Initial for re-encryption.
    if saved_header.is_none() {
        *saved_header = Some(decrypted.header.clone());
    }

    // Accumulate CRYPTO segments.
    assembler.add_segments(&decrypted.crypto_segments);

    let hs_data = assembler.contiguous_data();
    if hs_data.is_empty() {
        return Ok(ProcessResult::NeedMoreData);
    }

    // Check if we have a complete ClientHello.
    // A ClientHello starts with type(1) + length(3). Check if we have
    // at least the header, then check if we have the full message.
    if hs_data.len() < 4 {
        return Ok(ProcessResult::NeedMoreData);
    }
    if hs_data[0] != 0x01 {
        // Not a ClientHello — shouldn't happen, but pass through.
        return Ok(ProcessResult::Passthrough);
    }
    let msg_len = u32::from_be_bytes([0, hs_data[1], hs_data[2], hs_data[3]]) as usize;
    if hs_data.len() < 4 + msg_len {
        return Ok(ProcessResult::NeedMoreData);
    }

    // We have a complete ClientHello handshake message. Run ECH proxy.
    let client_hello_msg = &hs_data[..4 + msg_len];

    match ech_proxy.process_client_hello_msg(client_hello_msg)? {
        EchProxyResult::Decrypted(inner_msg) => {
            log::info!(
                "ECH decrypted: outer CH {} bytes → inner CH {} bytes",
                client_hello_msg.len(),
                inner_msg.len()
            );

            // Re-encrypt into a new Initial packet with the inner ClientHello.
            let header = saved_header.as_ref().expect("header saved");
            let new_packet = quic_packet::encrypt_initial(header, &inner_msg)?;
            Ok(ProcessResult::Forward(new_packet))
        }
        EchProxyResult::NotOffered => {
            log::info!("no ECH offered, forwarding unchanged");
            Ok(ProcessResult::Passthrough)
        }
        EchProxyResult::Rejected(retry_configs) => {
            log::info!(
                "ECH rejected ({} bytes retry_configs), forwarding unchanged",
                retry_configs.len()
            );
            Ok(ProcessResult::Passthrough)
        }
    }
}
