//! Rustoshi RPC server
//!
//! JSON-RPC server providing Bitcoin Core-compatible APIs for node interaction.
//! Uses `jsonrpsee` for standards-compliant JSON-RPC 2.0 support.
//!
//! # Overview
//!
//! The RPC server provides endpoints for:
//! - Blockchain queries (getblock, getblockchaininfo, getblockhash)
//! - Transaction operations (getrawtransaction, sendrawtransaction, decoderawtransaction)
//! - Mempool information (getmempoolinfo, getrawmempool)
//! - Mining operations (getblocktemplate, submitblock, getmininginfo)
//! - Network information (getpeerinfo, getnetworkinfo, addnode)
//! - Fee estimation (estimatesmartfee)
//! - UTXO queries (gettxout)
//!
//! # Example
//!
//! ```ignore
//! use rustoshi_rpc::{RpcConfig, RpcState, PeerState, start_rpc_server};
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! let db = Arc::new(ChainDb::open_temp().unwrap());
//! let params = ChainParams::testnet4();
//! let state = Arc::new(RwLock::new(RpcState::new(db, params)));
//! let peer_state = Arc::new(RwLock::new(PeerState::default()));
//!
//! let config = RpcConfig::testnet4();
//! let handle = start_rpc_server(config, state, peer_state).await?;
//! ```

pub mod server;
pub mod types;

pub use server::{start_rpc_server, PeerState, RpcServerImpl, RpcState, RustoshiRpcServer};
pub use types::*;
