//! Armory's blockchain backend: Bitcoin Core over JSON-RPC (spec 05, ADR-001 §1).

pub mod core;
pub mod rpc;

pub use crate::core::{Core, NodeConfig, NodeError, Rescan};
pub use rpc::{Auth, RpcClient, RpcError};
