//! Per-party protocol machinery for proactive threshold Monero signing.
//!
//! The crate intentionally separates deterministic protocol reducers from the authenticated QUIC
//! peer transport and operator-only HTTP control surface.
//! Every inbound message is authenticated before it reaches a state machine and every state
//! transition returns outbound messages for the caller to persist before sending.

pub mod auth;
pub mod avss;
pub mod committee;
pub mod compact_epoch_registry;
pub mod compact_registry_archive;
pub mod compact_registry_store;
pub mod config;
pub mod consolidation_consensus;
pub mod consolidation_roast;
pub mod deposit_archive;
mod deposit_clock;
pub mod deposit_consensus;
pub mod deposit_consolidation;
pub mod deposit_consolidation_wire;
pub mod deposit_index;
pub mod deposit_index_checkpoint;
mod deposit_index_retention;
pub mod deposit_index_store;
pub mod deposit_ledger;
pub mod deposit_output_scanner;
pub mod deposit_prefix_collection_store;
pub mod deposit_prefix_scan_store;
pub mod deposit_service;
pub mod deposit_state_export;
pub mod deposit_state_export_store;
pub mod deposit_state_import;
pub mod deposit_state_import_store;
pub mod deposit_state_transfer_wire;
pub mod deposit_sync_stage;
pub mod deposit_sync_support;
pub mod deposit_sync_wire;
pub mod deposit_wallet;
pub mod deposit_worker;
pub mod e2e;
pub mod epoch_history;
pub mod identity;
pub mod key_rotation;
pub mod keys;
pub mod qual;
pub mod quic_runtime;
pub mod quic_transport;
pub mod receiver_key_accumulator;
pub mod reconnecting_monero;
pub mod roast_attempt_archive;
pub mod roast_history_consistency;
pub mod server;
pub mod signing;
pub mod storage;

pub use committee::{Committee, Member, PartyId, SessionId};
pub use config::{DepositBirthAnchor, Hex32, NetworkKind, Scenario};
