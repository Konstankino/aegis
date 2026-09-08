//! Durable backing store for **per-thread gate state** (Rule-of-Two taint + meter snapshot) and
//! **per-agent quarantine**, so they survive a cold restart across a human-approval
//! (`waitForTaskToken`) pause.
//!
//! ## Why this exists
//!
//! All Rule-of-Two taint lives in the gate's in-memory `sessions` map, keyed by `thread_id`. A
//! `human_approve` decision pauses the run in Step Functions for up to an hour; when it resumes,
//! the Lambda execution environment may have been torn down, so a **cold** extension process
//! starts with an empty map and the accumulated taint (and meter budget) silently resets to zero.
//! A later tool call is then mediated with no memory that the session already read untrusted +
//! sensitive data — the lethal trifecta that forced the human gate is gone. The same loss hits the
//! meter budget and an agent quarantine.
//!
//! The gate keeps its in-memory maps as a *cache* and uses this store as the durable source of
//! truth: it **write-through**s on change and **read-through**s (rehydrates) on a cache miss.
//!
//! ## Unforgeability
//!
//! The extension shares the agent function's execution role (a Lambda layer has no IAM of its
//! own), so no store can be made writable by the extension but not the agent. Unforgeability is
//! therefore structural, not IAM-based: **the taint never crosses the wire** — the client neither
//! sees nor supplies it; only this gate-owned code reads and writes it, keyed by `thread_id`.
//!
//! ## Layout
//!
//! Taint and meter are stored under **separate keys** so the meter-only endpoints
//! (`/meter/preflight`, `/meter/record`) can persist a fresh meter snapshot without ever
//! overwriting the durable taint with an empty value on a cold start.
//!
//! ## Backends
//!
//! * [`SessionStore::Null`] — no durability. `load_*` returns "absent", `save_*` is a no-op, so an
//!   unconfigured deployment behaves exactly as before (pure in-memory) and never fails closed.
//! * [`SessionStore::Dynamo`] — DynamoDB-backed (feature `dynamodb`). Reuses the existing
//!   `${name}-checkpoints` table with distinct sort keys, so no new infrastructure is needed.
//! * `Mem` — an in-memory test double (compiled only under `cfg(test)`); two stores can share one
//!   backing map to simulate a cold-restart handoff.

use aegis_core::Capability;
use aegis_meter::MeterSnapshot;

/// A fixed, non-sensitive store error (safe to log/return). The gate treats **any** error as
/// fail-closed — it denies rather than proceed with possibly-reset taint.
#[derive(Debug, Clone)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for StoreError {}

/// Result alias for store operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// The durable backing store, dispatched as an enum so no `dyn`/`async-trait` machinery is needed.
pub enum SessionStore {
    /// No durability (local dev / unconfigured): identical to the prior in-memory-only behaviour.
    Null,
    /// Production DynamoDB-backed store (feature `dynamodb`).
    #[cfg(feature = "dynamodb")]
    Dynamo(DynamoStore),
    /// In-memory test double.
    #[cfg(test)]
    Mem(mem::MemStore),
}

// The dispatch methods forward their arguments only in the `Dynamo`/`Mem` arms; when neither is
// compiled (the lean Null-only build) those parameters are unused — allow it in that config only.
#[cfg_attr(not(any(feature = "dynamodb", test)), allow(unused_variables))]
impl SessionStore {
    /// The no-durability store.
    #[must_use]
    pub fn null() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::Null)
    }

    /// The DynamoDB-backed store over the given table name.
    #[cfg(feature = "dynamodb")]
    #[must_use]
    pub fn dynamo(table: String) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::Dynamo(DynamoStore::new(table)))
    }

    /// Load a thread's durable Rule-of-Two taint. `Ok(None)` ⇒ the thread is genuinely new; `Err`
    /// ⇒ the store could not be consulted (the caller must fail closed).
    pub async fn load_cap(&self, thread_id: &str) -> StoreResult<Option<Capability>> {
        match self {
            Self::Null => Ok(None),
            #[cfg(feature = "dynamodb")]
            Self::Dynamo(d) => d.load_cap(thread_id).await,
            #[cfg(test)]
            Self::Mem(m) => m.load_cap(thread_id),
        }
    }

    /// Write-through a thread's Rule-of-Two taint.
    pub async fn save_cap(&self, thread_id: &str, cap: &Capability) -> StoreResult<()> {
        match self {
            Self::Null => Ok(()),
            #[cfg(feature = "dynamodb")]
            Self::Dynamo(d) => d.save_cap(thread_id, cap).await,
            #[cfg(test)]
            Self::Mem(m) => m.save_cap(thread_id, cap),
        }
    }

    /// Load a thread's durable meter snapshot.
    pub async fn load_meter(&self, thread_id: &str) -> StoreResult<Option<MeterSnapshot>> {
        match self {
            Self::Null => Ok(None),
            #[cfg(feature = "dynamodb")]
            Self::Dynamo(d) => d.load_meter(thread_id).await,
            #[cfg(test)]
            Self::Mem(m) => m.load_meter(thread_id),
        }
    }

    /// Write-through a thread's meter snapshot.
    pub async fn save_meter(&self, thread_id: &str, meter: &MeterSnapshot) -> StoreResult<()> {
        match self {
            Self::Null => Ok(()),
            #[cfg(feature = "dynamodb")]
            Self::Dynamo(d) => d.save_meter(thread_id, meter).await,
            #[cfg(test)]
            Self::Mem(m) => m.save_meter(thread_id, meter),
        }
    }

    /// Whether an agent is durably quarantined. `Err` ⇒ fail closed.
    pub async fn load_quarantine(&self, agent_id: &str) -> StoreResult<bool> {
        match self {
            Self::Null => Ok(false),
            #[cfg(feature = "dynamodb")]
            Self::Dynamo(d) => d.load_quarantine(agent_id).await,
            #[cfg(test)]
            Self::Mem(m) => m.load_quarantine(agent_id),
        }
    }

    /// Durably record that an agent is quarantined.
    pub async fn save_quarantine(&self, agent_id: &str, reason: &str) -> StoreResult<()> {
        match self {
            Self::Null => Ok(()),
            #[cfg(feature = "dynamodb")]
            Self::Dynamo(d) => d.save_quarantine(agent_id, reason).await,
            #[cfg(test)]
            Self::Mem(m) => m.save_quarantine(agent_id, reason),
        }
    }
}

// ── DynamoDB backend (feature `dynamodb`) ───────────────────────────────────────────────────────
//
// Reuses the existing per-project `${name}-checkpoints` table (hash_key `PK`, range_key `SK`, both
// String) that the agent already uses for its message transcript. Distinct sort keys keep the uses
// from colliding, and keep taint separate from meter:
//   PK="thread#<id>", SK="aegis#cap"        -> Capability JSON in `value`
//   PK="thread#<id>", SK="aegis#meter"      -> MeterSnapshot JSON in `value`
//   PK="agent#<id>",  SK="aegis#quarantine" -> quarantine marker JSON in `value`
// Reads are strongly consistent, so a genuinely-absent item is distinguishable from a lost write.
#[cfg(feature = "dynamodb")]
pub use dynamo::DynamoStore;

#[cfg(feature = "dynamodb")]
mod dynamo {
    use super::{StoreError, StoreResult};
    use aegis_core::Capability;
    use aegis_meter::MeterSnapshot;
    use aws_sdk_dynamodb::types::AttributeValue;
    use tokio::sync::OnceCell;

    /// A DynamoDB-backed [`super::SessionStore`] over one table.
    pub struct DynamoStore {
        table: String,
    }

    // One shared client for the process (built lazily from the default provider chain), mirroring
    // `ledger_sink`.
    static CLIENT: OnceCell<aws_sdk_dynamodb::Client> = OnceCell::const_new();

    async fn client() -> &'static aws_sdk_dynamodb::Client {
        CLIENT
            .get_or_init(|| async {
                let config = aws_config::load_from_env().await;
                aws_sdk_dynamodb::Client::new(&config)
            })
            .await
    }

    impl DynamoStore {
        pub fn new(table: String) -> Self {
            Self { table }
        }

        /// Read the JSON `value` attribute of one item, or `None` if the item is absent.
        async fn get_value(&self, pk: String, sk: &str) -> StoreResult<Option<String>> {
            let resp = client()
                .await
                .get_item()
                .table_name(&self.table)
                .key("PK", AttributeValue::S(pk))
                .key("SK", AttributeValue::S(sk.to_string()))
                .consistent_read(true)
                .send()
                .await
                .map_err(|e| StoreError(format!("dynamodb get_item failed: {e}")))?;
            match resp.item().and_then(|it| it.get("value")) {
                Some(AttributeValue::S(s)) => Ok(Some(s.clone())),
                Some(_) => Err(StoreError("dynamodb `value` is not a string".into())),
                None => Ok(None),
            }
        }

        /// Write the JSON `value` attribute of one item.
        async fn put_value(&self, pk: String, sk: &str, value: String) -> StoreResult<()> {
            client()
                .await
                .put_item()
                .table_name(&self.table)
                .item("PK", AttributeValue::S(pk))
                .item("SK", AttributeValue::S(sk.to_string()))
                .item("value", AttributeValue::S(value))
                .send()
                .await
                .map_err(|e| StoreError(format!("dynamodb put_item failed: {e}")))?;
            Ok(())
        }

        pub async fn load_cap(&self, thread_id: &str) -> StoreResult<Option<Capability>> {
            match self
                .get_value(format!("thread#{thread_id}"), "aegis#cap")
                .await?
            {
                Some(json) => serde_json::from_str(&json)
                    .map(Some)
                    .map_err(|e| StoreError(format!("cap parse failed: {e}"))),
                None => Ok(None),
            }
        }

        pub async fn save_cap(&self, thread_id: &str, cap: &Capability) -> StoreResult<()> {
            let json = serde_json::to_string(cap)
                .map_err(|e| StoreError(format!("cap ser failed: {e}")))?;
            self.put_value(format!("thread#{thread_id}"), "aegis#cap", json)
                .await
        }

        pub async fn load_meter(&self, thread_id: &str) -> StoreResult<Option<MeterSnapshot>> {
            match self
                .get_value(format!("thread#{thread_id}"), "aegis#meter")
                .await?
            {
                Some(json) => serde_json::from_str(&json)
                    .map(Some)
                    .map_err(|e| StoreError(format!("meter parse failed: {e}"))),
                None => Ok(None),
            }
        }

        pub async fn save_meter(&self, thread_id: &str, meter: &MeterSnapshot) -> StoreResult<()> {
            let json = serde_json::to_string(meter)
                .map_err(|e| StoreError(format!("meter ser failed: {e}")))?;
            self.put_value(format!("thread#{thread_id}"), "aegis#meter", json)
                .await
        }

        pub async fn load_quarantine(&self, agent_id: &str) -> StoreResult<bool> {
            Ok(self
                .get_value(format!("agent#{agent_id}"), "aegis#quarantine")
                .await?
                .is_some())
        }

        pub async fn save_quarantine(&self, agent_id: &str, reason: &str) -> StoreResult<()> {
            // The reason is a fixed, non-sensitive string (never the canary/payload).
            let value = serde_json::json!({ "quarantined": true, "reason": reason }).to_string();
            self.put_value(format!("agent#{agent_id}"), "aegis#quarantine", value)
                .await
        }
    }
}

// ── In-memory test double ───────────────────────────────────────────────────────────────────────
#[cfg(test)]
pub mod mem {
    use super::{StoreError, StoreResult};
    use aegis_core::Capability;
    use aegis_meter::MeterSnapshot;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// An in-memory store double. `Clone` shares the backing maps, so two `SessionStore::Mem`
    /// instances (a "before pause" gate and a "cold resume" gate) can share durable state. `fail`
    /// injects a store outage to exercise the fail-closed path.
    #[derive(Clone, Default)]
    pub struct MemStore {
        caps: Arc<Mutex<HashMap<String, String>>>,
        meters: Arc<Mutex<HashMap<String, String>>>,
        quarantined: Arc<Mutex<HashSet<String>>>,
        fail: Arc<AtomicBool>,
    }

    impl MemStore {
        /// Start returning errors from every operation (simulates a store outage).
        pub fn set_failing(&self, on: bool) {
            self.fail.store(on, Ordering::SeqCst);
        }
        fn guard(&self) -> StoreResult<()> {
            if self.fail.load(Ordering::SeqCst) {
                Err(StoreError("injected store outage".into()))
            } else {
                Ok(())
            }
        }

        pub fn load_cap(&self, thread_id: &str) -> StoreResult<Option<Capability>> {
            self.guard()?;
            match self.caps.lock().unwrap().get(thread_id) {
                Some(s) => serde_json::from_str(s)
                    .map(Some)
                    .map_err(|e| StoreError(e.to_string())),
                None => Ok(None),
            }
        }
        pub fn save_cap(&self, thread_id: &str, cap: &Capability) -> StoreResult<()> {
            self.guard()?;
            let json = serde_json::to_string(cap).map_err(|e| StoreError(e.to_string()))?;
            self.caps
                .lock()
                .unwrap()
                .insert(thread_id.to_string(), json);
            Ok(())
        }
        pub fn load_meter(&self, thread_id: &str) -> StoreResult<Option<MeterSnapshot>> {
            self.guard()?;
            match self.meters.lock().unwrap().get(thread_id) {
                Some(s) => serde_json::from_str(s)
                    .map(Some)
                    .map_err(|e| StoreError(e.to_string())),
                None => Ok(None),
            }
        }
        pub fn save_meter(&self, thread_id: &str, meter: &MeterSnapshot) -> StoreResult<()> {
            self.guard()?;
            let json = serde_json::to_string(meter).map_err(|e| StoreError(e.to_string()))?;
            self.meters
                .lock()
                .unwrap()
                .insert(thread_id.to_string(), json);
            Ok(())
        }
        pub fn load_quarantine(&self, agent_id: &str) -> StoreResult<bool> {
            self.guard()?;
            Ok(self.quarantined.lock().unwrap().contains(agent_id))
        }
        pub fn save_quarantine(&self, agent_id: &str, _reason: &str) -> StoreResult<()> {
            self.guard()?;
            self.quarantined
                .lock()
                .unwrap()
                .insert(agent_id.to_string());
            Ok(())
        }
    }
}
