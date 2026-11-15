//! BPv7 extension block codecs and arbitrary CBOR inspection helpers.
//!
//! Supports:
//! - RFC 9171 Hop Count Block (Type 10)
//! - Unified Mesh Routing Extension Block (Type 200, `mesh-algo-extension-block.cddl`)
//! - Spray-and-Wait simple permit block (Type 194, ION-DTN / Hardy `feat/spray-n-wait`)
//! - Traceroute Extension Block / TREB (`draft-koo-dtn-traceroute-eb`, configurable default Type 201)
//! - Arbitrary / custom experimental CBOR blocks decoded dynamically to `serde_json::Value`

use std::collections::BTreeMap;

use ciborium::Value as CborValue;
use hardy_bpv7::{block, builder::Builder, bundle::Bundle, hop_info::HopInfo};
use hardy_cbor::decode::FromCbor;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors returned while encoding, decoding, or parsing BPv7 mesh routing extension blocks.
#[derive(Debug, Error)]
pub enum MeshBlockError {
    /// Failed to encode a BPv7 extension block to CBOR.
    #[error("CBOR encoding error: {0}")]
    CborEncode(String),

    /// Failed to decode a BPv7 extension block from CBOR.
    #[error("CBOR decoding error: {0}")]
    CborDecode(String),

    /// Invalid routing parameter supplied by user or API.
    #[error("Invalid routing parameter: {0}")]
    InvalidInput(String),
}

impl From<hardy_cbor::decode::Error> for MeshBlockError {
    fn from(err: hardy_cbor::decode::Error) -> Self {
        Self::CborDecode(err.to_string())
    }
}

/// RFC 9171 §4.3.1 Previous Node extension block type.
pub const BLOCK_TYPE_PREVIOUS_NODE: u64 = 6;

/// RFC 9171 §4.3.2 Bundle Age extension block type.
pub const BLOCK_TYPE_BUNDLE_AGE: u64 = 7;

/// RFC 9171 §4.3.3 Hop Count extension block type.
pub const BLOCK_TYPE_HOP_COUNT: u64 = 10;

/// Experimental / ION-DTN Spray-and-Wait permit count (`u32`) block type.
pub const BLOCK_TYPE_SPRAY_PERMIT: u64 = 194;

/// Unified Mesh Routing extension block type (`mesh-algo-extension-block.cddl`).
pub const BLOCK_TYPE_MESH_ROUTING: u64 = 200;

/// Default experimental block type for TREB (`draft-koo-dtn-traceroute-eb`).
pub const DEFAULT_BLOCK_TYPE_TREB: u64 = 201;

/// Maximum CBOR recursion depth when converting custom extension blocks into JSON.
const MAX_CBOR_DEPTH: usize = 32;

/// Maximum size in bytes accepted when parsing an arbitrary custom extension block.
const MAX_CUSTOM_CBOR_BYTES: usize = 256 * 1024;

/// External gateway identifier (LoRa / AX.25 bridge).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LegacyBridgeId {
    Uint(u64),
    Hex(String),
}

/// Spray-and-Wait / quota replication control facet (CDDL key 2 of Block Type 200).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationControl {
    pub quota: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u32>,
}

/// Strict node hop inside APRS / source trajectory control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictTarget {
    pub target_id: String,
    pub completed: bool,
}

/// Scoped alias hop inside APRS trajectory control (e.g., `WIDE1-1`, `WIDE2-2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedAlias {
    pub scope_name: String,
    pub max_count: u32,
    pub remaining_count: u32,
    pub completed: bool,
    pub serviced_by: Option<String>,
}

/// One element of an ordered future trajectory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathElement {
    Strict(StrictTarget),
    Alias(ScopedAlias),
}

#[derive(Serialize, Deserialize)]
struct SerdePathElement {
    #[serde(default)]
    target_type: Option<u8>,
    #[serde(default)]
    hop_kind: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remaining_count: Option<u32>,
    #[serde(default)]
    completed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    serviced_by: Option<String>,
}

impl Serialize for PathElement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = match self {
            Self::Strict(s) => SerdePathElement {
                target_type: Some(1),
                hop_kind: None,
                target_id: Some(s.target_id.clone()),
                scope_name: None,
                max_count: None,
                remaining_count: None,
                completed: s.completed,
                serviced_by: None,
            },
            Self::Alias(a) => SerdePathElement {
                target_type: Some(2),
                hop_kind: None,
                target_id: None,
                scope_name: Some(a.scope_name.clone()),
                max_count: Some(a.max_count),
                remaining_count: Some(a.remaining_count),
                completed: a.completed,
                serviced_by: a.serviced_by.clone(),
            },
        };
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PathElement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = SerdePathElement::deserialize(deserializer)?;
        let kind = raw
            .target_type
            .or(raw.hop_kind)
            .unwrap_or_else(|| if raw.scope_name.is_some() { 2 } else { 1 });
        if kind == 2 {
            Ok(Self::Alias(ScopedAlias {
                scope_name: raw.scope_name.unwrap_or_default(),
                max_count: raw.max_count.unwrap_or(0),
                remaining_count: raw.remaining_count.unwrap_or(0),
                completed: raw.completed,
                serviced_by: raw.serviced_by,
            }))
        } else {
            Ok(Self::Strict(StrictTarget {
                target_id: raw.target_id.unwrap_or_default(),
                completed: raw.completed,
            }))
        }
    }
}

/// Ordered future path facet (CDDL key 3 of Block Type 200).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrajectoryControl {
    #[serde(default)]
    pub path_elements: Vec<PathElement>,
    #[serde(default)]
    pub active_hop_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_substitution: Option<bool>,
}

/// Geographic delivery perimeter (CDDL key 5 of Block Type 200).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpatialScope {
    pub latitude: f64,
    pub longitude: f64,
    pub radius_meters: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub altitude_meters: Option<f64>,
}

/// Unified Block Type 200 payload (`mesh-algo-extension-block.cddl`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshRoutingData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_bridge_id: Option<LegacyBridgeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replication_control: Option<ReplicationControl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trajectory_control: Option<TrajectoryControl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opportunistic_threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spatial_scope: Option<SpatialScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_attributes: Option<BTreeMap<String, serde_json::Value>>,
}

/// Single visited hop recorded in the Traceroute Extension Block (`draft-koo-dtn-traceroute-eb`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrebHopEntry {
    pub node_eid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arrival_time_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub departure_time_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cla_info: Option<String>,
}

/// Past-path Traceroute Extension Block (configurable type, default 201).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrebData {
    #[serde(default)]
    pub hops: Vec<TrebHopEntry>,
}

/// Decodes a Block Type 194 Spray-and-Wait `u32` permit count from CBOR bytes.
pub fn decode_spray_permit(bytes: &[u8]) -> Result<u32, MeshBlockError> {
    let val = hardy_cbor::decode::parse::<u32>(bytes)?;
    Ok(val)
}

/// Encodes a Block Type 194 Spray-and-Wait `u32` permit count to canonical CBOR bytes.
pub fn encode_spray_permit(quota: u32) -> Box<[u8]> {
    hardy_cbor::encode::emit(&quota).0.into_boxed_slice()
}

/// Decodes an arbitrary CBOR byte slice into [`serde_json::Value`] so user Rego
/// policies can inspect any custom or experimental extension block.
pub fn decode_cbor_to_json(bytes: &[u8]) -> Result<serde_json::Value, MeshBlockError> {
    if bytes.len() > MAX_CUSTOM_CBOR_BYTES {
        return Err(MeshBlockError::CborDecode(format!(
            "Extension block payload exceeds {MAX_CUSTOM_CBOR_BYTES} byte limit"
        )));
    }
    let val: CborValue = ciborium::from_reader(bytes)
        .map_err(|e| MeshBlockError::CborDecode(format!("ciborium decode failed: {e}")))?;
    cbor_value_to_json(&val, 0)
}

fn cbor_value_to_json(val: &CborValue, depth: usize) -> Result<serde_json::Value, MeshBlockError> {
    if depth >= MAX_CBOR_DEPTH {
        return Err(MeshBlockError::CborDecode(
            "Maximum CBOR nesting depth exceeded".to_string(),
        ));
    }
    match val {
        CborValue::Integer(int_val) => {
            let i = i128::from(*int_val);
            if let Ok(u) = u64::try_from(i) {
                Ok(serde_json::Value::Number(u.into()))
            } else if let Ok(signed) = i64::try_from(i) {
                Ok(serde_json::Value::Number(signed.into()))
            } else {
                Ok(serde_json::Value::String(i.to_string()))
            }
        }
        CborValue::Bytes(bytes) => Ok(serde_json::Value::String(bytes_to_hex(bytes))),
        CborValue::Float(f) => match serde_json::Number::from_f64(*f) {
            Some(n) => Ok(serde_json::Value::Number(n)),
            None => Ok(serde_json::Value::Null),
        },
        CborValue::Text(s) => Ok(serde_json::Value::String(s.clone())),
        CborValue::Bool(b) => Ok(serde_json::Value::Bool(*b)),
        CborValue::Null => Ok(serde_json::Value::Null),
        CborValue::Tag(_tag, inner) => cbor_value_to_json(inner, depth + 1),
        CborValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(cbor_value_to_json(item, depth + 1)?);
            }
            Ok(serde_json::Value::Array(out))
        }
        CborValue::Map(entries) => {
            let mut map = serde_json::Map::with_capacity(entries.len());
            for (k, v) in entries {
                let key_str = cbor_key_to_string(k);
                let val_json = cbor_value_to_json(v, depth + 1)?;
                map.insert(key_str, val_json);
            }
            Ok(serde_json::Value::Object(map))
        }
        _ => Ok(serde_json::Value::Null),
    }
}

fn cbor_key_to_string(key: &CborValue) -> String {
    match key {
        CborValue::Text(s) => s.clone(),
        CborValue::Integer(i) => i128::from(*i).to_string(),
        CborValue::Bytes(b) => bytes_to_hex(b),
        CborValue::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, MeshBlockError> {
    if !hex.len().is_multiple_of(2) {
        return Err(MeshBlockError::CborEncode(
            "Hex string must have even length".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().as_chunks::<2>().0 {
        let s = std::str::from_utf8(chunk)
            .map_err(|_| MeshBlockError::CborEncode("Invalid UTF-8 in hex".to_string()))?;
        let byte = u8::from_str_radix(s, 16)
            .map_err(|e| MeshBlockError::CborEncode(format!("Invalid hex byte: {e}")))?;
        out.push(byte);
    }
    Ok(out)
}

fn cbor_to_uint(val: &CborValue) -> Option<u64> {
    if let CborValue::Integer(i) = val {
        u64::try_from(i128::from(*i)).ok()
    } else {
        None
    }
}

fn cbor_to_float(val: &CborValue) -> Option<f64> {
    match val {
        CborValue::Float(f) => Some(*f),
        CborValue::Integer(i) => Some(i128::from(*i) as f64),
        _ => None,
    }
}

fn encode_cbor_value(val: &CborValue) -> Result<Box<[u8]>, MeshBlockError> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf)
        .map_err(|e| MeshBlockError::CborEncode(format!("ciborium encode failed: {e}")))?;
    Ok(buf.into_boxed_slice())
}

fn json_to_cbor_value(val: &serde_json::Value, depth: usize) -> Result<CborValue, MeshBlockError> {
    if depth >= MAX_CBOR_DEPTH {
        return Err(MeshBlockError::CborEncode(
            "Maximum JSON->CBOR nesting depth exceeded".to_string(),
        ));
    }
    match val {
        serde_json::Value::Null => Ok(CborValue::Null),
        serde_json::Value::Bool(b) => Ok(CborValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(CborValue::Integer(u.into()))
            } else if let Some(i) = n.as_i64() {
                Ok(CborValue::Integer(i.into()))
            } else if let Some(f) = n.as_f64() {
                Ok(CborValue::Float(f))
            } else {
                Ok(CborValue::Null)
            }
        }
        serde_json::Value::String(s) => Ok(CborValue::Text(s.clone())),
        serde_json::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(json_to_cbor_value(item, depth + 1)?);
            }
            Ok(CborValue::Array(out))
        }
        serde_json::Value::Object(map) => {
            let mut pairs = Vec::with_capacity(map.len());
            for (k, v) in map {
                pairs.push((
                    CborValue::Text(k.clone()),
                    json_to_cbor_value(v, depth + 1)?,
                ));
            }
            Ok(CborValue::Map(pairs))
        }
    }
}

impl MeshRoutingData {
    /// Decodes Block Type 200 payload bytes using compact CDDL integer keys (or string keys).
    pub fn decode_cbor(bytes: &[u8]) -> Result<Self, MeshBlockError> {
        if bytes.len() > MAX_CUSTOM_CBOR_BYTES {
            return Err(MeshBlockError::CborDecode(
                "Block 200 payload exceeds size limit".to_string(),
            ));
        }
        let val: CborValue = ciborium::from_reader(bytes)
            .map_err(|e| MeshBlockError::CborDecode(format!("Invalid Block 200 CBOR: {e}")))?;
        let entries = match val {
            CborValue::Map(m) => m,
            _ => {
                return Err(MeshBlockError::CborDecode(
                    "Block 200 root must be a CBOR map".to_string(),
                ));
            }
        };

        let mut data = Self::default();
        for (k, v) in entries {
            match cbor_key_match(&k) {
                Some(KeyToken::Uint(1))
                | Some(KeyToken::Text("legacy-bridge-id" | "legacy_bridge_id")) => {
                    data.legacy_bridge_id = match v {
                        CborValue::Integer(i) => {
                            u64::try_from(i128::from(i)).ok().map(LegacyBridgeId::Uint)
                        }
                        CborValue::Bytes(b) => Some(LegacyBridgeId::Hex(bytes_to_hex(&b))),
                        CborValue::Text(s) => Some(LegacyBridgeId::Hex(s)),
                        _ => None,
                    };
                }
                Some(KeyToken::Uint(2))
                | Some(KeyToken::Text("replication-control" | "replication_control")) => {
                    data.replication_control = Some(decode_replication_control(&v)?);
                }
                Some(KeyToken::Uint(3))
                | Some(KeyToken::Text("trajectory-control" | "trajectory_control")) => {
                    data.trajectory_control = Some(decode_trajectory_control(&v)?);
                }
                Some(KeyToken::Uint(4))
                | Some(KeyToken::Text("opportunistic-threshold" | "opportunistic_threshold")) => {
                    data.opportunistic_threshold = cbor_to_float(&v);
                }
                Some(KeyToken::Uint(5))
                | Some(KeyToken::Text("spatial-scope" | "spatial_scope")) => {
                    data.spatial_scope = Some(decode_spatial_scope(&v)?);
                }
                Some(KeyToken::Uint(6))
                | Some(KeyToken::Text("custom-attributes" | "custom_attributes")) => {
                    if let CborValue::Map(attrs) = v {
                        let mut out = BTreeMap::new();
                        for (ak, av) in attrs {
                            out.insert(cbor_key_to_string(&ak), cbor_value_to_json(&av, 0)?);
                        }
                        data.custom_attributes = Some(out);
                    }
                }
                _ => {}
            }
        }
        Ok(data)
    }

    /// Encodes Block Type 200 payload into canonical integer-keyed CBOR bytes per CDDL.
    pub fn encode_cbor(&self) -> Result<Box<[u8]>, MeshBlockError> {
        let mut root = Vec::new();
        if let Some(id) = &self.legacy_bridge_id {
            let val = match id {
                LegacyBridgeId::Uint(u) => CborValue::Integer((*u).into()),
                LegacyBridgeId::Hex(h) => {
                    if let Ok(b) = hex_to_bytes(h) {
                        CborValue::Bytes(b)
                    } else {
                        CborValue::Text(h.clone())
                    }
                }
            };
            root.push((CborValue::Integer(1.into()), val));
        }
        if let Some(rep) = &self.replication_control {
            let mut m = vec![(
                CborValue::Integer(1.into()),
                CborValue::Integer(rep.quota.into()),
            )];
            if let Some(mode) = rep.mode {
                m.push((
                    CborValue::Integer(2.into()),
                    CborValue::Integer(mode.into()),
                ));
            }
            if let Some(phase) = rep.phase {
                m.push((
                    CborValue::Integer(3.into()),
                    CborValue::Integer(phase.into()),
                ));
            }
            if let Some(generation_val) = rep.generation {
                m.push((
                    CborValue::Integer(4.into()),
                    CborValue::Integer(generation_val.into()),
                ));
            }
            root.push((CborValue::Integer(2.into()), CborValue::Map(m)));
        }
        if let Some(traj) = &self.trajectory_control {
            let mut elems = Vec::with_capacity(traj.path_elements.len());
            for elem in &traj.path_elements {
                match elem {
                    PathElement::Strict(s) => {
                        elems.push(CborValue::Map(vec![
                            (CborValue::Integer(1.into()), CborValue::Integer(1.into())),
                            (
                                CborValue::Integer(2.into()),
                                CborValue::Text(s.target_id.clone()),
                            ),
                            (CborValue::Integer(3.into()), CborValue::Bool(s.completed)),
                        ]));
                    }
                    PathElement::Alias(a) => {
                        let mut am = vec![
                            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
                            (
                                CborValue::Integer(2.into()),
                                CborValue::Text(a.scope_name.clone()),
                            ),
                            (
                                CborValue::Integer(3.into()),
                                CborValue::Integer(a.max_count.into()),
                            ),
                            (
                                CborValue::Integer(4.into()),
                                CborValue::Integer(a.remaining_count.into()),
                            ),
                            (CborValue::Integer(5.into()), CborValue::Bool(a.completed)),
                        ];
                        if let Some(sb) = &a.serviced_by {
                            am.push((CborValue::Integer(6.into()), CborValue::Text(sb.clone())));
                        }
                        elems.push(CborValue::Map(am));
                    }
                }
            }
            let mut tm = vec![
                (CborValue::Integer(1.into()), CborValue::Array(elems)),
                (
                    CborValue::Integer(2.into()),
                    CborValue::Integer(traj.active_hop_index.into()),
                ),
            ];
            if let Some(sub) = traj.allow_substitution {
                tm.push((CborValue::Integer(3.into()), CborValue::Bool(sub)));
            }
            root.push((CborValue::Integer(3.into()), CborValue::Map(tm)));
        }
        if let Some(thr) = self.opportunistic_threshold {
            root.push((CborValue::Integer(4.into()), CborValue::Float(thr)));
        }
        if let Some(scope) = &self.spatial_scope {
            let mut sm = vec![
                (
                    CborValue::Integer(1.into()),
                    CborValue::Float(scope.latitude),
                ),
                (
                    CborValue::Integer(2.into()),
                    CborValue::Float(scope.longitude),
                ),
                (
                    CborValue::Integer(3.into()),
                    CborValue::Integer(scope.radius_meters.into()),
                ),
            ];
            if let Some(alt) = scope.altitude_meters {
                sm.push((CborValue::Integer(4.into()), CborValue::Float(alt)));
            }
            root.push((CborValue::Integer(5.into()), CborValue::Map(sm)));
        }
        if let Some(attrs) = &self.custom_attributes {
            let mut pairs = Vec::with_capacity(attrs.len());
            for (k, v) in attrs {
                pairs.push((CborValue::Text(k.clone()), json_to_cbor_value(v, 0)?));
            }
            root.push((CborValue::Integer(6.into()), CborValue::Map(pairs)));
        }
        encode_cbor_value(&CborValue::Map(root))
    }
}

impl TrebData {
    /// Decodes a TREB (`draft-koo-dtn-traceroute-eb`) CBOR payload.
    /// Accepts either `{ 1 / "hops": [ ... ] }` or a bare array `[ ... ]`.
    pub fn decode_cbor(bytes: &[u8]) -> Result<Self, MeshBlockError> {
        if bytes.len() > MAX_CUSTOM_CBOR_BYTES {
            return Err(MeshBlockError::CborDecode(
                "TREB payload exceeds size limit".to_string(),
            ));
        }
        let val: CborValue = ciborium::from_reader(bytes)
            .map_err(|e| MeshBlockError::CborDecode(format!("Invalid TREB CBOR: {e}")))?;

        let raw_hops = match val {
            CborValue::Array(arr) => arr,
            CborValue::Map(entries) => {
                let mut found = Vec::new();
                for (k, v) in entries {
                    if matches!(
                        cbor_key_match(&k),
                        Some(KeyToken::Uint(1)) | Some(KeyToken::Text("hops"))
                    ) && let CborValue::Array(arr) = v
                    {
                        found = arr;
                        break;
                    }
                }
                found
            }
            _ => {
                return Err(MeshBlockError::CborDecode(
                    "TREB root must be a CBOR map or array".to_string(),
                ));
            }
        };

        let mut hops = Vec::with_capacity(raw_hops.len());
        for entry in raw_hops {
            match entry {
                CborValue::Map(m) => {
                    let mut node_eid = String::new();
                    let mut arrival_time_ms = None;
                    let mut departure_time_ms = None;
                    let mut cla_info = None;
                    for (k, v) in m {
                        match cbor_key_match(&k) {
                            Some(KeyToken::Uint(1))
                            | Some(KeyToken::Text("node-eid" | "node_eid")) => {
                                if let CborValue::Text(s) = v {
                                    node_eid = s;
                                }
                            }
                            Some(KeyToken::Uint(2))
                            | Some(KeyToken::Text("arrival-time-ms" | "arrival_time_ms")) => {
                                arrival_time_ms = cbor_to_uint(&v);
                            }
                            Some(KeyToken::Uint(3))
                            | Some(KeyToken::Text("departure-time-ms" | "departure_time_ms")) => {
                                departure_time_ms = cbor_to_uint(&v);
                            }
                            Some(KeyToken::Uint(4))
                            | Some(KeyToken::Text("cla-info" | "cla_info")) => {
                                if let CborValue::Text(s) = v {
                                    cla_info = Some(s);
                                }
                            }
                            _ => {}
                        }
                    }
                    if !node_eid.is_empty() {
                        hops.push(TrebHopEntry {
                            node_eid,
                            arrival_time_ms,
                            departure_time_ms,
                            cla_info,
                        });
                    }
                }
                CborValue::Array(arr) if !arr.is_empty() => {
                    if let CborValue::Text(s) = &arr[0] {
                        hops.push(TrebHopEntry {
                            node_eid: s.clone(),
                            arrival_time_ms: arr.get(1).and_then(cbor_to_uint),
                            departure_time_ms: arr.get(2).and_then(cbor_to_uint),
                            cla_info: arr.get(3).and_then(|v| match v {
                                CborValue::Text(t) => Some(t.clone()),
                                _ => None,
                            }),
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(Self { hops })
    }

    /// Encodes the TREB payload using compact integer keys matching `draft-koo-dtn-traceroute-eb` concepts.
    pub fn encode_cbor(&self) -> Result<Box<[u8]>, MeshBlockError> {
        let mut encoded_hops = Vec::with_capacity(self.hops.len());
        for hop in &self.hops {
            let mut m = vec![(
                CborValue::Integer(1.into()),
                CborValue::Text(hop.node_eid.clone()),
            )];
            if let Some(arr) = hop.arrival_time_ms {
                m.push((CborValue::Integer(2.into()), CborValue::Integer(arr.into())));
            }
            if let Some(dep) = hop.departure_time_ms {
                m.push((CborValue::Integer(3.into()), CborValue::Integer(dep.into())));
            }
            if let Some(cla) = &hop.cla_info {
                m.push((CborValue::Integer(4.into()), CborValue::Text(cla.clone())));
            }
            encoded_hops.push(CborValue::Map(m));
        }
        let root = CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Array(encoded_hops),
        )]);
        encode_cbor_value(&root)
    }

    /// Appends a hop entry to the TREB path.
    pub fn push_hop(&mut self, entry: TrebHopEntry) {
        self.hops.push(entry);
    }

    /// Returns `true` if `node_eid` already appears in the recorded past path.
    pub fn contains_node(&self, node_eid: &str) -> bool {
        self.hops.iter().any(|h| h.node_eid == node_eid)
    }
}

enum KeyToken<'a> {
    Uint(u64),
    Text(&'a str),
}

fn cbor_key_match(key: &CborValue) -> Option<KeyToken<'_>> {
    match key {
        CborValue::Integer(i) => u64::try_from(i128::from(*i)).ok().map(KeyToken::Uint),
        CborValue::Text(s) => Some(KeyToken::Text(s.as_str())),
        _ => None,
    }
}

fn decode_replication_control(val: &CborValue) -> Result<ReplicationControl, MeshBlockError> {
    let CborValue::Map(m) = val else {
        return Err(MeshBlockError::CborDecode(
            "replication-control must be a CBOR map".to_string(),
        ));
    };
    let mut quota = None;
    let mut mode = None;
    let mut phase = None;
    let mut generation = None;
    for (k, v) in m {
        match cbor_key_match(k) {
            Some(KeyToken::Uint(1)) | Some(KeyToken::Text("quota")) => {
                quota = cbor_to_uint(v).and_then(|u| u32::try_from(u).ok());
            }
            Some(KeyToken::Uint(2)) | Some(KeyToken::Text("mode")) => {
                mode = cbor_to_uint(v).and_then(|u| u8::try_from(u).ok());
            }
            Some(KeyToken::Uint(3)) | Some(KeyToken::Text("phase")) => {
                phase = cbor_to_uint(v).and_then(|u| u8::try_from(u).ok());
            }
            Some(KeyToken::Uint(4)) | Some(KeyToken::Text("generation")) => {
                generation = cbor_to_uint(v).and_then(|u| u32::try_from(u).ok());
            }
            _ => {}
        }
    }
    Ok(ReplicationControl {
        quota: quota.unwrap_or(0),
        mode,
        phase,
        generation,
    })
}

fn decode_trajectory_control(val: &CborValue) -> Result<TrajectoryControl, MeshBlockError> {
    let CborValue::Map(m) = val else {
        return Err(MeshBlockError::CborDecode(
            "trajectory-control must be a CBOR map".to_string(),
        ));
    };
    let mut path_elements = Vec::new();
    let mut active_hop_index = 0;
    let mut allow_substitution = None;
    for (k, v) in m {
        match cbor_key_match(k) {
            Some(KeyToken::Uint(1)) | Some(KeyToken::Text("path-elements" | "path_elements")) => {
                if let CborValue::Array(arr) = v {
                    for elem in arr {
                        path_elements.push(decode_path_element(elem)?);
                    }
                }
            }
            Some(KeyToken::Uint(2))
            | Some(KeyToken::Text("active-hop-index" | "active_hop_index")) => {
                active_hop_index = cbor_to_uint(v)
                    .and_then(|u| u32::try_from(u).ok())
                    .unwrap_or(0);
            }
            Some(KeyToken::Uint(3))
            | Some(KeyToken::Text("allow-substitution" | "allow_substitution")) => {
                if let CborValue::Bool(b) = v {
                    allow_substitution = Some(*b);
                }
            }
            _ => {}
        }
    }
    Ok(TrajectoryControl {
        path_elements,
        active_hop_index,
        allow_substitution,
    })
}

fn decode_path_element(val: &CborValue) -> Result<PathElement, MeshBlockError> {
    let CborValue::Map(m) = val else {
        return Err(MeshBlockError::CborDecode(
            "path-element must be a CBOR map".to_string(),
        ));
    };
    let mut target_type = None;
    let mut target_id = None;
    let mut scope_name = None;
    let mut max_count = None;
    let mut remaining_count = None;
    let mut completed = None;
    let mut serviced_by = None;

    for (k, v) in m {
        match cbor_key_match(k) {
            Some(KeyToken::Uint(1))
            | Some(KeyToken::Text("target-type" | "target_type" | "hop_kind")) => {
                target_type = cbor_to_uint(v).and_then(|u| u8::try_from(u).ok());
            }
            Some(KeyToken::Uint(2)) => {
                if let CborValue::Text(s) = v {
                    target_id = Some(s.clone());
                    scope_name = Some(s.clone());
                }
            }
            Some(KeyToken::Text("target-id" | "target_id" | "node_identifier")) => {
                if let CborValue::Text(s) = v {
                    target_id = Some(s.clone());
                }
            }
            Some(KeyToken::Text("scope-name" | "scope_name" | "alias_name")) => {
                if let CborValue::Text(s) = v {
                    scope_name = Some(s.clone());
                }
            }
            Some(KeyToken::Uint(3)) => {
                // In CDDL, strict-target uses key 3 for `completed` (bool),
                // whereas scoped-alias defines key 3 as `max-count` (uint).
                match v {
                    CborValue::Bool(b) => completed = Some(*b),
                    CborValue::Integer(_) => {
                        max_count = cbor_to_uint(v).and_then(|u| u32::try_from(u).ok());
                    }
                    _ => {}
                }
            }
            Some(KeyToken::Text("max-count" | "max_count")) => {
                max_count = cbor_to_uint(v).and_then(|u| u32::try_from(u).ok());
            }
            Some(KeyToken::Uint(4))
            | Some(KeyToken::Text("remaining-count" | "remaining_count" | "remaining_hops")) => {
                remaining_count = cbor_to_uint(v).and_then(|u| u32::try_from(u).ok());
            }
            Some(KeyToken::Uint(5)) | Some(KeyToken::Text("completed")) => {
                if let CborValue::Bool(b) = v {
                    completed = Some(*b);
                }
            }
            Some(KeyToken::Uint(6)) | Some(KeyToken::Text("serviced-by" | "serviced_by")) => {
                if let CborValue::Text(s) = v {
                    serviced_by = Some(s.clone());
                }
            }
            _ => {}
        }
    }

    if target_type == Some(2)
        || (target_type.is_none() && (remaining_count.is_some() || max_count.is_some()))
    {
        let rem = remaining_count.unwrap_or(0);
        Ok(PathElement::Alias(ScopedAlias {
            scope_name: scope_name.unwrap_or_default(),
            max_count: max_count.unwrap_or(rem),
            remaining_count: rem,
            completed: completed.unwrap_or(rem == 0),
            serviced_by,
        }))
    } else {
        Ok(PathElement::Strict(StrictTarget {
            target_id: target_id.unwrap_or_default(),
            completed: completed.unwrap_or(false),
        }))
    }
}

fn decode_spatial_scope(val: &CborValue) -> Result<SpatialScope, MeshBlockError> {
    let CborValue::Map(m) = val else {
        return Err(MeshBlockError::CborDecode(
            "spatial-scope must be a CBOR map".to_string(),
        ));
    };
    let mut latitude = 0.0;
    let mut longitude = 0.0;
    let mut radius_meters = 0;
    let mut altitude_meters = None;

    for (k, v) in m {
        match cbor_key_match(k) {
            Some(KeyToken::Uint(1)) | Some(KeyToken::Text("latitude")) => {
                latitude = cbor_to_float(v).unwrap_or(0.0);
            }
            Some(KeyToken::Uint(2)) | Some(KeyToken::Text("longitude")) => {
                longitude = cbor_to_float(v).unwrap_or(0.0);
            }
            Some(KeyToken::Uint(3)) | Some(KeyToken::Text("radius-meters" | "radius_meters")) => {
                radius_meters = cbor_to_uint(v).unwrap_or(0);
            }
            Some(KeyToken::Uint(4))
            | Some(KeyToken::Text("altitude-meters" | "altitude_meters")) => {
                altitude_meters = cbor_to_float(v);
            }
            _ => {}
        }
    }

    Ok(SpatialScope {
        latitude,
        longitude,
        radius_meters,
        altitude_meters,
    })
}

/// Decoded RFC 9171 Hop Count Block (Type 10) summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopCountInfo {
    pub count: u64,
    pub limit: u8,
}

/// Summary of routing extension blocks present on a BPv7 bundle.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RoutingExtensionsSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_count: Option<HopCountInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spray_permit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_routing: Option<MeshRoutingData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aprs_path_formatted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treb: Option<TrebData>,
}

impl RoutingExtensionsSummary {
    /// Returns `true` if no routing extension blocks were found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hop_count.is_none()
            && self.spray_permit.is_none()
            && self.mesh_routing.is_none()
            && self.treb.is_none()
    }
}

/// Parses a comma-separated APRS-like path specification into [`PathElement`] items.
///
/// Examples:
/// - `"WIDE1-1,WIDE2-2"` -> two `ScopedAlias` hops (`WIDE1` 1/1, `WIDE2` 2/2)
/// - `"dtn://relay1/,WIDE2-2"` -> `StrictTarget("dtn://relay1/")`, `ScopedAlias("WIDE2", 2/2)`
/// - `"ipn:42.0,RELAY"` -> two `StrictTarget` hops
pub fn parse_aprs_path(spec: &str) -> Result<Vec<PathElement>, MeshBlockError> {
    let mut elements = Vec::new();
    for raw_hop in spec.split(',') {
        let hop = raw_hop.trim();
        if hop.is_empty() {
            continue;
        }
        if hop.starts_with("dtn://") || hop.starts_with("ipn:") {
            elements.push(PathElement::Strict(StrictTarget {
                target_id: hop.to_string(),
                completed: false,
            }));
            continue;
        }
        if let Some((scope, count_str)) = hop.rsplit_once('-')
            && !scope.is_empty()
            && scope.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && let Ok(count) = count_str.parse::<u32>()
        {
            if count == 0 {
                return Err(MeshBlockError::InvalidInput(format!(
                    "APRS alias '{hop}' must have a hop count >= 1"
                )));
            }
            elements.push(PathElement::Alias(ScopedAlias {
                scope_name: scope.to_ascii_uppercase(),
                max_count: count,
                remaining_count: count,
                completed: false,
                serviced_by: None,
            }));
            continue;
        }
        elements.push(PathElement::Strict(StrictTarget {
            target_id: hop.to_string(),
            completed: false,
        }));
    }
    if elements.is_empty() {
        return Err(MeshBlockError::InvalidInput(
            "APRS path cannot be empty".to_string(),
        ));
    }
    Ok(elements)
}

/// Formats a [`TrajectoryControl`] path into a concise human-readable APRS-like string.
#[must_use]
pub fn format_aprs_path(elements: &[PathElement]) -> String {
    elements
        .iter()
        .map(|elem| match elem {
            PathElement::Strict(s) => {
                if s.completed {
                    format!("{}*", s.target_id)
                } else {
                    s.target_id.clone()
                }
            }
            PathElement::Alias(a) => {
                let base = format!("{}-{}", a.scope_name, a.remaining_count);
                if a.completed {
                    if let Some(ref sb) = a.serviced_by {
                        format!("{base}*({sb})")
                    } else {
                        format!("{base}*")
                    }
                } else {
                    base
                }
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Attaches optional Hop Count (Type 10), APRS Trajectory (Type 200), and Spray-and-Wait
/// quota (Type 194 & Type 200) extension blocks onto a Hardy BPv7 [`Builder`].
pub fn apply_routing_extensions<'a>(
    mut builder: Builder<'a>,
    hop_limit: Option<u8>,
    aprs_path: Option<&str>,
    spray_quota: Option<u32>,
) -> anyhow::Result<Builder<'a>> {
    if let Some(limit) = hop_limit {
        let nz_limit = std::num::NonZeroU8::new(limit)
            .ok_or_else(|| anyhow::anyhow!("hop_limit must be >= 1"))?;
        builder = builder.with_hop_count(&HopInfo {
            limit: nz_limit,
            count: 0,
        });
    }

    if let Some(quota) = spray_quota {
        if quota == 0 {
            anyhow::bail!("spray_quota must be >= 1");
        }
        let permit_bytes = encode_spray_permit(quota);
        builder = builder
            .add_extension_block(block::Type::Unrecognised(BLOCK_TYPE_SPRAY_PERMIT))
            .map_err(|e| anyhow::anyhow!("Failed to add Spray Permit block (194): {e}"))?
            .with_flags(block::Flags {
                must_replicate: true,
                ..Default::default()
            })
            .build(permit_bytes.into_vec().into());
    }

    let trimmed_path = aprs_path.map(str::trim).filter(|s| !s.is_empty());
    if trimmed_path.is_some() || spray_quota.is_some() {
        let trajectory_control = match trimmed_path {
            Some(path_str) => {
                let path_elements = parse_aprs_path(path_str)?;
                Some(TrajectoryControl {
                    path_elements,
                    active_hop_index: 0,
                    allow_substitution: Some(true),
                })
            }
            None => None,
        };

        let replication_control = spray_quota.map(|quota| ReplicationControl {
            quota,
            mode: Some(2), // Binary Spray-and-Wait by default
            phase: Some(if quota > 1 { 1 } else { 2 }),
            generation: None,
        });

        let mesh = MeshRoutingData {
            replication_control,
            trajectory_control,
            ..Default::default()
        };
        let encoded = mesh.encode_cbor()?;
        builder = builder
            .add_extension_block(block::Type::Unrecognised(BLOCK_TYPE_MESH_ROUTING))
            .map_err(|e| anyhow::anyhow!("Failed to add Mesh Routing block (200): {e}"))?
            .with_flags(block::Flags {
                must_replicate: true,
                ..Default::default()
            })
            .build(encoded.into_vec().into());
    }

    Ok(builder)
}

/// Extracts and decodes routing extension blocks (Types 10, 194, 200, 201) from a parsed BPv7 bundle.
#[must_use]
pub fn extract_routing_extensions(bundle: &Bundle, raw_bundle: &[u8]) -> RoutingExtensionsSummary {
    let mut summary = RoutingExtensionsSummary::default();

    for block in bundle.blocks.values() {
        let Some(payload) = block.payload(raw_bundle) else {
            continue;
        };
        match block.block_type {
            block::Type::HopCount => {
                if let Ok((info, _, _)) = HopInfo::from_cbor(payload) {
                    summary.hop_count = Some(HopCountInfo {
                        count: info.count,
                        limit: info.limit.get(),
                    });
                }
            }
            block::Type::Unrecognised(BLOCK_TYPE_SPRAY_PERMIT) => {
                if let Ok(permit) = decode_spray_permit(payload) {
                    summary.spray_permit = Some(permit);
                }
            }
            block::Type::Unrecognised(BLOCK_TYPE_MESH_ROUTING) => {
                if let Ok(mesh) = MeshRoutingData::decode_cbor(payload) {
                    if let Some(ref traj) = mesh.trajectory_control {
                        summary.aprs_path_formatted = Some(format_aprs_path(&traj.path_elements));
                    }
                    summary.mesh_routing = Some(mesh);
                }
            }
            block::Type::Unrecognised(DEFAULT_BLOCK_TYPE_TREB) => {
                if let Ok(treb) = TrebData::decode_cbor(payload) {
                    summary.treb = Some(treb);
                }
            }
            _ => {}
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardy_bpv7::creation_timestamp::CreationTimestamp;
    use hardy_bpv7::eid::Eid;

    #[test]
    fn parse_and_format_aprs_path_roundtrip() {
        let parsed = parse_aprs_path("WIDE1-1, dtn://relay1/, WIDE2-2")
            .expect("valid APRS path should parse");
        assert_eq!(parsed.len(), 3);
        assert_eq!(format_aprs_path(&parsed), "WIDE1-1,dtn://relay1/,WIDE2-2");
    }

    #[test]
    fn parse_aprs_path_rejects_empty_or_zero_count() {
        assert!(parse_aprs_path("   ").is_err());
        assert!(parse_aprs_path("WIDE1-0").is_err());
    }

    #[test]
    fn apply_and_extract_routing_extensions_roundtrip() {
        let src: Eid = "dtn://node1/src".parse().expect("valid src eid");
        let dst: Eid = "dtn://node2/dst".parse().expect("valid dst eid");
        let builder = Builder::new(src, dst).with_payload(b"hello".as_slice().into());
        let builder = apply_routing_extensions(builder, Some(12), Some("WIDE1-1,WIDE2-2"), Some(8))
            .expect("apply extensions");
        let (_bundle, raw) = builder
            .build(CreationTimestamp::now())
            .expect("build bundle");

        let parsed = hardy_bpv7::parse::parse(raw.to_vec().into()).expect("parse built bundle");
        let summary = extract_routing_extensions(&parsed.bundle, &parsed.data);

        assert_eq!(
            summary.hop_count,
            Some(HopCountInfo {
                count: 0,
                limit: 12
            })
        );
        assert_eq!(summary.spray_permit, Some(8));
        assert_eq!(
            summary.aprs_path_formatted.as_deref(),
            Some("WIDE1-1,WIDE2-2")
        );
        let mesh = summary.mesh_routing.expect("mesh routing block 200");
        assert_eq!(mesh.replication_control.as_ref().map(|r| r.quota), Some(8));
        assert_eq!(
            mesh.trajectory_control
                .as_ref()
                .map(|t| t.path_elements.len()),
            Some(2)
        );
    }
}
