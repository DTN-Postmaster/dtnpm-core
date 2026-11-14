//! Identity, Authentication, and Policy-Based Access Control (PBAC) core primitives.

#[cfg(feature = "transport-grpc")]
pub mod grpc_guard;
pub mod policy;

pub use policy::{Capabilities, ContextInput, PolicyEngine, RegoInput, RequestInput, UserInput};
