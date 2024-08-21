


use std::sync::Arc;


use crate::apos::APos;
use crate::traits::ChainReader;

// API is a user facing jsonrpc API to allow controlling the signer and voting
// mechanisms of the proof-of-authority scheme.
pub struct API {
    pub chain: Arc<dyn ChainReader>,
    pub apos: Arc<APos>,
}