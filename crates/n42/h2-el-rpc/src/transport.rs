// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! How an Engine API call gets to the execution layer.
//!
//! Separated from the Engine API client itself so the parts that are easy to get
//! wrong — method version selection, parameter shape, error mapping — can be
//! tested against a recorded transport rather than a live node. HTTP is then a
//! thin layer with almost no logic in it.
//!
//! It also means the client is not married to HTTP: an IPC socket or an
//! in-process handle can implement the same trait.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use alloy_rpc_types_engine::{Claims, JwtSecret};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

/// A JSON-RPC error returned by the execution layer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RpcError {
    /// The error code. Engine API defines its own range; see
    /// [`UNKNOWN_PAYLOAD`].
    pub code: i64,
    /// The message.
    pub message: String,
}

/// `engine_getPayload*` for a build the execution layer does not know about.
///
/// Distinct from a failure: the caller asked about a job that does not exist,
/// which is a normal outcome when a build was superseded or the EL restarted.
pub const UNKNOWN_PAYLOAD: i64 = -38001;

/// The method version does not match the fork the payload belongs to.
///
/// `engine_getPayloadV3` on a Prague build, for instance. Not a failure of the
/// build: the execution layer is saying "ask again with the right version".
pub const UNSUPPORTED_FORK: i64 = -38005;

/// The Engine API's "invalid payload attributes".
///
/// A version refusing a *field* rather than the method: Amsterdam requires
/// EIP-7843's slot number on a `forkchoiceUpdatedV4` that starts a build, and
/// every fork before it refuses one. A client without the fork schedule reads
/// this the same way it reads [`UNSUPPORTED_FORK`] — as "ask the next version
/// down".
pub const INVALID_PAYLOAD_ATTRIBUTES: i64 = -38003;

/// JSON-RPC's "method not found".
///
/// What a stock execution layer answers to this repo's `n42Engine` methods; the
/// client falls back to the Engine API's own shape and does not ask again.
pub const METHOD_NOT_FOUND: i64 = -32601;

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}

/// Why a call did not produce a result.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The execution layer answered with a JSON-RPC error.
    #[error("execution layer: {0}")]
    Rpc(RpcError),
    /// The call did not reach the execution layer, or its answer was unusable.
    #[error("transport: {0}")]
    Transport(String),
    /// The JWT could not be produced. Almost always a clock problem — the
    /// Engine API accepts an `iat` within 60 seconds of the server's clock, so
    /// a badly skewed machine fails every call with a 401.
    #[error("jwt: {0}")]
    Jwt(String),
}

/// A JSON-RPC channel to an execution layer.
#[async_trait::async_trait]
pub trait JsonRpcTransport: Send + Sync + 'static {
    /// Sends one call and returns its `result` field.
    async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, TransportError>;

    /// Sends the same method many times in one request, returning how many
    /// succeeded.
    ///
    /// The caller that needs this is a consensus loop forwarding a gossiped
    /// batch of transactions: one round trip each blocks that loop for the
    /// length of the batch, and nothing else — including the libp2p swarm —
    /// runs while it does. The default is the sequential version, so a
    /// transport with nothing better still works.
    async fn call_many(&self, method: &str, params_each: Vec<Vec<Value>>) -> usize {
        let mut ok = 0;
        for params in params_each {
            if self.call(method, params).await.is_ok() {
                ok += 1;
            }
        }
        ok
    }
}

/// The authenticated HTTP transport an Engine API endpoint expects.
#[derive(Debug)]
pub struct HttpTransport {
    client: reqwest::Client,
    url: Url,
    jwt: JwtSecret,
    next_id: AtomicU64,
}

impl HttpTransport {
    /// Connects to `url`, authenticating with `jwt`.
    ///
    /// `url` is the *auth* endpoint (reth's `--authrpc.port`, default 8551), not
    /// the public JSON-RPC port. Pointing this at the public port produces
    /// "method not found" for every Engine API call, which reads like a version
    /// problem and is not one.
    pub fn new(url: Url, jwt: JwtSecret, timeout: Duration) -> Result<Self, TransportError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| TransportError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            url,
            jwt,
            next_id: AtomicU64::new(1),
        })
    }

    /// Mints a bearer token for one call.
    ///
    /// Per call, not per connection: the Engine API rejects an `iat` more than
    /// 60 seconds from its own clock, so a cached token silently starts failing
    /// on a long-lived node.
    fn bearer(&self) -> Result<String, TransportError> {
        self.jwt
            .encode(&Claims::with_current_timestamp())
            .map(|token| format!("Bearer {token}"))
            .map_err(|e| TransportError::Jwt(e.to_string()))
    }
}

#[async_trait::async_trait]
impl JsonRpcTransport for HttpTransport {
    /// One HTTP request carrying a JSON-RPC array. Elements are independent —
    /// some accepted, some refused — so this counts the results rather than
    /// failing the batch, and a malformed answer counts as none accepted rather
    /// than as one failure.
    async fn call_many(&self, method: &str, params_each: Vec<Vec<Value>>) -> usize {
        if params_each.is_empty() {
            return 0;
        }
        let body: Vec<Value> = params_each
            .into_iter()
            .map(|params| {
                json!({
                    "jsonrpc": "2.0",
                    "id": self.next_id.fetch_add(1, Ordering::Relaxed),
                    "method": method,
                    "params": params,
                })
            })
            .collect();
        let Ok(bearer) = self.bearer() else { return 0 };
        let response = self
            .client
            .post(self.url.clone())
            .header(reqwest::header::AUTHORIZATION, bearer)
            .json(&body)
            .send()
            .await;
        let Ok(response) = response else { return 0 };
        match response.json::<Value>().await {
            Ok(Value::Array(results)) => {
                results.iter().filter(|r| r.get("error").is_none()).count()
            }
            _ => 0,
        }
    }

    async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, TransportError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        // A send that fails before any response -- a pooled keep-alive
        // connection the server closed meanwhile, a reset -- is retried once
        // on a fresh connection; a timeout is not (the request may have been
        // acted on). Round 38: three such failures on a tenure leader's
        // forkchoiceUpdated each cost a view (10 s of timeout) and a window.
        let mut response = None;
        for attempt in 0..2u8 {
            match self
                .client
                .post(self.url.clone())
                .header(reqwest::header::AUTHORIZATION, self.bearer()?)
                .json(&body)
                .send()
                .await
            {
                Ok(r) => {
                    response = Some(r);
                    break;
                }
                Err(e) if attempt == 0 && !e.is_timeout() && (e.is_connect() || e.is_request()) => {
                    tracing::warn!(target: "n42.h2.el", method, %e, "engine request failed before a response; retrying once");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(e) => return Err(TransportError::Transport(e.to_string())),
            }
        }
        let response = response.expect("set on the successful attempt");

        // A 401 here is the JWT, not the payload, and saying so saves a long
        // detour through Engine API version differences.
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(TransportError::Jwt(
                "execution layer rejected the token; check the jwt secret and the system clock"
                    .into(),
            ));
        }
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .map_err(|e| TransportError::Transport(format!("HTTP {status}: {e}")))?;

        parse_response(body)
    }
}

/// Splits a JSON-RPC response into result or error.
///
/// Free-standing so it can be tested without a socket; malformed responses are
/// where a wrong port or a proxy in the way shows up.
pub fn parse_response(body: Value) -> Result<Value, TransportError> {
    if let Some(error) = body.get("error") {
        let error: RpcError = serde_json::from_value(error.clone())
            .map_err(|e| TransportError::Transport(format!("unparsable JSON-RPC error: {e}")))?;
        return Err(TransportError::Rpc(error));
    }
    body.get("result").cloned().ok_or_else(|| {
        TransportError::Transport("JSON-RPC response has neither result nor error".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_result_comes_back_as_a_result() {
        let body = json!({"jsonrpc": "2.0", "id": 1, "result": {"status": "VALID"}});
        assert_eq!(parse_response(body).unwrap(), json!({"status": "VALID"}));
    }

    #[test]
    fn an_unknown_payload_keeps_its_code_so_the_caller_can_tell_it_apart() {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": UNKNOWN_PAYLOAD, "message": "Unknown payload"},
        });
        match parse_response(body) {
            Err(TransportError::Rpc(err)) => assert_eq!(err.code, UNKNOWN_PAYLOAD),
            other => panic!("expected an RPC error, got {other:?}"),
        }
    }

    #[test]
    fn a_response_with_neither_field_is_an_error_not_a_null_result() {
        // What a wrong port or an HTTP proxy in the way tends to produce. Taking
        // it as a null result would turn a misconfiguration into a consensus
        // failure much later.
        let body = json!({"jsonrpc": "2.0", "id": 1});
        assert!(parse_response(body).is_err());
    }

    #[test]
    fn a_null_result_is_a_result() {
        // `engine_forkchoiceUpdated` legitimately returns a null payload id, and
        // some clients spell an absent value this way.
        let body = json!({"jsonrpc": "2.0", "id": 1, "result": null});
        assert_eq!(parse_response(body).unwrap(), Value::Null);
    }
}
