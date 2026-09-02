//! N42: a way for the node to hand the engine a block it has already executed.
//!
//! reth inserts the payloads its own builder produced without re-executing
//! them (`InsertExecutedBlock`), but only through the payload builder's event
//! stream, and only for payload types that carry an execution result -- the
//! Ethereum ones do not. On a chain where consensus seals the header after
//! the build, the sealed block is a different hash from the built one, so
//! the node has to make the pairing itself and hand the engine the result.
//! This is the channel it does that on; the engine loop in `engine.rs`
//! forwards each message as an `InsertExecutedBlock`.
//!
//! The block travels as `Box<dyn Any>` because this module has no way to
//! name the node's primitives; the loop downcasts to the type it inserts and
//! answers `false` on a mismatch.

use std::{
    any::Any,
    sync::{Mutex, OnceLock},
};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

/// One already-executed block for the engine, and where to say it went in.
#[derive(Debug)]
pub struct ExecutedInsert {
    /// A `BuiltPayloadExecutedBlock<N>` for the node's `N`.
    pub block: Box<dyn Any + Send>,
    /// `true` once the engine has been handed the block; `false` if it was
    /// not of the type the engine inserts.
    pub done: oneshot::Sender<bool>,
}

struct Channel {
    sender: UnboundedSender<ExecutedInsert>,
    receiver: Mutex<Option<UnboundedReceiver<ExecutedInsert>>>,
}

fn channel() -> &'static Channel {
    static CHANNEL: OnceLock<Channel> = OnceLock::new();
    CHANNEL.get_or_init(|| {
        let (sender, receiver) = unbounded_channel();
        Channel { sender, receiver: Mutex::new(Some(receiver)) }
    })
}

/// A sender into the engine loop. Messages sent before the engine has been
/// launched wait in the channel.
pub fn sender() -> UnboundedSender<ExecutedInsert> {
    channel().sender.clone()
}

/// The receiving end, once: the engine loop takes it at launch.
pub(crate) fn take_receiver() -> Option<UnboundedReceiver<ExecutedInsert>> {
    channel().receiver.lock().unwrap_or_else(|p| p.into_inner()).take()
}
