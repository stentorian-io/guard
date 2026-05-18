//! crates/sentinel-cli/src/prompt_channel.rs
//!
//! Phase 3 plan 03-12 — long-lived channel client with in-flight prompt tracking.
//!
//! CR-02: the channel is split into a Mutex-free reader half (owned by the
//! render thread) and a Mutex-protected writer half (shared between the render
//! thread and the SIGINT handler). The blocking `read_frame` syscall in
//! `next_prompt` no longer holds any lock that the SIGINT handler needs to
//! call `cancel`, so the cancel arm can run while the render thread is parked
//! waiting on a daemon-side PromptRequest. Mirrors the daemon-side
//! prompt_channel handler pattern (`crates/sentinel-daemon/src/handlers/prompt_channel.rs`).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use sentinel_ipc::{
    IPC_SCHEMA_V3, PromptCancel, PromptChannelInit, PromptChannelInitAck, PromptRequest,
    PromptResponse,
};

use crate::CliError;
use crate::ipc_client::TAG_PROMPT_CHANNEL_INIT;

/// Channel-internal frame (CLI → daemon direction).
#[derive(Serialize, Deserialize)]
#[serde(tag = "frame_kind", rename_all = "snake_case")]
pub enum ClientChannelFrame {
    Response(PromptResponse),
    Cancel(PromptCancel),
}

/// In-flight prompt-id registry shared between the render-loop thread and the
/// SIGINT handler (plan 03-13 BLOCKER #1).
#[derive(Clone, Default)]
pub struct InflightPrompts(pub Arc<Mutex<HashSet<String>>>);

/// Reader half handed out by `PromptChannel::take_reader`. Owned exclusively
/// by the render thread; never shared, never locked. Holds the inflight
/// registry so it can record prompt_ids as they arrive — symmetric with the
/// writer half's removal on answer/cancel.
pub struct PromptReader {
    stream: UnixStream,
    inflight: InflightPrompts,
}

/// Owning handle returned by `PromptChannel::open`. After construction, the
/// caller takes the reader out via `take_reader` and stores the remaining
/// `PromptChannel` (the writer half) inside the SharedChannel mutex used by
/// the SIGINT handler. The writer half ALSO supports `answer` for the render
/// thread; the render thread acquires the outer SharedChannel mutex briefly
/// to send the user's response, but never while the read half is parked.
pub struct PromptChannel {
    /// Reader is `take`-d once into a `PromptReader` and moved to the render
    /// thread. After takeout, this is None and `next_prompt` returns an error.
    /// Pre-takeout, this allows the legacy single-handle code path used in
    /// tests where only one thread drives the channel.
    reader: Option<UnixStream>,
    /// Writer half — used by `answer` and `cancel`. Shared between the render
    /// thread and the SIGINT handler via the outer `Arc<Mutex<Option<…>>>`.
    /// Cloned via `try_clone` from the same socket as `reader`; the kernel
    /// handles the half-duplex synchronization so reads and writes are
    /// independent.
    writer: UnixStream,
    pub run_uuid: String,
    inflight: InflightPrompts,
}

impl PromptChannel {
    /// Open a long-lived prompt channel tied to `run_uuid`.
    /// Called immediately after PrepareSnapshot on V3 + is_tty=true.
    pub fn open(sock: &Path, run_uuid: &str) -> Result<Self, CliError> {
        let mut stream = crate::ipc_client::connect_with_timeout(sock)?;
        stream
            .write_all(&[TAG_PROMPT_CHANNEL_INIT])
            .map_err(|e| CliError::DaemonUnreachable(format!("tag write: {e}")))?;
        sentinel_ipc::frame::write_frame(
            &mut stream,
            &PromptChannelInit {
                schema_version: IPC_SCHEMA_V3,
                run_uuid: run_uuid.to_string(),
            },
        )
        .map_err(|e| CliError::DaemonUnreachable(format!("write init: {e}")))?;
        let mut tag_back = [0u8; 1];
        stream
            .read_exact(&mut tag_back)
            .map_err(|e| CliError::DaemonUnreachable(format!("read tag echo: {e}")))?;
        if tag_back[0] != TAG_PROMPT_CHANNEL_INIT {
            return Err(CliError::DaemonUnreachable(format!(
                "tag mismatch: got 0x{:02x}",
                tag_back[0]
            )));
        }
        let ack: PromptChannelInitAck = sentinel_ipc::frame::read_frame(&mut stream)
            .map_err(|e| CliError::DaemonUnreachable(format!("read ack: {e}")))?;
        match ack {
            PromptChannelInitAck::Ok { .. } => {}
            PromptChannelInitAck::Err { message, .. } => {
                return Err(CliError::Other(format!("PromptChannelInit Err: {message}")));
            }
        }
        // Remove timeouts — the channel is long-lived (D-47).
        let _ = stream.set_read_timeout(None);
        let _ = stream.set_write_timeout(None);
        // CR-02: split the stream so the blocking read half doesn't hold a lock
        // the SIGINT handler needs. `try_clone` duplicates the underlying fd —
        // both halves point at the same kernel socket; the kernel handles the
        // half-duplex synchronization for us (reads and writes are independent).
        let writer_stream = stream
            .try_clone()
            .map_err(|e| CliError::DaemonUnreachable(format!("try_clone: {e}")))?;
        Ok(Self {
            reader: Some(stream),
            writer: writer_stream,
            run_uuid: run_uuid.to_string(),
            inflight: InflightPrompts::default(),
        })
    }

    /// Returns a clone of the shared in-flight prompt-id registry. The SIGINT
    /// handler (plan 03-13) takes a snapshot of this set on Ctrl-C and sends
    /// a PromptCancel frame for each.
    pub fn inflight_handle(&self) -> InflightPrompts {
        self.inflight.clone()
    }

    /// CR-02: take the reader half out of the channel so the render thread can
    /// drive blocking reads WITHOUT holding the SharedChannel mutex. After
    /// this call the channel still holds the writer half (used by `answer`
    /// from the render thread and `cancel` from the SIGINT handler).
    /// Returns None if the reader has already been taken.
    pub fn take_reader(&mut self) -> Option<PromptReader> {
        let stream = self.reader.take()?;
        Some(PromptReader {
            stream,
            inflight: self.inflight.clone(),
        })
    }

    /// Block until the daemon sends a PromptRequest on the channel.
    /// Records the prompt_id in the in-flight registry.
    ///
    /// Pre-CR-02 callers can still use this when they own the channel
    /// exclusively (single-thread tests). Production callers should
    /// `take_reader()` once and call `PromptReader::next_prompt` from the
    /// render thread without holding the SharedChannel lock.
    pub fn next_prompt(&mut self) -> Result<PromptRequest, CliError> {
        let stream = self.reader.as_mut().ok_or_else(|| {
            CliError::Other("PromptChannel::next_prompt called after take_reader".into())
        })?;
        let req: PromptRequest = sentinel_ipc::frame::read_frame(stream)
            .map_err(|e| CliError::DaemonUnreachable(format!("read PromptRequest: {e}")))?;
        if let Ok(mut g) = self.inflight.0.lock() {
            g.insert(req.prompt_id.clone());
        }
        Ok(req)
    }

    /// Send the user's response back to the daemon. Removes the prompt_id from in-flight.
    pub fn answer(&mut self, resp: PromptResponse) -> Result<(), CliError> {
        let prompt_id = resp.prompt_id.clone();
        let result =
            sentinel_ipc::frame::write_frame(&mut self.writer, &ClientChannelFrame::Response(resp))
                .map_err(|e| CliError::DaemonUnreachable(format!("write response: {e}")));
        if let Ok(mut g) = self.inflight.0.lock() {
            g.remove(&prompt_id);
        }
        result
    }

    /// Send a PromptCancel for the given prompt_id (used by SIGINT handler).
    pub fn cancel(&mut self, prompt_id: &str) -> Result<(), CliError> {
        let frame = ClientChannelFrame::Cancel(PromptCancel {
            schema_version: IPC_SCHEMA_V3,
            prompt_id: prompt_id.to_string(),
        });
        let result = sentinel_ipc::frame::write_frame(&mut self.writer, &frame)
            .map_err(|e| CliError::DaemonUnreachable(format!("write cancel: {e}")));
        if let Ok(mut g) = self.inflight.0.lock() {
            g.remove(prompt_id);
        }
        result
    }
}

impl PromptReader {
    /// Clone the underlying socket so the orchestrator can interrupt a blocked
    /// `next_prompt` during run teardown.
    pub fn shutdown_handle(&self) -> Result<UnixStream, CliError> {
        self.stream
            .try_clone()
            .map_err(|e| CliError::DaemonUnreachable(format!("try_clone prompt reader: {e}")))
    }

    pub fn shutdown(stream: &UnixStream) {
        let _ = stream.shutdown(Shutdown::Both);
    }

    /// Block until the daemon sends a PromptRequest. CR-02: this is the
    /// production read entry point — the render thread owns the `PromptReader`
    /// and calls this without holding the SharedChannel mutex, so a concurrent
    /// SIGINT handler can acquire the SharedChannel mutex to call `cancel` on
    /// the writer half.
    pub fn next_prompt(&mut self) -> Result<PromptRequest, CliError> {
        let req: PromptRequest = sentinel_ipc::frame::read_frame(&mut self.stream)
            .map_err(|e| CliError::DaemonUnreachable(format!("read PromptRequest: {e}")))?;
        if let Ok(mut g) = self.inflight.0.lock() {
            g.insert(req.prompt_id.clone());
        }
        Ok(req)
    }
}
