//! crates/sentinel-cli/src/prompt_channel.rs
//!
//! Phase 3 plan 03-12 — long-lived channel client with in-flight prompt tracking.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use sentinel_ipc::{
    IPC_SCHEMA_V3, PromptCancel, PromptChannelInit, PromptChannelInitAck,
    PromptRequest, PromptResponse,
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

pub struct PromptChannel {
    stream: UnixStream,
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
                return Err(CliError::Other(format!(
                    "PromptChannelInit Err: {message}"
                )));
            }
        }
        // Remove timeouts — the channel is long-lived (D-47).
        let _ = stream.set_read_timeout(None);
        let _ = stream.set_write_timeout(None);
        Ok(Self {
            stream,
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

    /// Block until the daemon sends a PromptRequest on the channel.
    /// Records the prompt_id in the in-flight registry.
    pub fn next_prompt(&mut self) -> Result<PromptRequest, CliError> {
        let req: PromptRequest = sentinel_ipc::frame::read_frame(&mut self.stream)
            .map_err(|e| CliError::DaemonUnreachable(format!("read PromptRequest: {e}")))?;
        if let Ok(mut g) = self.inflight.0.lock() {
            g.insert(req.prompt_id.clone());
        }
        Ok(req)
    }

    /// Send the user's response back to the daemon. Removes the prompt_id from in-flight.
    pub fn answer(&mut self, resp: PromptResponse) -> Result<(), CliError> {
        let prompt_id = resp.prompt_id.clone();
        let result = sentinel_ipc::frame::write_frame(
            &mut self.stream,
            &ClientChannelFrame::Response(resp),
        )
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
        let result = sentinel_ipc::frame::write_frame(&mut self.stream, &frame)
            .map_err(|e| CliError::DaemonUnreachable(format!("write cancel: {e}")));
        if let Ok(mut g) = self.inflight.0.lock() {
            g.remove(prompt_id);
        }
        result
    }
}
