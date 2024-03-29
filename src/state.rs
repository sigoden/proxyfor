use crate::traffic::{wrap_entries, Body, Traffic};

use anyhow::{anyhow, bail, Result};
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::Value;
use std::sync::Mutex;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite;

#[derive(Debug)]
pub(crate) struct State {
    traffics: Mutex<IndexMap<usize, Traffic>>,
    traffics_notifier: broadcast::Sender<Head>,
    websockets: Mutex<IndexMap<usize, Vec<WebsocketMessage>>>,
    websockets_notifier: broadcast::Sender<(usize, WebsocketMessage)>,
}

impl State {
    pub(crate) fn new() -> Self {
        let (traffics_notifier, _) = broadcast::channel(16);
        let (websockets_notifier, _) = broadcast::channel(64);
        Self {
            traffics: Default::default(),
            traffics_notifier,
            websockets: Default::default(),
            websockets_notifier,
        }
    }

    pub(crate) fn add_traffic(&self, traffic: Traffic) {
        let Ok(mut traffics) = self.traffics.lock() else {
            return;
        };
        let id = traffics.len() + 1;
        let head = traffic.head(id);
        traffics.insert(id, traffic);
        let _ = self.traffics_notifier.send(head);
    }

    pub(crate) fn get_traffic(&self, id: usize) -> Option<Traffic> {
        let entries = self.traffics.lock().ok()?;
        entries.get(&id).cloned()
    }

    pub(crate) fn subscribe_traffics(&self) -> broadcast::Receiver<Head> {
        self.traffics_notifier.subscribe()
    }

    pub(crate) fn list_heads(&self) -> Vec<Head> {
        let Ok(entries) = self.traffics.lock() else {
            return vec![];
        };
        entries
            .iter()
            .map(|(id, traffic)| traffic.head(*id))
            .collect()
    }

    pub(crate) fn export_traffics(&self, format: &str) -> Result<(String, &'static str)> {
        let entries = self.traffics.lock().map_err(|err| anyhow!("{err}"))?;
        match format {
            "markdown" => {
                let output = entries
                    .values()
                    .map(|v| v.markdown(false))
                    .collect::<Vec<String>>()
                    .join("\n\n");
                Ok((output, "text/markdown; charset=UTF-8"))
            }
            "har" => {
                let entries: Vec<Value> = entries.values().filter_map(|v| v.har_entry()).collect();
                let json_output = wrap_entries(entries);
                let output = serde_json::to_string_pretty(&json_output)?;
                Ok((output, "application/json; charset=UTF-8"))
            }
            "curl" => {
                let output = entries
                    .values()
                    .map(|v| v.curl())
                    .collect::<Vec<String>>()
                    .join("\n\n");
                Ok((output, "text/plain; charset=UTF-8"))
            }
            "mem" => {
                let traffics: Vec<&Traffic> = entries.values().collect();
                let output = serde_json::to_string_pretty(&traffics)?;
                Ok((output, "application/json; charset=UTF-8"))
            }
            _ => bail!("Unsupported format: {}", format),
        }
    }

    pub(crate) fn new_websocket(&self) -> Option<usize> {
        let Ok(mut websockets) = self.websockets.lock() else {
            return None;
        };
        let id = websockets.len() + 1;
        websockets.insert(id, vec![]);
        Some(id)
    }

    pub(crate) fn add_websocket_error(&self, id: usize, error: String) {
        let Ok(mut websockets) = self.websockets.lock() else {
            return;
        };
        let Some(messages) = websockets.get_mut(&id) else {
            return;
        };
        let message = WebsocketMessage::Error(error);
        messages.push(message.clone());
        let _ = self.websockets_notifier.send((id, message));
    }

    pub(crate) fn add_websocket_message(
        &self,
        id: usize,
        message: &tungstenite::Message,
        server_to_client: bool,
    ) {
        let Ok(mut websockets) = self.websockets.lock() else {
            return;
        };
        let Some(messages) = websockets.get_mut(&id) else {
            return;
        };
        let body = match message {
            tungstenite::Message::Text(text) => Body::text(text),
            tungstenite::Message::Binary(bin) => Body::bytes(bin),
            _ => return,
        };
        let message = WebsocketMessage::Data(WebsocketData {
            create: OffsetDateTime::now_utc(),
            server_to_client,
            body,
        });
        messages.push(message.clone());
        let _ = self.websockets_notifier.send((id, message));
    }

    pub(crate) fn subscribe_websocket(&self, id: usize) -> Option<SubscribeWebSocket> {
        let websockets = self.websockets.lock().ok()?;
        let messages = websockets.get(&id)?;
        Some((messages.to_vec(), self.websockets_notifier.subscribe()))
    }
}

pub(crate) type SubscribeWebSocket = (
    Vec<WebsocketMessage>,
    broadcast::Receiver<(usize, WebsocketMessage)>,
);

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Head {
    pub(crate) id: usize,
    pub(crate) method: String,
    pub(crate) uri: String,
    pub(crate) status: Option<u16>,
    pub(crate) size: Option<usize>,
    pub(crate) time: Option<usize>,
    pub(crate) mime: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) enum WebsocketMessage {
    #[serde(rename = "error")]
    Error(String),
    #[serde(rename = "data")]
    Data(WebsocketData),
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WebsocketData {
    #[serde(serialize_with = "crate::traffic::serialize_datetime")]
    create: OffsetDateTime,
    server_to_client: bool,
    body: Body,
}
