use crate::traffic::{Body, Traffic};

use indexmap::IndexMap;
use serde::Serialize;
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
        let head = Head::new(id, &traffic);
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

    pub(crate) fn list(&self) -> Vec<Head> {
        let Ok(entries) = self.traffics.lock() else {
            return vec![];
        };
        entries
            .iter()
            .map(|(id, traffic)| Head::new(*id, traffic))
            .collect()
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
        let Ok(websockets) = self.websockets.lock() else {
            return None;
        };
        let Some(messages) = websockets.get(&id) else {
            return None;
        };
        Some((messages.to_vec(), self.websockets_notifier.subscribe()))
    }
}

pub(crate) type SubscribeWebSocket = (
    Vec<WebsocketMessage>,
    broadcast::Receiver<(usize, WebsocketMessage)>,
);

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Head {
    id: usize,
    method: String,
    uri: String,
    status: Option<u16>,
}

impl Head {
    pub(crate) fn new(id: usize, traffic: &Traffic) -> Self {
        let (method, uri, status) = traffic.head();
        Self {
            id,
            method: method.to_string(),
            uri: uri.to_string(),
            status,
        }
    }
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
