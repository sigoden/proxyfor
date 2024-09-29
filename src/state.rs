use crate::{
    server::PrintMode,
    traffic::{wrap_entries, Body, Traffic, TrafficHead},
};

use anyhow::{bail, Result};
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use tokio::{sync::broadcast, sync::Mutex};
use tokio_tungstenite::tungstenite;

#[derive(Debug)]
pub struct State {
    print_mode: PrintMode,
    traffics: Mutex<IndexMap<usize, Traffic>>,
    traffics_notifier: broadcast::Sender<TrafficHead>,
    websockets: Mutex<IndexMap<usize, Vec<WebsocketMessage>>>,
    websockets_notifier: broadcast::Sender<(usize, WebsocketMessage)>,
}

impl State {
    pub fn new(print_mode: PrintMode) -> Self {
        let (traffics_notifier, _) = broadcast::channel(16);
        let (websockets_notifier, _) = broadcast::channel(64);
        Self {
            print_mode,
            traffics: Default::default(),
            traffics_notifier,
            websockets: Default::default(),
            websockets_notifier,
        }
    }

    pub async fn add_traffic(&self, traffic: Traffic) {
        if !traffic.valid {
            return;
        }
        let mut traffics = self.traffics.lock().await;
        let id = traffics.len() + 1;
        let head = traffic.head(id);
        traffics.insert(id, traffic);
        let _ = self.traffics_notifier.send(head);
    }

    pub async fn done_traffic(&self, gid: usize, raw_size: u64) {
        let mut traffics = self.traffics.lock().await;
        let Some((id, traffic)) = traffics.iter_mut().find(|(_, v)| v.gid == gid) else {
            return;
        };

        let head = traffic.done_res_body(*id, raw_size);
        let _ = self.traffics_notifier.send(head);
        match self.print_mode {
            PrintMode::Nothing => {}
            PrintMode::Oneline => {
                println!("# {}", traffic.oneline());
            }
            PrintMode::Markdown => {
                println!("{}", traffic.markdown().await);
            }
        }
    }

    pub async fn get_traffic(&self, id: usize) -> Option<Traffic> {
        let traffics = self.traffics.lock().await;
        traffics.get(&id).cloned()
    }

    pub fn subscribe_traffics(&self) -> broadcast::Receiver<TrafficHead> {
        self.traffics_notifier.subscribe()
    }

    pub async fn list_heads(&self) -> Vec<TrafficHead> {
        let traffics = self.traffics.lock().await;
        traffics
            .iter()
            .map(|(id, traffic)| traffic.head(*id))
            .collect()
    }

    pub async fn export_traffics(&self, format: &str) -> Result<(String, &'static str)> {
        let traffics = self.traffics.lock().await;
        match format {
            "markdown" => {
                let output =
                    futures_util::future::join_all(traffics.iter().map(|(_, v)| v.markdown()))
                        .await
                        .into_iter()
                        .collect::<Vec<String>>()
                        .join("\n\n");
                Ok((output, "text/markdown; charset=UTF-8"))
            }
            "har" => {
                let values: Vec<Value> =
                    futures_util::future::join_all(traffics.iter().map(|(_, v)| v.har_entry()))
                        .await
                        .into_iter()
                        .flatten()
                        .collect();
                let json_output = wrap_entries(values);
                let output = serde_json::to_string_pretty(&json_output)?;
                Ok((output, "application/json; charset=UTF-8"))
            }
            "curl" => {
                let output = futures_util::future::join_all(traffics.iter().map(|(_, v)| v.curl()))
                    .await
                    .into_iter()
                    .collect::<Vec<String>>()
                    .join("\n\n");
                Ok((output, "text/plain; charset=UTF-8"))
            }
            "mem" => {
                let values = futures_util::future::join_all(traffics.iter().map(|(_, v)| v.json()))
                    .await
                    .into_iter()
                    .collect::<Vec<Value>>();
                let output = serde_json::to_string_pretty(&values)?;
                Ok((output, "application/json; charset=UTF-8"))
            }
            "" => {
                let values = traffics
                    .iter()
                    .map(|(id, traffic)| traffic.head(*id))
                    .collect::<Vec<TrafficHead>>();
                let output = serde_json::to_string_pretty(&values)?;
                Ok((output, "application/json; charset=UTF-8"))
            }
            _ => bail!("Unsupported format: {}", format),
        }
    }

    pub async fn new_websocket(&self) -> usize {
        let mut websockets = self.websockets.lock().await;
        let id = websockets.len() + 1;
        websockets.insert(id, vec![]);
        id
    }

    pub async fn add_websocket_error(&self, id: usize, error: String) {
        let mut websockets = self.websockets.lock().await;
        let Some(messages) = websockets.get_mut(&id) else {
            return;
        };
        let message = WebsocketMessage::Error(error);
        messages.push(message.clone());
        let _ = self.websockets_notifier.send((id, message));
    }

    pub async fn add_websocket_message(
        &self,
        id: usize,
        message: &tungstenite::Message,
        server_to_client: bool,
    ) {
        let mut websockets = self.websockets.lock().await;
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

    pub async fn subscribe_websocket(&self, id: usize) -> Option<SubscribeWebSocket> {
        let websockets = self.websockets.lock().await;
        let messages = websockets.get(&id)?;
        Some((messages.to_vec(), self.websockets_notifier.subscribe()))
    }
}

pub type SubscribeWebSocket = (
    Vec<WebsocketMessage>,
    broadcast::Receiver<(usize, WebsocketMessage)>,
);

#[derive(Debug, Clone, Serialize)]
pub enum WebsocketMessage {
    #[serde(rename = "error")]
    Error(String),
    #[serde(rename = "data")]
    Data(WebsocketData),
}

#[derive(Debug, Clone, Serialize)]
pub struct WebsocketData {
    #[serde(serialize_with = "crate::traffic::serialize_datetime")]
    create: OffsetDateTime,
    server_to_client: bool,
    body: Body,
}
