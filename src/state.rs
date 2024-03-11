use crate::traffic::Traffic;

use indexmap::IndexMap;
use serde::Serialize;
use std::sync::Mutex;
use tokio::sync::broadcast;

#[derive(Debug)]
pub(crate) struct State {
    entries: Mutex<IndexMap<usize, Traffic>>,
    tx: broadcast::Sender<Head>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Head {
    id: usize,
    method: String,
    uri: String,
    status: Option<u16>,
}

impl State {
    pub(crate) fn new() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            entries: Mutex::new(IndexMap::new()),
            tx,
        }
    }

    pub(crate) fn add_traffic(&self, traffic: Traffic) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let id = entries.len() + 1;
        let head = Head::new(id, &traffic);
        entries.insert(id, traffic);
        let _ = self.tx.send(head);
    }

    pub(crate) fn get_traffic(&self, id: usize) -> Option<Traffic> {
        let entries = self.entries.lock().ok()?;
        entries.get(&id).cloned()
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Head> {
        self.tx.subscribe()
    }

    pub(crate) fn list(&self) -> Vec<Head> {
        let Ok(entries) = self.entries.lock() else {
            return vec![];
        };
        entries
            .iter()
            .map(|(id, traffic)| Head::new(*id, traffic))
            .collect()
    }
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
