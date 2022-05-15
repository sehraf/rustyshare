use log::{debug, trace, warn};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::UnboundedSender, Mutex};

use retroshare_compat::{basics::SslId, events::EventType, gxs::GroupMetaData};

use crate::{parser::Packet, retroshare_compat::ssl_key::SslKey};

use self::{gxs::Gxs, intercom::Intercom, location::Location, person::Peer};

pub mod gxs;
pub mod intercom;
pub mod location;
pub mod person;

pub struct ConnectedPeerEntries(
    pub HashMap<Arc<SslId>, (UnboundedSender<Intercom>, tokio::task::JoinHandle<()>)>,
);

impl Default for ConnectedPeerEntries {
    fn default() -> Self {
        ConnectedPeerEntries(HashMap::new())
    }
}

pub struct DataCore {
    own_key_pair: SslKey,
    own_location: Arc<Location>,

    pub event_listener: Mutex<Vec<UnboundedSender<Intercom>>>,
    webui_clients: Mutex<Vec<UnboundedSender<Value>>>,

    peers: Vec<Arc<Peer>>,
    locations: Vec<Arc<Location>>,

    gxs: Vec<Mutex<Gxs>>,

    connected_peers: Mutex<ConnectedPeerEntries>,
}

impl DataCore {
    pub fn new(
        keys: SslKey,
        friends: (Vec<Arc<Peer>>, Vec<Arc<Location>>),
        peer_id: Arc<SslId>,
        gxs: Vec<Gxs>,
    ) -> Arc<DataCore> {
        // let pos = friends
        //     .1
        //     .iter()
        //     .position(|loc| loc.get_location_id() == peer_id)
        //     .expect("can't find own location!");
        // let me = friends.1.remove(pos);
        let me = friends
            .1
            .iter()
            .find(|loc| loc.get_location_id() == peer_id)
            .expect("can't find own location!");

        Arc::new(DataCore {
            own_key_pair: keys,
            own_location: me.clone(),

            peers: friends.0,
            locations: friends.1,

            event_listener: Mutex::new(vec![]),
            webui_clients: Mutex::new(vec![]),

            gxs: gxs.into_iter().map(|g| Mutex::new(g)).collect(),

            connected_peers: Mutex::new(ConnectedPeerEntries::default()),
        })
    }

    pub fn get_own_location(&self) -> Arc<Location> {
        self.own_location.clone()
    }

    pub fn get_own_person(&self) -> Arc<Peer> {
        // used stored location for O(1) lookup of own person
        self.own_location.get_person()
    }

    // #[allow(dead_code)]
    pub fn get_own_keypair(&self) -> &SslKey {
        &self.own_key_pair
    }

    pub fn get_locations(&self) -> Vec<Arc<Location>> {
        self.locations.clone()
    }

    pub fn get_location_by_id(&self, ssl_id: Arc<SslId>) -> Option<Arc<Location>> {
        self.get_locations()
            .into_iter()
            .find(|loc| loc.get_location_id() == ssl_id)
    }

    pub fn get_persons(&self) -> Vec<Arc<Peer>> {
        self.peers.clone()
    }

    pub async fn events_subscribe(&self, receiver: UnboundedSender<Intercom>) {
        self.event_listener.lock().await.push(receiver);
    }

    pub async fn is_online(&self, peer_id: Arc<SslId>) -> bool {
        self.connected_peers.lock().await.0.contains_key(&peer_id)
    }

    pub fn get_connected_peers(&self) -> &Mutex<ConnectedPeerEntries> {
        &self.connected_peers
    }

    pub async fn try_send_to_peer(&self, packet: Packet) {
        // lock peers once

        if packet.has_location() {
            debug!("sending to peer {}", packet.peer_id());
            self.send_to_peer(packet).await;
        } else {
            debug!("sending to <all>");
            for peer in &self.connected_peers.lock().await.0 {
                let mut item = packet.to_owned();
                item.peer_id = peer.0.to_owned();
                peer.1 .0.send(Intercom::Send(item)).unwrap_or_else(|_| {
                    warn!("[core] failed to send to peer worker");
                });
            }
        }
    }

    async fn send_to_peer(&self, packet: Packet) {
        assert!(packet.has_location());

        let to = packet.peer_id.clone();

        self.connected_peers
            .lock()
            .await
            .0
            .entry(to)
            .and_modify(|(tx, _)| {
                tx.send(Intercom::Send(packet)).unwrap_or_else(|_| {
                    warn!("[core] failed to send to peer worker");
                })
            });
    }

    pub async fn webui_add_client(&self, tx: UnboundedSender<Value>) {
        trace!("webui_add_client");

        tx.send(json!({
            "retval":{
                "errorNumber":0,
                "errorCategory":"generic",
                "errorMessage":"Success"
            }
        }))
        .expect("failed to send");
        self.webui_clients.lock().await.push(tx);
    }

    pub async fn webui_send(&self, event: EventType) {
        trace!("webui_send");

        let msg: Value = event.into();

        let mut ok_clients = Vec::new();
        for client in self.webui_clients.lock().await.iter() {
            let result = client.send(msg.to_owned());

            if let Ok(()) = result {
                ok_clients.push(client.to_owned());
            }
        }
        *self.webui_clients.lock().await = ok_clients;
    }

    pub async fn get_identities_summaries(&self) -> Vec<GroupMetaData> {
        self.gxs
            .first()
            .unwrap()
            .lock()
            .await
            .get_meta()
            .into_iter()
            .map(|x| x.into())
            .collect()
    }
}
