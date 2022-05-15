use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use retroshare_compat::{
    basics::SslId, events::EventType, services::service_info::RsServiceInfo, tlv::TlvIpAddressInfo,
};
use tokio::net::TcpStream;

use crate::parser::Packet;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Intercom {
    Event(EventType),
    PeerUpdate(PeerUpdate),
    Receive(Packet),
    ServiceInfoUpdate(Vec<RsServiceInfo>),
    Send(Packet),
    Thread(PeerThreadCommand),
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum PeerThreadCommand {
    Incoming(TcpStream),
    Start,
    Stop,
    TryConnect,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum PeerUpdate {
    Status(PeerState),
    Address(
        Arc<SslId>,
        HashSet<TlvIpAddressInfo>,
        HashSet<TlvIpAddressInfo>,
    ),
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum PeerState {
    Connected(Arc<SslId>, SocketAddr),
    NotConnected(Arc<SslId>),
}
