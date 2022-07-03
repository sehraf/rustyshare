use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use headers::*;
use retroshare_compat::basics::*;

pub mod headers;
pub mod parser_network;

#[derive(Clone, Debug)]
pub struct PacketInner {
    pub header: Header,
    pub payload: Vec<u8>,
    pub peer_id: Arc<SslId>,
}

/// Wraps a `PacketInner` in a `Box` to ensure heap usage
#[derive(Debug)]
pub struct Packet(Box<PacketInner>);

// impl PacketInner {
impl Packet {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(&self.header.to_bytes());
        data.extend(self.payload.iter());
        data
    }

    pub fn peer_id(&self) -> &Arc<SslId> {
        &self.peer_id
    }
}

impl Packet {
    pub fn new(header: Header, payload: Vec<u8>, loc: Arc<SslId>) -> Packet {
        Packet(Box::new(PacketInner {
            header,
            payload,
            peer_id: loc,
        }))
    }

    pub fn new_without_location(header: Header, payload: Vec<u8>) -> Packet {
        Packet::new(header, payload, Arc::new(SslId::default()))
    }

    /// Used to enforce proper meta data handling.
    ///
    /// The core mostly uses this to ensure that it is known from where packets come and where they need to go.
    pub fn has_location(&self) -> bool {
        *self.peer_id != SslId::default()
    }
}

impl Deref for Packet {
    type Target = PacketInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Packet {
    // type Target = PacketInner;
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// TODO come up with a better way to handle this
impl Clone for Packet {
    fn clone(&self) -> Self {
        Packet(Box::new(self.deref().clone()))
    }
}

impl AsRef<PacketInner> for Packet {
    fn as_ref(&self) -> &PacketInner {
        &self.0
    }
}