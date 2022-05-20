use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use headers::*;
use log::{trace, warn};
use retroshare_compat::basics::*;

use crate::services::ServiceType;

pub mod headers;

const SLICE_FLAG_START_BIT: u8 = 1 << 0;
const SLICE_FLAG_END_BIT: u8 = 1 << 1;
const SLICE_ID_MAX_VALUE: u32 = 1 << 24; // this value is taken from RetroShare
const SLICE_PREFERED_PACKET_SIZE: usize = 512;

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

struct SlicePacket {
    slice_packet_id: u32,
    payload: Vec<u8>,
}

pub struct Parser {
    incoming_partial_store: Vec<SlicePacket>,
    next_id: u32,
    location: Arc<SslId>,
}

impl Parser {
    pub fn new(location: Arc<SslId>) -> Parser {
        Parser {
            incoming_partial_store: vec![],
            next_id: 0,
            location,
        }
    }

    fn add_slice(
        &mut self,
        slice_packet_id: u32,
        partial_flags: u8,
        payload: &mut Vec<u8>,
    ) -> Option<Packet> {
        let mut is_new = false;
        let found = self.get_slice_by_id(slice_packet_id).is_some();

        // check for start
        if (partial_flags & SLICE_FLAG_START_BIT) != 0 {
            // start
            if found {
                // found existing?!
                warn!(
                    "found existing packet with id {} but 'start' flag is set",
                    slice_packet_id
                );
            } else {
                // start -> create new
                is_new = true;
                self.incoming_partial_store.push(SlicePacket {
                    slice_packet_id,
                    payload: vec![],
                });
            };
        }
        let slice = self
            .get_slice_by_id(slice_packet_id)
            .expect("failed to find slice data, this is weird!");

        // append new data
        slice.payload.append(payload);

        if (partial_flags & SLICE_FLAG_END_BIT) != 0 {
            // end
            if is_new {
                // end should never be also start
                warn!(
                    "can't find packet with id {} but 'end' flag is set",
                    slice.slice_packet_id
                );
            }

            // handle finished packet
            let mut header: [u8; 8] = [0; 8];
            header.copy_from_slice(&slice.payload[0..8]);
            let header = match Header::try_parse(&header) {
                Ok(h) => h,
                _ => {
                    warn!("failed to parse header from finished slice!");
                    self.remove_slice_by_id(slice_packet_id);
                    return None;
                }
            };

            // extract payload
            let payload: Vec<u8> = slice.payload.drain(8..).collect();

            // remove packet from index
            self.remove_slice_by_id(slice_packet_id);

            // last sanity check
            assert_eq!(payload.len(), header.get_payload_size());
            return self.handle_incoming_packet(header, payload);
        }
        None
    }

    fn get_slice_by_id(&mut self, slice_packet_id: u32) -> Option<&mut SlicePacket> {
        self.incoming_partial_store
            .iter_mut()
            .find(|ps| ps.slice_packet_id == slice_packet_id)
    }

    fn remove_slice_by_id(&mut self, slice_packet_id: u32) {
        let index = self
            .incoming_partial_store
            .iter()
            .position(|ps| ps.slice_packet_id == slice_packet_id)
            .expect("failed to find slice data, this is weird!");
        self.incoming_partial_store.remove(index);
    }

    pub fn handle_incoming_packet(&mut self, header: Header, payload: Vec<u8>) -> Option<Packet> {
        trace!("handling packet {:?}: {:02X?}", header, payload);
        match header {
            Header::Service {
                service, sub_type, ..
            } => {
                // got Item
                trace!("item");

                if service == ServiceType::SliceProbe {
                    // silently drop slice probing packets
                    assert_eq!(sub_type, 0xcc);
                    return None;
                }

                let packet = Packet::new(header, payload, self.location.clone());

                return Some(packet);
            }
            Header::Slice {
                slice_packet_id,
                partial_flags,
                ..
            } => {
                // got Slice
                trace!("slice");

                let mut payload = payload;
                return self.add_slice(slice_packet_id, partial_flags, &mut payload);
            }
            // Header::Class {..} =>
            _ => {
                warn!("unsupported header! {:?}", header);
                return None;
            }
        }
        // None
    }

    fn get_next_slice_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        if self.next_id > SLICE_ID_MAX_VALUE {
            self.next_id = 0;
        }
        id
    }

    pub fn handle_outgoign_packet(&mut self, mut packet: Packet) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = vec![];

        // for easier access
        let packet_size = packet.payload.len();

        // simple case: packet fits into the desired size, no splitting necessary
        if packet_size + headers::HEADER_SIZE < SLICE_PREFERED_PACKET_SIZE {
            out.push(packet.to_bytes());
        } else {
            // packet is too large, split it
            let packet_size_first = SLICE_PREFERED_PACKET_SIZE - headers::HEADER_SIZE; // slice header
            let payload_size_first =
                SLICE_PREFERED_PACKET_SIZE - headers::HEADER_SIZE - headers::HEADER_SIZE; // slice header + packet header
            let mut data: Vec<u8> = vec![];
            let slice_id = self.get_next_slice_id();

            // create first starting packet
            let header = Header::Slice {
                partial_flags: SLICE_FLAG_START_BIT,
                size: packet_size_first as u16,
                slice_packet_id: slice_id,
            };

            // write slice header
            data.extend_from_slice(&header.to_bytes());
            // write packet header
            data.extend_from_slice(&packet.header.to_bytes());
            // write payload
            data.append(&mut packet.payload.drain(..payload_size_first).collect());

            assert_eq!(&data.len(), &SLICE_PREFERED_PACKET_SIZE);
            out.push(data);

            // now handle the remaining data
            while packet.payload.len() > SLICE_PREFERED_PACKET_SIZE - headers::HEADER_SIZE {
                let mut data: Vec<u8> = vec![];
                let payload_size_middle = SLICE_PREFERED_PACKET_SIZE - headers::HEADER_SIZE; // slice header

                // create middle header
                let header = Header::Slice {
                    partial_flags: 0,
                    size: (SLICE_PREFERED_PACKET_SIZE - headers::HEADER_SIZE) as u16,
                    slice_packet_id: slice_id,
                };
                // write packet header
                data.extend_from_slice(&header.to_bytes());
                // write payload
                data.append(&mut packet.payload.drain(..payload_size_middle).collect());

                assert_eq!(&data.len(), &SLICE_PREFERED_PACKET_SIZE);
                out.push(data);
            }

            let mut data: Vec<u8> = vec![];

            // handle end
            let header = Header::Slice {
                partial_flags: SLICE_FLAG_END_BIT,
                size: packet.payload.len() as u16,
                slice_packet_id: slice_id,
            };
            // write packet header
            data.extend_from_slice(&header.to_bytes());
            // write payload
            data.append(&mut packet.payload.drain(..).collect());

            assert!(&data.len() <= &SLICE_PREFERED_PACKET_SIZE);
            out.push(data);
        }

        out
    }
}
