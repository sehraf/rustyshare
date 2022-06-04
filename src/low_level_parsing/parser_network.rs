use std::sync::Arc;

use log::{trace, warn};
use retroshare_compat::{basics::SslId, services::ServiceType};

use crate::low_level_parsing::{headers::Header, Packet};

use super::headers::HEADER_SIZE;

const SLICE_FLAG_START_BIT: u8 = 1 << 0;
const SLICE_FLAG_END_BIT: u8 = 1 << 1;
const SLICE_ID_MAX_VALUE: u32 = 1 << 24; // this value is taken from RetroShare
const SLICE_PREFERED_PACKET_SIZE: usize = 512;

/// SlicePacket
///
/// RetroShare slices larger packets up into smaller ones. The prefered size is 512 bytes.
/// When a packet (ready to be sent - in other words, with a proper header) is larger, it is split up
/// and each part is wrapped into a slice packet.
///
/// A slice packet has the header type `0x10`, contains a flag, packet id an (payload) size.
/// The flag indicates if this packet is start `0x01` or end packet `0x02` (packet inbetween have the flag `0x00`).
/// The packet id identifies slices belonging to the same packet. Ordering is ensured by TCP, there
/// is no other order mechanism inside the slice packet.
/// Finally, the (payload) size indicates how much data the *one* slice contains. (Its main purpose is
/// to calculate the size of the whole slice packet (contrary to the class and service packet - the
/// size does *not* include the header bytes))
///
/// The expected behaviour is that first a slice packet with start flag is received, followed by
/// any amount of intermediat slice packets (there can be zero intermediates) and finally, a slice packet
/// with the end flag set.
/// Their payload is then concatinated in the order of arrival. The resulting packet is a normal network
/// packet which needs to be parsed again (in other words, it contains a normal packet header).
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

    /// Adds a slice packet to the internal store.
    ///
    /// When a start packet is received, a new partial packet is created which accumulates the payloads.
    /// When a end packet is received, the accumulated payload is stored in a new (network) packet.
    ///
    /// Sanity checks are performed.
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

    /// Consumes a packet fresh from the network and parses its header.
    ///
    /// If it is a service packet, it is wrapped into a `Packet` and returned.
    ///
    /// If it is a slice packet, it is added to the internal state. When a end slice is received
    /// the resulting packet is wrapped into a `Packet` and returned.
    ///
    /// A class packet is not expected!
    pub fn handle_incoming_packet(&mut self, header: Header, payload: Vec<u8>) -> Option<Packet> {
        trace!("handling packet {:?}: {:02X?}", header, payload);
        match header {
            Header::Service {
                service, sub_type, ..
            } if service == ServiceType::SliceProbe => {
                // silently drop slice probing packets
                assert_eq!(sub_type, 0xcc);
                return None;
            }
            Header::Service { service, .. } if service != ServiceType::SliceProbe => {
                // got Item
                trace!("Service");

                let packet = Packet::new(header, payload, self.location.clone());
                return Some(packet);
            }
            Header::Slice {
                slice_packet_id,
                partial_flags,
                ..
            } => {
                // got Slice
                trace!("Slice");

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

    /// Consumes a packet and converts it into bytes.
    ///
    /// When the resulting (network) packet is too long, it is split up into slice packets.
    pub fn handle_outgoign_packet(&mut self, mut packet: Packet) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = vec![];

        // for easier access
        let packet_size = packet.payload.len();

        // simple case: packet fits into the desired size, no splitting necessary
        if packet_size + HEADER_SIZE < SLICE_PREFERED_PACKET_SIZE {
            out.push(packet.to_bytes());
        } else {
            // packet is too large, split it
            let packet_size_first = SLICE_PREFERED_PACKET_SIZE - HEADER_SIZE; // slice header
            let payload_size_first = SLICE_PREFERED_PACKET_SIZE - HEADER_SIZE - HEADER_SIZE; // slice header + packet header
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
            while packet.payload.len() > SLICE_PREFERED_PACKET_SIZE - HEADER_SIZE {
                // create intermediate packet
                let mut data: Vec<u8> = vec![];
                let payload_size_middle = SLICE_PREFERED_PACKET_SIZE - HEADER_SIZE; // slice header

                // create middle header
                let header = Header::Slice {
                    partial_flags: 0,
                    size: (SLICE_PREFERED_PACKET_SIZE - HEADER_SIZE) as u16,
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

            // create end packet
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

#[cfg(test)]
mod test_slice {
    use std::sync::Arc;

    use retroshare_compat::basics::SslId;

    use crate::low_level_parsing::{
        headers::{Header, ServiceHeader, HEADER_SIZE},
        parser_network::{SLICE_FLAG_END_BIT, SLICE_FLAG_START_BIT},
    };

    use super::{Parser, SLICE_PREFERED_PACKET_SIZE};

    #[test]
    fn test_slicing() {
        const PACKET_EXTRA: usize = 42;

        let large_payload = [0xab; SLICE_PREFERED_PACKET_SIZE * 2 + PACKET_EXTRA].to_vec();
        let header = ServiceHeader::new(0x13.into(), 0x37, &large_payload);
        let large_packet =
            super::Packet::new_without_location(header.to_owned().into(), large_payload);
        let mut parser = Parser::new(Arc::new(SslId::default()));

        let res = parser.handle_outgoign_packet(large_packet);

        assert_eq!(res.len(), 3);

        let expected: Vec<Vec<u8>> = {
            // 1st slice
            let header_1 = Header::Slice {
                partial_flags: SLICE_FLAG_START_BIT,
                slice_packet_id: 0,
                size: (SLICE_PREFERED_PACKET_SIZE - HEADER_SIZE) as u16,
            }
            .to_bytes()
            .to_vec();
            let mut payload_1 = Into::<Header>::into(header).to_bytes().to_vec();
            // subtract slice packet header, actual packet header
            payload_1.extend([0xab; SLICE_PREFERED_PACKET_SIZE - HEADER_SIZE - HEADER_SIZE]);

            // 2nd slice
            let header_2 = Header::Slice {
                partial_flags: 0,
                slice_packet_id: 0,
                size: (SLICE_PREFERED_PACKET_SIZE - HEADER_SIZE) as u16,
            }
            .to_bytes()
            .to_vec();
            // subtract slice packet header
            let payload_2 = [0xab; SLICE_PREFERED_PACKET_SIZE - HEADER_SIZE].to_vec();

            // 3rd slice
            let header_3 = Header::Slice {
                partial_flags: SLICE_FLAG_END_BIT,
                slice_packet_id: 0,
                size: (PACKET_EXTRA + 2 * HEADER_SIZE + HEADER_SIZE) as u16,
            }
            .to_bytes()
            .to_vec();
            // remaining: PACKET_EXTRA + two times the slice header + one time the actual packet header
            let payload_3 = [0xab; PACKET_EXTRA + 2 * HEADER_SIZE + HEADER_SIZE].to_vec();

            vec![
                header_1.into_iter().chain(payload_1.into_iter()).collect(),
                header_2.into_iter().chain(payload_2.into_iter()).collect(),
                header_3.into_iter().chain(payload_3.into_iter()).collect(),
            ]
        };

        for i in 0..3 {
            println!("{i}");
            assert_eq!(res[i], expected[i]);
        }
    }
}
