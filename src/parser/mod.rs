pub mod headers;

use headers::*;

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub data: Vec<u8>,
    pub from: String,
}

struct SlicePacket {
    slice_packet_id: u32,
    payload: Vec<u8>,
}

pub struct Parser {
    partial_store: Vec<SlicePacket>,
}

impl Parser {
    pub fn new() -> Parser {
        Parser {
            partial_store: vec![],
        }
    }

    fn add_slice(
        &mut self,
        slice_packet_id: u32,
        partial_flags: u8,
        payload: &mut Vec<u8>,
    ) -> Option<Packet> {
        // TODO figure out if one slice can contain multiple packets
        // There is an assert at the end, that would catch this case.

        let mut is_new = false;
        let found = self.get_slice_by_id(slice_packet_id).is_some();

        // check for start
        if (partial_flags & 0x01) != 0 {
            // start
            if found {
                // found existing?!
                println!(
                    "found existing packet with id {} but 'start' flag is set",
                    slice_packet_id
                );
            } else {
                // starte -> create new
                is_new = true;

                let a = SlicePacket {
                    slice_packet_id,
                    payload: vec![],
                };
                self.partial_store.push(a);
            };
        }
        let slice = self.get_slice_by_id(slice_packet_id).unwrap();

        // middle / append new data
        slice.payload.append(payload);

        if (partial_flags & 0x02) != 0 {
            // end
            if is_new {
                // end should never be also start
                println!(
                    "can't find packet with id {} but 'end' flag is set",
                    slice.slice_packet_id
                );
            }

            // handle finished packet
            // println!("got {:?} bytes: {:X?}", slice.payload.len(), &slice.payload);
            let mut header: [u8; 8] = [0; 8];
            header.copy_from_slice(&slice.payload[0..8]);
            let header = Header::Raw { data: header };
            let header = match header.try_parse() {
                Ok(h) => h,
                _ => return None,
            };
            let payload: Vec<u8> = slice.payload.drain(8..).collect();

            // last sanity check
            assert_eq!(payload.len(), header.get_payload_size().unwrap());
            return self.parse_packet(header, payload);
        }
        None
    }

    fn get_slice_by_id(&mut self, slice_packet_id: u32) -> Option<&mut SlicePacket> {
        for slice in self.partial_store.iter_mut() {
            if slice.slice_packet_id == slice_packet_id {
                return Some(slice);
            }
        }
        None
    }

    pub fn parse_packet(&mut self, header: Header, payload: Vec<u8>) -> Option<Packet> {
        match header {
            Header::Service { service, .. } => {
                // got Item
                if service == 0xaabb {
                    // silently drop slice probing packets
                    return None;
                }

                let packet = Packet {
                    header,
                    data: payload,
                    from: String::new(),
                };

                return Some(packet);
            }
            Header::Slice {
                slice_packet_id,
                partial_flags,
                ..
            } => {
                // got Slice
                let mut payload = payload;
                return self.add_slice(slice_packet_id, partial_flags, &mut payload);
            }
            // Header::Class {..} =>
            _ => return None,
        }
        // None
    }
}
