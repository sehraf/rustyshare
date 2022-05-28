use std::fmt::Display;

use crate::{error::*, services::ServiceType};
use byteorder::{BigEndian, ByteOrder, NetworkEndian};

pub const HEADER_SIZE: usize = 8;

#[derive(Debug, Clone, Copy)]
pub enum Header {
    Slice {
        partial_flags: u8,
        slice_packet_id: u32,
        size: u16,
    },
    Service {
        service: ServiceType,
        sub_type: u8,
        size: u32,
    },
    Class {
        class: u8,
        ty: u8,
        sub_type: u8,
        size: u32,
    },
}

impl Header {
    fn version(&self) -> u8 {
        match self {
            Header::Slice { .. } => 0x10,
            Header::Service { .. } => 0x02,
            Header::Class { .. } => 0x01,
        }
    }

    pub fn try_parse(data: &[u8; 8]) -> Result<Header, RsError> {
        match data[0] {
            0x01 => {
                // got class
                let t = NetworkEndian::read_u32(&data[0..4]);
                let class = (t >> 16) as u8;
                let ty = (t >> 8) as u8;
                let sub_type = t as u8;
                let size = NetworkEndian::read_u32(&data[4..8]);
                Ok(Header::Class {
                    class,
                    ty,
                    sub_type,
                    size,
                })
            }
            0x02 => {
                // service
                let t = NetworkEndian::read_u32(&data[0..4]);
                let service = ((t >> 8) as u16).into();
                let sub_type = t as u8;
                let size = NetworkEndian::read_u32(&data[4..8]);
                Ok(Header::Service {
                    service,
                    sub_type,
                    size,
                })
            }
            0x10 => {
                // got Slice
                let partial_flags = data[1];
                // slice_packet_id += (header[2] as u32) << 24;
                // slice_packet_id += (header[3] as u32) << 16;
                // slice_packet_id += (header[4] as u32) << 8;
                // slice_packet_id += (header[5] as u32) << 0;
                let slice_packet_id = BigEndian::read_u32(&data[2..6]);
                // size += (header[6] as u16) << 8;
                // size += (header[7] as u16) << 0;
                let size = BigEndian::read_u16(&data[6..8]);
                Ok(Header::Slice {
                    partial_flags,
                    slice_packet_id,
                    size,
                })
            }
            _ => Err(RsError::ParserError(RsErrorParser::UnknownHeaderType)),
        }
    }

    pub fn get_payload_size(&self) -> usize {
        match self {
            // slice, "new format", size field is payload size (excluding 8 bytes for the header)
            Header::Slice { ref size, .. } => size.clone() as usize,
            // service + class, "old format", size field includes 8 byte header
            Header::Service { ref size, .. } | Header::Class { ref size, .. } => {
                assert!(size >= &(HEADER_SIZE as u32));
                size.clone() as usize - HEADER_SIZE
            }
        }
    }

    pub fn to_bytes(self) -> [u8; 8] {
        match self {
            Header::Slice {
                partial_flags,
                slice_packet_id,
                size,
            } => {
                let mut data: [u8; 8] = [0; 8];
                // ((char*)mPkt_wpending)[mPkt_wpending_size+0x00] = PQISTREAM_SLICE_PROTOCOL_VERSION_ID_01 ;
                data[0] = self.version();
                // ((char*)mPkt_wpending)[mPkt_wpending_size+0x01] = partial_flags ;
                data[1] = partial_flags;
                // ((char*)mPkt_wpending)[mPkt_wpending_size+0x02] = uint8_t(slice_packet_id >> 24) & 0xff ;
                // ((char*)mPkt_wpending)[mPkt_wpending_size+0x03] = uint8_t(slice_packet_id >> 16) & 0xff ;
                // ((char*)mPkt_wpending)[mPkt_wpending_size+0x04] = uint8_t(slice_packet_id >>  8) & 0xff ;
                // ((char*)mPkt_wpending)[mPkt_wpending_size+0x05] = uint8_t(slice_packet_id >>  0) & 0xff ;
                BigEndian::write_u32(&mut data[2..6], slice_packet_id);
                // ((char*)mPkt_wpending)[mPkt_wpending_size+0x06] = uint8_t(slice_size      >>  8) & 0xff ;
                // ((char*)mPkt_wpending)[mPkt_wpending_size+0x07] = uint8_t(slice_size      >>  0) & 0xff ;
                BigEndian::write_u16(&mut data[6..8], size);
                data
            }
            Header::Service {
                service,
                sub_type,
                size,
            } => {
                let mut data: [u8; 8] = [0; 8];
                let t = ((self.version() as u32) << 24 | (service as u32) << 8 | (sub_type as u32))
                    as u32;
                NetworkEndian::write_u32(&mut data[0..4], t);
                NetworkEndian::write_u32(&mut data[4..8], size);
                data
            }
            Header::Class {
                class,
                ty: typ,
                sub_type,
                size,
            } => {
                let mut data: [u8; 8] = [0; 8];
                let t = ((self.version() as u32) << 24
                    | (class as u32) << 16
                    | (typ as u32) << 8
                    | (sub_type as u32)) as u32;
                NetworkEndian::write_u32(&mut data[0..4], t);
                NetworkEndian::write_u32(&mut data[4..8], size);
                data
            }
        }
    }
}

impl From<SliceHeader> for Header {
    fn from(header: SliceHeader) -> Self {
        Header::Slice {
            partial_flags: header.partial_flags,
            slice_packet_id: header.slice_packet_id,
            size: header.size,
        }
    }
}

impl From<ServiceHeader> for Header {
    fn from(header: ServiceHeader) -> Self {
        Header::Service {
            service: header.service,
            sub_type: header.sub_type,
            size: header.size,
        }
    }
}

impl From<ClassHeader> for Header {
    fn from(header: ClassHeader) -> Self {
        Header::Class {
            class: header.class,
            ty: header.typ,
            sub_type: header.sub_type,
            size: header.size,
        }
    }
}

impl From<&Vec<u8>> for Header {
    fn from(data: &Vec<u8>) -> Self {
        assert_eq!(data.len(), HEADER_SIZE);
        // copy into array
        let mut raw = [0 as u8; HEADER_SIZE];
        raw.copy_from_slice(&data[0..HEADER_SIZE]);

        // crash here
        Header::try_parse(&raw).expect("failed to parse header!")
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Header::Class {
                class,
                ty: typ,
                sub_type,
                size,
            } => {
                write!(
                    f,
                    "Header::Class: class: {class}, typ: {typ}, sub_type: {sub_type}, size: {size}"
                )
            }
            Header::Service {
                service,
                sub_type,
                size,
            } => {
                write!(
                    f,
                    "Header::Service: service: {service:?}, sub_type: {sub_type}, size: {size}"
                )
            }
            Header::Slice {
                partial_flags,
                slice_packet_id,
                size,
            } => {
                write!(f, "Header::Slice: partial_flags: {partial_flags}, slice_packet_id: {slice_packet_id}, size: {size}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SliceHeader {
    pub partial_flags: u8,
    pub slice_packet_id: u32,
    pub size: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct ServiceHeader {
    pub service: ServiceType,
    pub sub_type: u8,
    pub size: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ClassHeader {
    pub class: u8,
    pub typ: u8,
    pub sub_type: u8,
    pub size: u32,
}

impl ServiceHeader {
    pub fn new(service: ServiceType, sub_type: u8, payload: &Vec<u8>) -> ServiceHeader {
        ServiceHeader {
            service,
            sub_type,
            size: (payload.len() + HEADER_SIZE) as u32,
        }
    }
}

impl From<Header> for ServiceHeader {
    fn from(header: Header) -> Self {
        match header {
            Header::Service {
                service,
                sub_type,
                size,
            } => ServiceHeader {
                service,
                sub_type,
                size,
            },
            _ => panic!("trying to convert incompatible header! {:?}", header),
        }
    }
}

impl From<Header> for SliceHeader {
    fn from(header: Header) -> Self {
        match header {
            Header::Slice {
                partial_flags,
                slice_packet_id,
                size,
            } => SliceHeader {
                partial_flags,
                slice_packet_id,
                size,
            },
            _ => panic!("trying to convert incompatible header! {:?}", header),
        }
    }
}

impl From<Header> for ClassHeader {
    fn from(header: Header) -> Self {
        match header {
            Header::Class {
                class,
                ty: typ,
                sub_type,
                size,
            } => ClassHeader {
                class,
                typ,
                sub_type,
                size,
            },
            _ => panic!("trying to convert incompatible header! {:?}", header),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{assert_eq, convert::TryInto};

    use crate::services::ServiceType;

    use super::Header;

    fn gen_slice_probe() -> Vec<u8> {
        let header = Header::Service {
            service: ServiceType::SliceProbe,
            sub_type: 0xcc,
            size: 8,
        };
        let mut item: Vec<u8> = Vec::new();
        item.extend_from_slice(&header.to_bytes());
        item
    }

    #[test]
    fn header_convert() {
        let a: [u8; 8] = gen_slice_probe().try_into().unwrap();

        // let header = Header::Raw { data: a.clone() };
        let header = Header::try_parse(&a).unwrap();

        match header {
            Header::Service {
                service,
                sub_type,
                size,
            } => {
                assert_eq!(service, ServiceType::SliceProbe);
                assert_eq!(sub_type, 0xcc);
                assert_eq!(size, 8);
            }
            _ => panic!("failed"),
        }

        let b = header.to_bytes();
        assert_eq!(a, b);

        let c = [0x02, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x08];
        assert_eq!(a, c);
    }
}
