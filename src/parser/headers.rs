use std::fmt::Display;

use crate::error::*;
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
        service: u16,
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
                let service = (t >> 8) as u16;
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
                    "Header::Service: service: {service}, sub_type: {sub_type}, size: {size}"
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

#[derive(Debug)]
pub struct SliceHeader {
    pub partial_flags: u8,
    pub slice_packet_id: u32,
    pub size: u16,
}

#[derive(Debug)]
pub struct ServiceHeader {
    pub service: u16,
    pub sub_type: u8,
    pub size: u32,
}

#[derive(Debug)]
pub struct ClassHeader {
    pub class: u8,
    pub typ: u8,
    pub sub_type: u8,
    pub size: u32,
}

impl ServiceHeader {
    pub fn new(service: u16, sub_type: u8, payload: &Vec<u8>) -> ServiceHeader {
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

    use crate::serial_stuff;

    use super::Header;

    #[test]
    fn header_convert() {
        let a: [u8; 8] = serial_stuff::gen_slice_probe().try_into().unwrap();

        // let header = Header::Raw { data: a.clone() };
        let header = Header::try_parse(&a).unwrap();

        match header {
            Header::Service {
                service,
                sub_type,
                size,
            } => {
                assert_eq!(service, 0xaabb);
                assert_eq!(sub_type, 0xcc);
                assert_eq!(size, 8);
            }
            _ => panic!("failed"),
        }

        let b = header.to_bytes();
        assert_eq!(a, b);
    }
}

// impl fmt::Debug for Header {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             Header::Raw{data} => {
//                 write!(
//             f,
//             "Header::Raw {{ version: {:02X?}, partial_flags: {:02X?}, slice_packet_id: {:08X?}, size: {:?} ({:04X?}) }}",
//             self.version(), partial_flags, slice_packet_id, size, size
//         )
//             },
//             Header::Slice{partial_flags,
//                             slice_packet_id,
//                             size,} => {
//                                 write!(
//             f,
//             "Slice {{ version: {:02X?}, partial_flags: {:02X?}, slice_packet_id: {:08X?}, size: {:?} ({:04X?}) }}",
//             self.version(), partial_flags, slice_packet_id, size, size
//         )
//                             },
//             Header::Service{service,
//                             sub_type,
//                             size,} => {
//                         write!(
//             f,
//             "Service {{ version: {:02X?}, service: {:04X?}, sub_type: {:02X?}, size: {:?} ({:08X?}) }}",
//             self.version(), service, sub_type, size, size
//         )
//             },
//             Header::Class{class,
//                             typ,
//                             sub_type,
//                             size,} => {
//                                 write!(
//             f,
//             "Class {{ version: {:02X}, class: {:02X}, type: {:02X}, sub_type: {:02X}, size: {:?} ({:08X}) }}",
//             self.version(), class, typ, sub_type, size, size
//         )
//                             },
//         }

//     }
// }

// pub trait Header {
//     fn version() -> u8;
//     fn payload_size(&self) -> usize;
// }
/*
pub struct ServiceHeader {
    service: u16,
    sub_type: u8,
    size: u32,
}

impl ServiceHeader {
    pub fn new() -> ServiceHeader {
        ServiceHeader {
            service: 0,
            sub_type: 0,
            size: 0,
        }
    }
    pub fn new_with_values(service: u16, sub_type: u8, size: u32) -> ServiceHeader {
        ServiceHeader {
            service: service,
            sub_type: sub_type,
            size: size,
        }
    }

    pub fn get_values(&self) -> (u16, u8, u32) {
        (self.service, self.sub_type, self.size)
    }

    fn from_type(&mut self, t: u32) {
        // self.version = (t >> 24) as u8;
        assert_eq!(ServiceHeader::version(), (t >> 24) as u8);
        self.service = (t >> 8) as u16;
        self.sub_type = t as u8;
    }

    fn to_type(&self) -> u32 {
        // 	type = (ver << 24) + (service << 8) + subtype;
        ((ServiceHeader::version() as u32) << 24)
            + ((self.service as u32) << 8)
            + (self.sub_type as u32)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut data: [u8; 8] = [0; 8];
        NetworkEndian::write_u32(&mut data[0..4], self.to_type());
        NetworkEndian::write_u32(&mut data[4..8], self.size);
        data
    }

    pub fn parse_header(data: &[u8; 8]) -> Option<ServiceHeader> {
        let mut item = ServiceHeader::new();
        item.from_type(NetworkEndian::read_u32(&data[0..4]));
        item.size = NetworkEndian::read_u32(&data[4..8]);
        Some(item)
    }
}

impl Header for ServiceHeader {
    fn version() -> u8 {
        0x2
    }

    fn payload_size(&self) -> usize {
        let mut s = self.size;
        if s > 262143 {
            s = 262143;
        }
        s as usize - 8
    }
}

impl fmt::Debug for ServiceHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ServiceHeader {{ version: {:02X?}, service: {:04X?}, sub_type: {:02X?}, size: {:?} ({:08X?}) }}",
            ServiceHeader::version(), self.service, self.sub_type, self.size, self.size
        )
    }
}

pub struct SliceHeader {
    partial_flags: u8,
    slice_packet_id: u32,
    size: u16,
}

impl SliceHeader {
    pub fn new() -> SliceHeader {
        SliceHeader {
            partial_flags: 0,
            slice_packet_id: 0,
            size: 0,
        }
    }

    pub fn get_values(&self) -> (u8, u32, u16) {
        (self.partial_flags, self.slice_packet_id, self.size)
    }

    pub fn parse_header(data: &[u8; 8]) -> Option<SliceHeader> {
        let mut header = SliceHeader::new();
        assert_eq!(SliceHeader::version(), data[0]);
        header.partial_flags = data[1];
        header.slice_packet_id += (data[2] as u32) << 24;
        header.slice_packet_id += (data[3] as u32) << 16;
        header.slice_packet_id += (data[4] as u32) << 8;
        header.slice_packet_id += (data[5] as u32) << 0;
        header.size += (data[6] as u16) << 8;
        header.size += (data[7] as u16) << 0;
        Some(header)
    }

    #[allow(dead_code)]
    fn to_bytes(&self) -> [u8; 8] {
        let mut data: [u8; 8] = [0; 8];

        data[0] = SliceHeader::version();
        data[1] = self.partial_flags;
        data[2] = (self.slice_packet_id >> 24) as u8;
        data[3] = (self.slice_packet_id >> 16) as u8;
        data[4] = (self.slice_packet_id >> 8) as u8;
        data[5] = (self.slice_packet_id >> 0) as u8;
        data[6] = (self.size >> 8) as u8;
        data[7] = (self.size >> 0) as u8;
        data
    }
}

impl fmt::Debug for SliceHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SliceHeader {{ version: {:02X?}, partial_flags: {:02X?}, slice_packet_id: {:08X?}, size: {:?} ({:04X?}) }}",
            SliceHeader::version(), self.partial_flags, self.slice_packet_id, self.size, self.size
        )
    }
}

impl Header for SliceHeader {
    fn payload_size(&self) -> usize {
        self.size as usize
    }
    fn version() -> u8 {
        0x10
    }
}

pub struct ClassHeader {
    class: u8,
    typ: u8,
    sub_type: u8,
    size: u32,
}

impl ClassHeader {
    pub fn new() -> ClassHeader {
        ClassHeader {
            class: 0,
            typ: 0,
            sub_type: 0,
            size: 0,
        }
    }
    // pub fn new_with_values(service: u16, sub_type: u8, size: u32) -> ClassHeader {
    //     ServiceHeader {
    //         service: service,
    //         sub_type: sub_type,
    //         size: size,
    //     }
    // }

    pub fn get_values(&self) -> (u8, u8, u8, u32) {
        (self.class, self.typ, self.sub_type, self.size)
    }

    fn from_type(&mut self, t: u32) {
        // self.version = (t >> 24) as u8;
        assert_eq!(ClassHeader::version(), (t >> 24) as u8);
        self.class = (t >> 16) as u8;
        self.typ = (t >> 8) as u8;
        self.sub_type = t as u8;
    }

    fn to_type(&self) -> u32 {
        // 	type = (ver << 24) + (service << 8) + subtype;
        ((ClassHeader::version() as u32) << 24)
            + ((self.class as u32) << 16)
            + ((self.typ as u32) << 8)
            + (self.sub_type as u32)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut data: [u8; 8] = [0; 8];
        NetworkEndian::write_u32(&mut data[0..4], self.to_type());
        NetworkEndian::write_u32(&mut data[4..8], self.size);
        data
    }

    pub fn parse_header(data: &[u8; 8]) -> Option<ClassHeader> {
        let mut item = ClassHeader::new();
        item.from_type(NetworkEndian::read_u32(&data[0..4]));
        item.size = NetworkEndian::read_u32(&data[4..8]);
        Some(item)
    }
}

impl Header for ClassHeader {
    fn version() -> u8 {
        0x1
    }

    fn payload_size(&self) -> usize {
        let mut s = self.size;
        if s > 262143 {
            s = 262143;
        }
        s as usize - 8
    }
}

impl fmt::Debug for ClassHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ClassHeader {{ version: {:02X}, class: {:02X}, type: {:02X}, sub_type: {:02X}, size: {:?} ({:08X}) }}",
            ClassHeader::version(), self.class, self.typ, self.sub_type, self.size, self.size
        )
    }
}
*/
