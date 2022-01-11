use std::{
    collections::HashSet,
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::{
    basics::*,
    read_u16, read_u32, read_u64,
    serde::{from_retroshare_wire, to_retroshare_wire},
    write_u16, write_u32, write_u64,
};

// pub mod serde;
// pub mod typed_string;
// pub mod macros;

pub const TLV_HEADER_SIZE: usize = 6;

// typedef t_RsTlvIdSet<RsPeerId,      TLV_TYPE_PEERSET>	        RsTlvPeerIdSet ;
// typedef t_RsTlvIdSet<RsPgpId,       TLV_TYPE_PGPIDSET>	        RsTlvPgpIdSet ;
// typedef t_RsTlvIdSet<Sha1CheckSum,  TLV_TYPE_HASHSET> 	        RsTlvHashSet ;
// typedef t_RsTlvIdSet<RsGxsId,       TLV_TYPE_GXSIDSET>          RsTlvGxsIdSet ;
// typedef t_RsTlvIdSet<RsGxsMessageId,TLV_TYPE_GXSMSGIDSET>       RsTlvGxsMsgIdSet ;
// typedef t_RsTlvIdSet<RsGxsCircleId, TLV_TYPE_GXSCIRCLEIDSET>    RsTlvGxsCircleIdSet ;
// typedef t_RsTlvIdSet<RsNodeGroupId, TLV_TYPE_NODEGROUPIDSET>    RsTlvNodeGroupIdSet ;
const TLV_TYPE_PEERSET: u16 = 0x1021;
const TLV_TYPE_HASHSET: u16 = 0x1022;
const TLV_TYPE_PGPIDSET: u16 = 0x1023;
const TLV_TYPE_GXSIDSET: u16 = 0x1025;
const TLV_TYPE_GXSCIRCLEIDSET: u16 = 0x1026;
const TLV_TYPE_NODEGROUPIDSET: u16 = 0x1027;
const TLV_TYPE_GXSMSGIDSET: u16 = 0x1028;

macro_rules! make_tlv_id_set_type {
    ($name:ident, $typ:ident, $tag:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq, Default)]
        pub struct $name(pub HashSet<$typ>);

        impl $name {
            pub fn read(data: &mut Vec<u8>) -> Self {
                let mut item = $name(HashSet::new());
                let tag = read_u16(data);
                let len = read_u32(data) as usize;
                assert_eq!(tag, $tag);

                let end = data.len() - (len - TLV_HEADER_SIZE);
                while data.len() > end {
                    let id: $typ = from_retroshare_wire(data).expect("failed to read ID");
                    item.0.insert(id);
                }

                item
            }

            pub fn write(&self) -> Vec<u8> {
                let mut data: Vec<u8> = vec![];

                // write payload
                for entry in &self.0 {
                    data.append(&mut to_retroshare_wire(entry).expect("failed to serialize ID"));
                }
                // create TLV header
                let mut packet: Vec<u8> = vec![];
                write_u16(&mut packet, $tag);
                write_u32(&mut packet, (data.len() + TLV_HEADER_SIZE) as u32);
                packet.append(&mut data);

                packet
            }
        }

        // impl Default for $name {
        //     fn default() -> Self {
        //         Self([0u8; $width])
        //     }
        // }

        // impl fmt::Display for $name {
        //     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //         write!(f, "{}: {}", stringify!($name), hex::encode(self.0))
        //     }
        // }

        // impl Hash for $name {
        //     fn hash<H: Hasher>(&self, state: &mut H) {
        //         self.0.hash(state);
        //     }
        // }
    };
}

make_tlv_id_set_type!(TlvPeerIdSet, PeerId, TLV_TYPE_PEERSET);
make_tlv_id_set_type!(TlvPgpIdSet, PgpId, TLV_TYPE_PGPIDSET);
make_tlv_id_set_type!(TlvHashSet, Sha1CheckSum, TLV_TYPE_HASHSET);
make_tlv_id_set_type!(TlvGxsIdSet, GxsId, TLV_TYPE_GXSIDSET);
make_tlv_id_set_type!(TlvGxsMsgIdSet, GxsMessageId, TLV_TYPE_GXSMSGIDSET);
make_tlv_id_set_type!(TlvGxsCircleIdSet, GxsCircleId, TLV_TYPE_GXSCIRCLEIDSET);
make_tlv_id_set_type!(TlvNodeGroupIdSet, NodeGroupId, TLV_TYPE_NODEGROUPIDSET);

// typed string

pub fn read_string_typed(data: &mut Vec<u8>, tag: u16) -> String {
    let t = read_u16(data); // type
    let s = read_u32(data); // len
    assert_eq!(t, tag);
    assert!(s >= TLV_HEADER_SIZE as u32);
    let str_len = s as usize - TLV_HEADER_SIZE; // remove tlv header length
    String::from_utf8(data.drain(..str_len).collect()).unwrap()
}
pub fn write_string_typed(data: &mut Vec<u8>, val: &str, tag: u16) {
    write_u16(data, tag);
    write_u32(data, (val.len() + TLV_HEADER_SIZE) as u32); // len
    data.extend_from_slice(val.as_bytes());
}

// pub struct TypedString {
//     str: String,
//     tag: u16,
// }

// impl TypedString {
//     pub fn new(s: &str, tag: u16) -> TypedString {
//         TypedString {
//             str: s.to_owned(),
//             tag,
//         }
//     }
// }

// impl Serialize for TypedString {
//     // fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//     //     use ser::SerializeTuple;

//     //     // let mut seq = serializer.serialize_tuple(SIGNATURE_LENGTH)?;

//     //     // for byte in &self.0[..] {
//     //     //     seq.serialize_element(byte)?;
//     //     // }

//     //     // seq.end()
//     //     serializer.
//     // }
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         serializer.serialize_u16(self.tag)?;
//         // len is part of the following
//         serializer.serialize_str(self.str)y
//     }
// }

// impl<'de> Deserialize<'de> for TypedString {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         struct Vis {};

//         impl Visitor<'de> for Vis {
//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str("tlv encoded string")
//             }

//             fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
//             where
//                     E: serde::de::Error, {
//                 Ok(v)
//             }

//             // fn visit_b
//         }

//         deserializer.deserialize_u16(Vis).and_then(|tag| assert_eq!(tag, self.tag))?;
//         deserializer.deserialize_bytes(Vis)
//     }
// }

// tlv ip addr

pub fn read_tlv_ip_addr(data: &mut Vec<u8>) -> SocketAddr {
    let tag = read_u16(data); // type
    let len = read_u32(data); // len
    assert_eq!(tag, 0x1072); // const uint16_t TLV_TYPE_ADDRESS       = 0x1072;

    if len == TLV_HEADER_SIZE as u32 {
        // no actual payload
        return TlvIpAddress::default().0;
    }

    let tag = read_u16(data); // type
    match tag {
        0x0085 => {
            assert_eq!(read_u32(data), 12); // len
            let addr_loc_v4 = {
                let ip = read_u32(data).swap_bytes(); // why?!
                let port = read_u16(data).swap_bytes(); // why?!
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
            };
            return addr_loc_v4;
        }
        0x0086 => {
            assert_eq!(read_u32(data), 24); // len
            let mut ip: u128 = 0;
            for _ in 0..4 {
                ip = ip.overflowing_shl(32).0;
                ip += read_u32(data) as u128;
            }
            let port = read_u16(data).swap_bytes(); // why?!
            return SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port);
        }
        tag => panic!("unkown ip type {:04X} size {:?}", tag, len),
    }
}
pub fn write_tlv_ip_addr(data: &mut Vec<u8>, addr: &SocketAddr) {
    write_u16(data, 0x1072); // tag

    if addr == &TlvIpAddress::default().0 {
        // empty packet
        write_u32(data, TLV_HEADER_SIZE as u32); // len
        return;
    }

    match addr {
        SocketAddr::V4(addr) => {
            write_u32(data, (TLV_HEADER_SIZE + TLV_HEADER_SIZE + 4 + 2) as u32); // len
            write_u16(data, 0x0085); // tag
            write_u32(data, (TLV_HEADER_SIZE + 4 + 2) as u32);
            write_u32(data, u32::from_le_bytes(addr.ip().octets())); // is LE correct here?!
            write_u16(data, addr.port().swap_bytes());
        }
        SocketAddr::V6(addr) => {
            write_u32(data, (TLV_HEADER_SIZE + TLV_HEADER_SIZE + 16 + 2) as u32); // len
            write_u16(data, 0x0086); // tag
            write_u32(data, (TLV_HEADER_SIZE + 16 + 2) as u32);
            data.extend_from_slice(&addr.ip().octets()); // swap bytes required?!
            write_u16(data, addr.port().swap_bytes());
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
// #[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub struct TlvIpAddress(pub SocketAddr);

impl Default for TlvIpAddress {
    fn default() -> Self {
        TlvIpAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0)), 0))
    }
}

impl Hash for TlvIpAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl From<SocketAddr> for TlvIpAddress {
    fn from(s: SocketAddr) -> Self {
        TlvIpAddress(s)
    }
}

impl fmt::Display for TlvIpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// class RsTlvIpAddressInfo: public RsTlvItem
// {
// 	RsTlvIpAddress addr; 				// Mandatory :
// 	uint64_t  seenTime;				// Mandatory :
// 	uint32_t  source; 				// Mandatory :
// };
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct TlvIpAddressInfo {
    pub addr: TlvIpAddress,
    pub seen_time: u64,
    pub source: u32,
}

impl Hash for TlvIpAddressInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.seen_time.hash(state);
        self.source.hash(state);
    }
}

impl From<TlvIpAddressInfo> for SocketAddr {
    fn from(tlv: TlvIpAddressInfo) -> Self {
        tlv.addr.0
    }
}

impl fmt::Display for TlvIpAddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TlvIpAddressInfo: [")?;
        write!(f, " addr: {}", self.addr)?;
        write!(f, " seen_time: {}", self.seen_time)?;
        write!(f, " source: {}", self.source)?;
        write!(f, " ]")
    }
}

pub fn read_tlv_ip_address_info(data: &mut Vec<u8>) -> TlvIpAddressInfo {
    let mut item = TlvIpAddressInfo::default();
    assert_eq!(read_u16(data), 0x1070); // const uint16_t TLV_TYPE_ADDRESS_INFO  = 0x1070;
    let _ = read_u32(data); // len
    item.addr = read_tlv_ip_addr(data).into();
    item.seen_time = read_u64(data);
    item.source = read_u32(data);
    item
}

#[derive(Debug, Default, PartialEq, Eq)]
// #[derive(Debug)]
pub struct TlvIpAddrSet(pub HashSet<TlvIpAddressInfo>);

impl fmt::Display for TlvIpAddrSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;

        write!(f, "TlvIpAddrSet: [")?;
        for ip in &self.0 {
            if !first {
                write!(f, ", ")?;
            } else {
                first = false;
            }
            write!(f, "{}", ip.addr.0)?;
        }
        write!(f, "]")
    }
}

pub fn read_tlv_ip_addr_set(data: &mut Vec<u8>) -> TlvIpAddrSet {
    let mut item = TlvIpAddrSet(HashSet::new());
    assert_eq!(read_u16(data), 0x1071); // const uint16_t TLV_TYPE_ADDRESS_SET   = 0x1071;
    let len = read_u32(data) as usize; // len
    let end_len = data.len() - (len - TLV_HEADER_SIZE);
    while data.len() > end_len {
        item.0.insert(read_tlv_ip_address_info(data));
    }
    item
}

pub fn write_tlv_ip_addr_set(data: &mut Vec<u8>, addrs: &TlvIpAddrSet) {
    let mut payload: Vec<u8> = vec![];
    for addr in &addrs.0 {
        let mut ip_payload: Vec<u8> = vec![];
        write_tlv_ip_addr(&mut ip_payload, &addr.addr.0);

        write_u16(&mut payload, 0x1070);
        write_u32(&mut payload, (TLV_HEADER_SIZE + ip_payload.len()) as u32);
        payload.append(&mut ip_payload);
        write_u64(&mut payload, addr.seen_time);
        write_u32(&mut payload, addr.source);
    }

    write_u16(data, 0x1071);
    write_u32(data, (TLV_HEADER_SIZE + payload.len()) as u32);
    data.append(&mut payload);
}
