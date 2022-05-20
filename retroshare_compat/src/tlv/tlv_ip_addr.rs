use std::{
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::{read_u16, read_u32, tlv::TLV_HEADER_SIZE, write_u16, write_u32};

use super::{tags::*, tlv_set::TlvSet, Tlv};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TlvIpAddress(pub SocketAddr);

impl Serialize for TlvIpAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser = vec![];
        // tag
        write_u16(&mut ser, TLV_IP_ADDR_TAG);

        match self.0 {
            s @ _ if s == TlvIpAddress::default().0 => {
                // empty packet
                // len
                write_u32(&mut ser, TLV_HEADER_SIZE as u32);
            }
            SocketAddr::V4(addr) => {
                // len
                write_u32(&mut ser, (TLV_HEADER_SIZE * 2 + 4 + 2) as u32);

                // tag
                write_u16(&mut ser, TLV_IP_ADDR_TAG_IPV4);
                // len
                write_u32(&mut ser, (TLV_HEADER_SIZE + 4 + 2) as u32);
                // val
                write_u32(&mut ser, u32::from_le_bytes(addr.ip().octets()));
                write_u16(&mut ser, addr.port().swap_bytes());
            }
            SocketAddr::V6(addr) => {
                // len
                write_u32(&mut ser, (TLV_HEADER_SIZE * 2 + 16 + 2) as u32);

                // tag
                write_u16(&mut ser, 0x0086);
                // len
                write_u32(&mut ser, (TLV_HEADER_SIZE + 16 + 2) as u32);
                // val
                ser.extend_from_slice(&addr.ip().octets()); // swap bytes required?!
                write_u16(&mut ser, addr.port().swap_bytes());
            }
        }

        serializer.serialize_bytes(ser.as_slice())
    }
}

impl<'de> Deserialize<'de> for TlvIpAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TaggedStringVisitor();

        impl<'de> Visitor<'de> for TaggedStringVisitor {
            type Value = TlvIpAddress;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a TlvIpAddress")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let tag = read_u16(&mut v[0..2].to_owned());
                if tag != TLV_IP_ADDR_TAG {
                    return Err(::serde::de::Error::custom(crate::serde::Error::WrongTag));
                }
                let len = read_u32(&mut v[2..6].to_owned()) as usize;
                assert!(len >= TLV_HEADER_SIZE);
                assert!(len == v.len());

                if len == TLV_HEADER_SIZE {
                    // empty packet
                    return Ok(TlvIpAddress::default());
                }

                let tag_2 = read_u16(&mut v[6..8].to_owned());
                let len_2 = read_u32(&mut v[8..12].to_owned()) as usize;

                let ip_addr = match tag_2 {
                    TLV_IP_ADDR_TAG_IPV4 if len == TLV_HEADER_SIZE * 2 + 4 + 2 => {
                        assert_eq!(len_2, TLV_HEADER_SIZE + 4 + 2);

                        let addr_loc_v4 = {
                            let ip = read_u32(&mut v[12..16].to_owned()).swap_bytes(); // why?!
                            let port = read_u16(&mut v[16..18].to_owned()).swap_bytes(); // why?!
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
                        };
                        TlvIpAddress::from(addr_loc_v4)
                    }
                    TLV_IP_ADDR_TAG_IPV6 if len == TLV_HEADER_SIZE * 2 + 16 + 2 => {
                        assert_eq!(len_2, TLV_HEADER_SIZE + 16 + 2);

                        let addr_loc_v6 = {
                            let mut ip: u128 = 0;
                            for index in 0..4 {
                                let i = 12 + index * 4;
                                ip = ip.overflowing_shl(32).0;
                                ip += read_u32(&mut v[i..i + 4].to_owned()) as u128;
                            }
                            let port = read_u16(&mut v[28..30].to_owned()).swap_bytes(); // why?!
                            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
                        };
                        TlvIpAddress::from(addr_loc_v6)
                    }
                    _tag @ _ => {
                        return Err(::serde::de::Error::custom(crate::serde::Error::WrongTag))
                    }
                };

                Ok(ip_addr)
            }
        }

        deserializer.deserialize_bytes(TaggedStringVisitor())
    }
}

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
#[derive(Debug, PartialEq, Eq, Default, Clone, Serialize, Deserialize)]
pub struct TlvIpAddressInfoInner {
    pub addr: TlvIpAddress,
    pub seen_time: u64,
    pub source: u32,
}
pub type TlvIpAddressInfo = Tlv<TLV_IP_ADDR_INFO, TlvIpAddressInfoInner>;

impl Hash for TlvIpAddressInfoInner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.seen_time.hash(state);
        self.source.hash(state);
    }
}

impl From<TlvIpAddressInfoInner> for SocketAddr {
    fn from(tlv: TlvIpAddressInfoInner) -> Self {
        tlv.addr.0
    }
}

impl fmt::Display for TlvIpAddressInfoInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TlvIpAddressInfo: [")?;
        write!(f, " addr: {}", self.addr)?;
        write!(f, " seen_time: {}", self.seen_time)?;
        write!(f, " source: {}", self.source)?;
        write!(f, "]")
    }
}

pub type TlvIpAddrSet = TlvSet<TLV_IP_ADDR_SET_TAG, TlvIpAddressInfo>;

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

#[cfg(test)]
mod test_tlv_ip {
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    };

    use crate::{
        read_u16, read_u32, read_u64,
        serde::{from_retroshare_wire, to_retroshare_wire},
        tlv::{
            tlv_ip_addr::{
                TlvIpAddress, TlvIpAddressInfo, TLV_IP_ADDR_INFO, TLV_IP_ADDR_SET_TAG,
                TLV_IP_ADDR_TAG,
            },
            TLV_HEADER_SIZE,
        },
        write_u16, write_u32, write_u64,
    };

    use super::TlvIpAddrSet;

    fn read_tlv_ip_addr(data: &mut Vec<u8>) -> SocketAddr {
        let tag = read_u16(data); // type
        let len = read_u32(data); // len
        assert_eq!(tag, TLV_IP_ADDR_TAG); // const uint16_t TLV_TYPE_ADDRESS       = 0x1072;

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
    fn write_tlv_ip_addr(data: &mut Vec<u8>, addr: &SocketAddr) {
        write_u16(data, TLV_IP_ADDR_TAG); // tag

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

    #[test]
    fn test_tlv_ip_empty() {
        let orig = TlvIpAddress::default();
        let mut ser = to_retroshare_wire(&orig).unwrap();

        let expected = hex::decode("107200000006").unwrap();
        assert_eq!(ser, expected);

        let mut expected_old = vec![];
        write_tlv_ip_addr(&mut expected_old, &orig.0);
        assert_eq!(ser, expected_old);

        let de_old = read_tlv_ip_addr(&mut ser.clone());
        assert_eq!(orig.0, de_old);

        let de = from_retroshare_wire(&mut ser).unwrap();
        assert_eq!(orig, de);
    }

    #[test]
    fn test_tlv_ip_v4() {
        let orig: TlvIpAddress =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).into();
        let mut ser = to_retroshare_wire(&orig).unwrap();

        let expected = hex::decode("10720000001200850000000c0100007f901f").unwrap();
        assert_eq!(ser, expected);

        let mut expected_old = vec![];
        write_tlv_ip_addr(&mut expected_old, &orig.0);
        assert_eq!(ser, expected_old);

        let de_old = read_tlv_ip_addr(&mut ser.clone());
        assert_eq!(orig.0, de_old);

        let de = from_retroshare_wire(&mut ser).unwrap();
        assert_eq!(orig, de);
    }

    #[test]
    fn test_tlv_ip_v6() {
        let orig: TlvIpAddress = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x9, 0x8)),
            8080,
        )
        .into();
        let mut ser = to_retroshare_wire(&orig).unwrap();

        let expected =
            hex::decode("10720000001e008600000018000a000b000c000d000e000f00090008901f").unwrap();
        assert_eq!(ser, expected);

        let mut expected_old = vec![];
        write_tlv_ip_addr(&mut expected_old, &orig.0);
        assert_eq!(ser, expected_old);

        let de_old = read_tlv_ip_addr(&mut ser.clone());
        assert_eq!(orig.0, de_old);

        let de = from_retroshare_wire(&mut ser).unwrap();
        assert_eq!(orig, de);
    }

    // -----------------------
    // TlvIpAddressInfo
    // -----------------------

    fn read_tlv_ip_address_info(data: &mut Vec<u8>) -> TlvIpAddressInfo {
        let mut item = TlvIpAddressInfo::default();
        assert_eq!(read_u16(data), TLV_IP_ADDR_INFO); // const uint16_t TLV_TYPE_ADDRESS_INFO  = 0x1070;
        let _ = read_u32(data); // len
        item.addr = read_tlv_ip_addr(data).into();
        item.seen_time = read_u64(data);
        item.source = read_u32(data);
        item
    }

    #[test]
    fn test_tlv_ip_addr_info() {
        let orig = TlvIpAddressInfo {
            0: crate::tlv::tlv_ip_addr::TlvIpAddressInfoInner {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).into(),
                seen_time: 0x1337_1338_1339_1330,
                source: 0x42,
            },
        };
        let mut ser = to_retroshare_wire(&orig).unwrap();

        let expected =
            hex::decode("10700000002410720000001200850000000c0100007f901f133713381339133000000042")
                .unwrap();
        assert_eq!(ser, expected);

        let de_old = read_tlv_ip_address_info(&mut ser.clone());
        assert_eq!(orig, de_old);

        let de = from_retroshare_wire(&mut ser).unwrap();
        assert_eq!(orig, de);
    }

    // -----------------------
    // TlvIpAddrSet
    // -----------------------

    fn read_tlv_ip_addr_set(data: &mut Vec<u8>) -> TlvIpAddrSet {
        let mut item = TlvIpAddrSet { 0: HashSet::new() };
        assert_eq!(read_u16(data), TLV_IP_ADDR_SET_TAG); // const uint16_t TLV_TYPE_ADDRESS_SET   = 0x1071;
        let len = read_u32(data) as usize; // len
        let end_len = data.len() - (len - TLV_HEADER_SIZE);
        while data.len() > end_len {
            item.0.insert(read_tlv_ip_address_info(data));
        }
        item
    }

    fn write_tlv_ip_addr_set(data: &mut Vec<u8>, addrs: &TlvIpAddrSet) {
        let mut payload: Vec<u8> = vec![];
        for addr in &addrs.0 {
            let mut ip_payload: Vec<u8> = vec![];
            write_tlv_ip_addr(&mut ip_payload, &addr.addr.0);

            write_u16(&mut payload, TLV_IP_ADDR_INFO);
            write_u32(
                &mut payload,
                (TLV_HEADER_SIZE + ip_payload.len() + 8 + 4) as u32,
            );
            payload.append(&mut ip_payload);
            write_u64(&mut payload, addr.seen_time);
            write_u32(&mut payload, addr.source);
        }

        write_u16(data, TLV_IP_ADDR_SET_TAG);
        write_u32(data, (TLV_HEADER_SIZE + payload.len()) as u32);
        data.append(&mut payload);
    }

    #[test]
    fn test_tlv_ip_set() {
        let mut orig = TlvIpAddrSet::default();
        orig.0.insert(TlvIpAddressInfo {
            0: crate::tlv::tlv_ip_addr::TlvIpAddressInfoInner {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).into(),
                seen_time: 0x1337_1338_1339_1330,
                source: 0x42,
            },
        });
        let mut ser = to_retroshare_wire(&orig).unwrap();

        let expected = hex::decode(
            "10710000002a10700000002410720000001200850000000c0100007f901f133713381339133000000042",
        )
        .unwrap();
        assert_eq!(ser, expected);

        let mut expected_old = vec![];
        write_tlv_ip_addr_set(&mut expected_old, &orig);
        assert_eq!(ser, expected_old);

        let de_old = read_tlv_ip_addr_set(&mut ser.clone());
        assert_eq!(orig, de_old);

        let de = from_retroshare_wire(&mut ser).unwrap();
        assert_eq!(orig, de);
    }
}
