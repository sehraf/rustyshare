use byteorder::{ByteOrder, NetworkEndian};
use retroshare_compat::{
    basics::*,
    groups::*,
    keyring::Keyring,
    read_u16, read_u32,
    serde::from_retroshare_wire,
    tlv::{
        read_string_typed, read_tlv_ip_addr, read_tlv_ip_addr_set, TlvIpAddressInfo,
        TLV_HEADER_SIZE,
    },
};
use std::{collections::HashSet, sync::Arc};

use crate::{
    model::peers::{location::Location, Peer},
    parser::{
        self,
        headers::{Header, HEADER_SIZE},
    },
};

// #[allow(dead_code)]
// pub fn read_u8(data: &Vec<u8>, offset: &mut usize) -> u8 {
//     const SIZE: usize = 1;
//     let r = data[*offset..*offset + SIZE][0];
//     *offset += SIZE;
//     r
// }
// #[allow(dead_code)]
// pub fn read_u16(data: &Vec<u8>, offset: &mut usize) -> u16 {
//     const SIZE: usize = 2;
//     let r = NetworkEndian::read_u16(&data[*offset..*offset + SIZE]);
//     // println!("{:?}, {:?}", &data[*offset..*offset + SIZE], r);
//     *offset += SIZE;
//     r
// }
// #[allow(dead_code)]
// pub fn read_u32(data: &Vec<u8>, offset: &mut usize) -> u32 {
//     const SIZE: usize = 4;
//     let r = NetworkEndian::read_u32(&data[*offset..*offset + SIZE]);
//     *offset += SIZE;
//     r
// }
// #[allow(dead_code)]
// pub fn read_u64(data: &Vec<u8>, offset: &mut usize) -> u64 {
//     const SIZE: usize = 8;
//     let r = NetworkEndian::read_u64(&data[*offset..*offset + SIZE]);
//     *offset += SIZE;
//     r
// }
// #[allow(dead_code)]
// pub fn read_string(data: &Vec<u8>, offset: &mut usize) -> String {
//     let str_len: usize = read_u32(data, offset) as usize;
//     let s = String::from_utf8(data[*offset..*offset + str_len].to_owned()).unwrap();
//     *offset += str_len;
//     return s;
// }
// pub fn read_string_typed(data: &Vec<u8>, offset: &mut usize, typ: &u16) -> String {
//     // let old = offset.clone();
//     let t = read_u16(&data, offset); // type
//     let s = read_u32(&data, offset); // len
//     assert_eq!(t, *typ);
//     assert_eq!(s >= 6, true);
//     let str_len = s as usize - 6; // remove tlv header length
//     let string = String::from_utf8(data[*offset..*offset + str_len].to_owned()).unwrap();
//     // let copy = &data[old..*offset + str_len];

//     *offset += str_len;

//     // let copy: Vec<u8> = Vec::from(copy);
//     // println!("{}", hex::encode(copy));

//     string
// }
// pub fn read_tlv_ip_addr(data: &Vec<u8>, offset: &mut usize) -> Option<SocketAddr> {
//     // onyl peek values!
//     let mut offset_copy = offset.clone();

//     let t = read_u16(&data, &mut offset_copy); // type
//     let s = read_u32(&data, &mut offset_copy); // len
//     assert_eq!(t, 0x1072); // const uint16_t TLV_TYPE_ADDRESS       = 0x1072;

//     if s == 6 {
//         *offset = offset_copy;
//         return None;
//     }

//     // type
//     match read_u16(&data, &mut offset_copy) {
//         // now use original offset!
//         0x0085 => return read_tlv_ip_addr_v4(data, offset),
//         0x0086 => return read_tlv_ip_addr_v6(data, offset),
//         t => panic!("unkown ip type {:04X} size {:?}", t, s),
//     }
// }
// pub fn read_tlv_ip_addr_v4(data: &Vec<u8>, offset: &mut usize) -> Option<SocketAddr> {
//     let t = read_u16(&data, offset); // type
//     let s = read_u32(&data, offset); // len
//     assert_eq!(t, 0x1072); // const uint16_t TLV_TYPE_ADDRESS       = 0x1072;
//     return match s {
//         6 => None,
//         // current header (6) + coming header (6) + ipv4 (4) + port(2)
//         18 => {
//             assert_eq!(read_u16(&data, offset), 0x0085); // type, const uint16_t TLV_TYPE_IPV4          = 0x0085;
//             assert_eq!(read_u32(&data, offset), 12); // len
//             let addr_loc_v4 = {
//                 let ip = read_u32(&data, offset).swap_bytes(); // why?!
//                 let port = read_u16(&data, offset).swap_bytes();
//                 SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
//             };
//             Some(addr_loc_v4)
//         }
//         m => panic!("unkown ipv4 size {:?}", m),
//     };
// }
// pub fn read_tlv_ip_addr_v6(data: &Vec<u8>, offset: &mut usize) -> Option<SocketAddr> {
//     let t = read_u16(&data, offset); // type
//     let s = read_u32(&data, offset); // len
//     assert_eq!(t, 0x1072); // const uint16_t TLV_TYPE_ADDRESS       = 0x1072;
//     return match s {
//         6 => None,
//         // current header (6) + coming header (6) + ipv4 (16) + port(2)
//         30 => {
//             assert_eq!(read_u16(&data, offset), 0x0086); // type, const uint16_t TLV_TYPE_IPV6          = 0x0086;
//             assert_eq!(read_u32(&data, offset), 24); // len
//             let mut ip: u128 = 0;
//             for _ in 0..4 {
//                 ip = ip.overflowing_shl(32).0;
//                 ip += read_u32(&data, offset) as u128;
//             }
//             let port = read_u16(&data, offset).swap_bytes(); // why?!
//             let ip = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port);
//             Some(ip)
//         }
//         m => panic!("unkown ipv6 size {:?}", m),
//     };
// }
pub fn read_peer_net_item(
    data: &mut Vec<u8>,
) -> (
    PgpId,
    String,
    PeerId,
    (HashSet<TlvIpAddressInfo>, HashSet<TlvIpAddressInfo>),
) {
    // RsTypeSerializer::serial_process(j,ctx,nodePeerId,"peerId") ;
    let mut peer_id = [0u8; 16];
    let d: Vec<u8> = data.drain(..16).collect();
    peer_id.copy_from_slice(d.as_slice());
    let peer_id = PeerId(peer_id);

    // RsTypeSerializer::serial_process(j,ctx,pgpId,"pgpId") ;
    let mut pgp_id = [0u8; 8];
    let d: Vec<u8> = data.drain(..8).collect();
    pgp_id.copy_from_slice(d.as_slice());
    let pgp_id = PgpId(pgp_id);

    // RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_LOCATION,location,"location") ;
    // const uint16_t TLV_TYPE_STR_LOCATION  = 0x005c;
    let location = read_string_typed(data, 0x005c);

    // RsTypeSerializer::serial_process<uint32_t>(j,ctx,netMode,"netMode") ;
    let _net_mode = read_u32(data);
    // RsTypeSerializer::serial_process<uint16_t>(j,ctx,vs_disc,"vs_disc") ;
    let _vs_disc = read_u16(data);
    // RsTypeSerializer::serial_process<uint16_t>(j,ctx,vs_dht,"vs_dht") ;
    let _vs_dht = read_u16(data);

    // RsTypeSerializer::serial_process<uint32_t>(j,ctx,lastContact,"lastContact") ;
    let _last_contact = read_u32(data);

    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,localAddrV4,"localAddrV4") ;
    let _addr_loc_v4 = read_tlv_ip_addr(data);
    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,extAddrV4,"extAddrV4") ;
    let _addr_ext_v4 = read_tlv_ip_addr(data);

    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,localAddrV6,"localAddrV6") ;
    let _addr_loc_v6 = read_tlv_ip_addr(data);
    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,extAddrV6,"extAddrV6") ;
    let _addr_ext_v6 = read_tlv_ip_addr(data);

    // RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_DYNDNS,dyndns,"dyndns") ;
    let _dyndns = read_string_typed(data, 0x0083); // const uint16_t TLV_TYPE_STR_DYNDNS    = 0x0083;

    // prepare ips
    let mut ips_local: HashSet<TlvIpAddressInfo> = HashSet::new();
    let mut ips_external: HashSet<TlvIpAddressInfo> = HashSet::new();

    // for ip in vec![addr_loc_v4, addr_loc_v6] {
    //     ips_local.insert(ip);
    // }

    // for ip in vec![addr_ext_v4, addr_ext_v6] {
    //     ips_external.insert(ip);
    // }

    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,localAddrList,"localAddrList") ;
    read_tlv_ip_addr_set(data).0.into_iter().for_each(|ip| {
        ips_local.insert(ip);
    });
    read_tlv_ip_addr_set(data).0.into_iter().for_each(|ip| {
        ips_external.insert(ip);
    });

    // RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_DOMADDR,domain_addr,"domain_addr") ;
    let _hidden_addr = read_string_typed(data, 0x0084); // const uint16_t TLV_TYPE_STR_DOMADDR   = 0x0084;

    // RsTypeSerializer::serial_process<uint16_t>(j,ctx,domain_port,"domain_port") ;
    let _hidden_port = read_u16(data);

    (pgp_id, location, peer_id, (ips_local, ips_external))
}

#[cfg(test)]
pub fn write_u16(data: &mut Vec<u8>, offset: &mut usize, val: u16) {
    const SIZE: usize = 2;
    let mut buf: [u8; SIZE] = [0; SIZE];
    NetworkEndian::write_u16(&mut buf, val);
    data.extend_from_slice(&buf);
    *offset += SIZE;
}
pub fn write_u32(data: &mut Vec<u8>, offset: &mut usize, val: u32) {
    const SIZE: usize = 4;
    let mut buf: [u8; SIZE] = [0; SIZE];
    NetworkEndian::write_u32(&mut buf, val);
    data.extend_from_slice(&buf);
    *offset += SIZE;
}
pub fn write_u64(data: &mut Vec<u8>, offset: &mut usize, val: u64) {
    const SIZE: usize = 8;
    let mut buf: [u8; SIZE] = [0; SIZE];
    NetworkEndian::write_u64(&mut buf, val);
    data.extend_from_slice(&buf);
    *offset += SIZE;
}

pub fn gen_slice_probe() -> Vec<u8> {
    // vec![0x02, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x08]
    let header = parser::headers::Header::Service {
        service: 0xaabb,
        sub_type: 0xcc,
        size: 8,
    };
    let mut item: Vec<u8> = Vec::new();
    item.extend_from_slice(&header.to_bytes());
    item
}

// static (old) version
#[cfg(test)]
pub fn gen_service_info_rtt() -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    let header = parser::headers::Header::Service {
        service: 0x0020,
        sub_type: 0x01,
        size: 8 + 41 + 6,
    };
    data.extend_from_slice(&header.to_bytes());

    let mut offset = 0;
    //     // RsTlvGenericMapRef<uint32_t, RsServiceInfo> FUN!
    // let _ = ServiceInfo::read_u16(payload, &mut offset); // type
    // let _ = ServiceInfo::read_u32(payload, &mut offset); // len
    write_u16(&mut data, &mut offset, 1);
    write_u32(&mut data, &mut offset, 47);

    // while offset < payload.len() {
    //     // RsTlvGenericPairRef moar FUN
    //     let _ = ServiceInfo::read_u16(payload, &mut offset); // type
    //     let _ = ServiceInfo::read_u32(payload, &mut offset); // len
    write_u16(&mut data, &mut offset, 1);
    write_u32(&mut data, &mut offset, 41);

    //     // RsTlvParamRef we are getting there ...
    //     // key
    //     let _ = ServiceInfo::read_u16(payload, &mut offset); // type
    //     let _ = ServiceInfo::read_u32(payload, &mut offset); // len
    //     let servcie_num = ServiceInfo::read_u32(payload, &mut offset);
    write_u16(&mut data, &mut offset, 1);
    write_u32(&mut data, &mut offset, 10);
    write_u32(&mut data, &mut offset, 0x02101100);
    //     // value
    //     let _ = ServiceInfo::read_u16(payload, &mut offset); // type
    //     let _ = ServiceInfo::read_u32(payload, &mut offset); // len
    write_u16(&mut data, &mut offset, 1);
    write_u32(&mut data, &mut offset, 25);
    //     let mut info = RsServiceInfo {
    //         mServiceName: String::new(),
    //         mServiceType: 0,
    //         mVersionMajor: 0,
    //         mVersionMinor: 0,
    //         mMinVersionMajor: 0,
    //         mMinVersionMinor: 0,
    //     };
    //     // read struct
    //     {
    //         let str_len: usize = ServiceInfo::read_u32(payload, &mut offset) as usize;
    write_u32(&mut data, &mut offset, 0x3);

    //         info.mServiceName =
    //             String::from_utf8(payload[offset..offset + str_len].to_owned()).unwrap();
    //         offset += str_len;
    let s = "rtt";
    data.extend_from_slice(s.as_bytes());
    offset += 3;
    //         info.mServiceType = ServiceInfo::read_u32(payload, &mut offset);
    write_u32(&mut data, &mut offset, 0x02101100);
    // unsigned int RsServiceInfo::RsServiceInfoUIn16ToFullServiceId(uint16_t serviceType)
    // {
    //   return (((uint32_t) RS_PKT_VERSION_SERVICE) << 24) + (((uint32_t) serviceType) << 8);
    // }

    //         info.mVersionMajor = ServiceInfo::read_u16(payload, &mut offset);
    write_u16(&mut data, &mut offset, 1);
    //         info.mVersionMinor = ServiceInfo::read_u16(payload, &mut offset);
    write_u16(&mut data, &mut offset, 0);
    //         info.mMinVersionMajor = ServiceInfo::read_u16(payload, &mut offset);
    write_u16(&mut data, &mut offset, 1);
    //         info.mMinVersionMinor = ServiceInfo::read_u16(payload, &mut offset);
    write_u16(&mut data, &mut offset, 0);
    //     }
    // }
    println!("{:?}", &data);
    data
}

pub fn parse_general_cfg(data: &Vec<u8>) -> () {
    let mut offset = 0;
    let data_size = data.len();

    // helper for reading a varying amount of bytes
    // let read = |data: &Vec<u8>, offset: &mut usize, len: &usize| -> Vec<u8> {
    //     let d = data[*offset..*offset + len].to_owned();
    //     *offset += len;
    //     d
    // };

    // TODO port to new code
    let read_u16 = |data: &Vec<u8>, offset: &mut usize| -> u16 {
        const SIZE: usize = 2;
        let r = NetworkEndian::read_u16(&data[*offset..*offset + SIZE]);
        // println!("{:?}, {:?}", &data[*offset..*offset + SIZE], r);
        *offset += SIZE;
        r
    };

    let read_u32 = |data: &Vec<u8>, offset: &mut usize| -> u32 {
        const SIZE: usize = 4;
        let r = NetworkEndian::read_u32(&data[*offset..*offset + SIZE]);
        *offset += SIZE;
        r
    };

    let read_string_typed = |data: &Vec<u8>, offset: &mut usize, typ: &u16| -> String {
        // let old = offset.clone();
        let t = read_u16(&data, offset); // type
        let s = read_u32(&data, offset); // len
        assert_eq!(t, *typ);
        assert_eq!(s >= 6, true);
        let str_len = s as usize - 6; // remove tlv header length
        let string = String::from_utf8(data[*offset..*offset + str_len].to_owned()).unwrap();
        *offset += str_len;
        string
    };

    while offset < data_size {
        // get header
        let mut header: [u8; 8] = [0; 8];
        header.copy_from_slice(&data[offset..offset + 8]);
        let (class, typ, sub_type, packet_size) = match Header::try_parse(header) {
            Ok(header) => match header {
                Header::Class {
                    class,
                    typ,
                    sub_type,
                    size,
                } => (class, typ, sub_type, size),
                _ => panic!("This should not happen! Expected a class header!"),
            },
            Err(why) => {
                panic!("failed to read header: {:?}", why);
            }
        };
        // header read
        offset += 8;

        // used for parsing individual packets
        let mut offset_inner = offset.clone();

        // used for tracking packet end
        offset += packet_size as usize - 8; // header was already removed

        // dbg!(class, typ, sub_type);
        match class {
            // const uint8_t RS_PKT_CLASS_CONFIG    = 0x02;
            0x02 => {
                // RsTlvKeyValueSet
                match typ {
                    // const uint8_t RS_PKT_TYPE_GENERAL_CONFIG = 0x01;
                    0x01 => {
                        // RsGeneralConfigSerialiser
                        match sub_type {
                            // const uint8_t RS_PKT_SUBTYPE_KEY_VALUE = 0x01;
                            0x01 => {
                                // RsConfigKeyValueSet

                                // const uint16_t TLV_TYPE_KEYVALUESET   = 0x1011;
                                let t = read_u16(&data, &mut offset_inner);
                                assert_eq!(t, 0x1011);

                                // size without 6 byte TLV header
                                let size = read_u32(&data, &mut offset_inner);
                                assert_eq!(size as usize - 6 + offset_inner, offset);

                                while offset_inner < offset {
                                    // RsTlvKeyValue kv;
                                    //  - this are just a bunch of strings with an header

                                    // header
                                    // const uint16_t TLV_TYPE_KEYVALUE      = 0x1010;
                                    let t = read_u16(&data, &mut offset_inner); // type
                                    let size = read_u32(&data, &mut offset_inner); // len
                                    let check = offset_inner;
                                    assert_eq!(t, 0x1010);

                                    // const uint16_t TLV_TYPE_STR_KEY       = 0x0053;
                                    let key = read_string_typed(&data, &mut offset_inner, &0x0053);
                                    // const uint16_t TLV_TYPE_STR_VALUE     = 0x0054;
                                    let value =
                                        read_string_typed(&data, &mut offset_inner, &0x0054);
                                    println!("loaded RsGeneralConfigSerialiser/RsConfigKeyValueSet: {}: {}", key, value);

                                    // this must be the end
                                    assert_eq!(offset_inner, check + size as usize - 6);
                                }
                            }
                            m => {
                                println!(
                                    "unable to handle RsGeneralConfigSerialiser sub type {:02X}",
                                    m
                                );
                                panic!("invalid sub type!")
                            }
                        }
                    }
                    // const uint8_t RS_PKT_TYPE_PEER_CONFIG    = 0x02;
                    0x02 => {
                        match sub_type {
                            // const uint8_t RS_PKT_SUBTYPE_PEER_STUN             = 0x02;
                            // const uint8_t RS_PKT_SUBTYPE_PEER_NET              = 0x03;
                            // const uint8_t RS_PKT_SUBTYPE_PEER_GROUP_deprecated = 0x04;
                            // const uint8_t RS_PKT_SUBTYPE_PEER_PERMISSIONS      = 0x05;
                            // const uint8_t RS_PKT_SUBTYPE_PEER_BANDLIMITS       = 0x06;
                            // const uint8_t RS_PKT_SUBTYPE_NODE_GROUP            = 0x07;
                            m => {
                                println!("unable to handle RsGeneralConfigSerialiser/RS_PKT_TYPE_PEER_CONFIG type (sub_type {:02X})", m);
                            }
                        }
                    }
                    // const uint8_t RS_PKT_TYPE_CACHE_CONFIG   = 0x03;
                    // const uint8_t RS_PKT_TYPE_FILE_CONFIG    = 0x04;
                    // const uint8_t RS_PKT_TYPE_PLUGIN_CONFIG  = 0x05;
                    // const uint8_t RS_PKT_TYPE_HISTORY_CONFIG = 0x06;
                    m => println!("unable to handle RsGeneralConfigSerialiser type {:02X}", m),
                }
            }
            m => println!("unable to handle RsGeneralConfigSerialiser class {:02X}", m),
        }
        assert_eq!(offset, offset_inner);
    }
}

pub fn load_peers(data: &mut Vec<u8>, keys: &Keyring) -> (Vec<Arc<Peer>>, Vec<Arc<Location>>) {
    let mut persons: Vec<Arc<Peer>> = vec![];
    let mut locations: Vec<Arc<Location>> = vec![];

    while !data.is_empty() {
        // get header
        let header: Vec<u8> = data.drain(..8).collect();
        let (class, typ, sub_type, packet_size) = match Header::from(&header) {
            Header::Class {
                class,
                typ,
                sub_type,
                size,
            } => (class, typ, sub_type, size),
            _ => panic!("This should not happen! Expected a class header!"),
        };

        match class {
            // const uint8_t RS_PKT_CLASS_BASE      = 0x01;
            // const uint8_t RS_PKT_CLASS_CONFIG    = 0x02;
            0x02 => match typ {
                // const uint8_t RS_PKT_TYPE_GENERAL_CONFIG = 0x01;
                0x01 => {
                    // RsGeneralConfigSerialiser
                    match sub_type {
                        // const uint8_t RS_PKT_SUBTYPE_KEY_VALUE = 0x01;
                        0x01 => {
                            // const uint16_t TLV_TYPE_KEYVALUESET   = 0x1011;
                            assert_eq!(read_u16(data), 0x1011); // tag

                            // size without 6 byte TLV header
                            let size = read_u32(data) as usize;
                            // simple check to verify the various sizes/lengths
                            assert_eq!(size, packet_size as usize - HEADER_SIZE);

                            let end = data.len() - (size - TLV_HEADER_SIZE);
                            while data.len() > end {
                                // RsTlvKeyValue kv;

                                // const uint16_t TLV_TYPE_KEYVALUE      = 0x1010;
                                assert_eq!(read_u16(data), 0x1010); // tag
                                let len = read_u32(data) as usize; // len

                                // simple check to verify the length
                                let end = data.len() - (len - TLV_HEADER_SIZE);

                                // const uint16_t TLV_TYPE_STR_KEY       = 0x0053;
                                let key = read_string_typed(data, 0x0053);
                                // const uint16_t TLV_TYPE_STR_VALUE     = 0x0054;
                                let value = read_string_typed(data, 0x0054);
                                println!("{}: {}", key, value);

                                assert_eq!(end, data.len());
                            }
                        }
                        m => {
                            println!(
                                "unable to handle RsGeneralConfigSerialiser sub type {:02X}",
                                m
                            );
                            data.drain(..packet_size as usize - HEADER_SIZE);
                        }
                    }
                }
                // const uint8_t RS_PKT_TYPE_PEER_CONFIG    = 0x02;
                0x2 => {
                    // RsPeerConfigSerialiser
                    match sub_type {
                        // const uint8_t RS_PKT_SUBTYPE_PEER_STUN             = 0x02;
                        // const uint8_t RS_PKT_SUBTYPE_PEER_NET              = 0x03;
                        0x3 => {
                            let (pgp_id, location, peer_id, ips) = read_peer_net_item(data);

                            // lookup key
                            if let Some(pgp) = keys.get_key_by_id_bytes(&pgp_id, false) {
                                let name = {
                                    let mut s2: String = String::new();
                                    for ua in pgp.userids() {
                                        let s3 = String::from_utf8_lossy(ua.value());
                                        s2.push_str(&s3);
                                    }
                                    s2
                                };

                                println!("adding peer {:?} with location {:?}", &name, &location);

                                let mut peer =
                                    persons.iter_mut().find(|p| p.get_pgp_id() == &pgp_id);

                                if peer.is_none() {
                                    persons.push(Arc::new(Peer::new(name, pgp.clone(), pgp_id)));
                                    peer = persons.last_mut();
                                }

                                // this shall not crash
                                let peer = peer.unwrap();

                                let loc = Arc::new(Location::new(
                                    location,
                                    peer_id,
                                    peer.get_pgp_id().clone(),
                                    ips,
                                    Arc::downgrade(peer),
                                ));

                                peer.add_location(Arc::downgrade(&loc));
                                locations.push(loc);
                            }
                        }
                        // const uint8_t RS_PKT_SUBTYPE_PEER_GROUP_deprecated = 0x04;
                        // const uint8_t RS_PKT_SUBTYPE_PEER_PERMISSIONS      = 0x05;
                        0x5 => {
                            let len = read_u32(data);
                            for i in 0..len {
                                let mut pgp_id = [0u8; 8];
                                let d: Vec<u8> = data.drain(..8).collect();
                                pgp_id.copy_from_slice(d.as_slice());
                                let pgp_id = PgpId(pgp_id);

                                // #define FLAGS_TAG_SERVICE_PERM 	0x380912
                                let flags = read_u32(data);

                                println!("[{:02}] {}: {:#032b}", i, pgp_id, flags);
                            }
                        }
                        // const uint8_t RS_PKT_SUBTYPE_PEER_BANDLIMITS       = 0x06;
                        0x6 => {
                            let entries: RsPeerBandwidthLimitsItem =
                                from_retroshare_wire(data).expect("failed to deserialize");
                            println!("Bandwidth: {:?}", entries);
                        }
                        // const uint8_t RS_PKT_SUBTYPE_NODE_GROUP            = 0x07;
                        0x07 => {
                            let group = read_rs_node_group_item(data);
                            println!("group info: {:?}", group);
                        }
                        m => {
                            println!("unable to handle RsPeerConfigSerialiser sub type {:02X}", m);
                            data.drain(..packet_size as usize - HEADER_SIZE);
                        }
                    }
                }
                // const uint8_t RS_PKT_TYPE_CACHE_CONFIG   = 0x03;
                // const uint8_t RS_PKT_TYPE_FILE_CONFIG    = 0x04;
                // const uint8_t RS_PKT_TYPE_PLUGIN_CONFIG  = 0x05;
                // const uint8_t RS_PKT_TYPE_HISTORY_CONFIG = 0x06;
                m => println!("unable to handle type {:02X}", m),
            },
            m => println!("unable to handle class {:02X}", m),
        }
    }

    // summarize
    println!("loaded the following:");
    for person in &persons {
        println!(" - person '{}'", person.get_name());
        let locs = person.get_locations();
        for loc in locs.iter() {
            let loc = loc.upgrade();
            if let Some(loc) = loc {
                println!("   - location '{}'", loc.get_name());
            } else {
                unreachable!("We just allocated the locations, an upgrade should work fine!");
            }
        }
    }

    (persons, locations)
}

#[cfg(test)]
mod tests {
    use retroshare_compat::service_info::RsServiceInfo;

    #[test]
    fn slice_probe() {
        let a = crate::serial_stuff::gen_slice_probe();
        let b = vec![0x02, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x08];
        assert_eq!(a, b);
    }

    #[test]
    fn service_info_probe() {
        use crate::services::{rtt::Rtt, Services};
        let a = crate::serial_stuff::gen_service_info_rtt();
        let b = vec![
            2, 0, 32, 1, 0, 0, 0, 55, 0, 1, 0, 0, 0, 47, 0, 1, 0, 0, 0, 41, 0, 1, 0, 0, 0, 10, 2,
            16, 17, 0, 0, 1, 0, 0, 0, 25, 0, 0, 0, 3, 114, 116, 116, 2, 16, 17, 0, 0, 1, 0, 0, 0,
            1, 0, 0,
        ];
        assert_eq!(a, b);

        let mut services = Services::new();
        let rtt = Box::new(Rtt::new());
        services.add_service(rtt);
        let list: Vec<RsServiceInfo> = services.get_services().map(|s| s.into()).collect();
        let c = crate::services::service_info::gen_service_info(&list).to_bytes();
        assert_eq!(a, c);
    }

    // #[test]
    // fn service_info_probe_serde() {
    //     // use retroshare_compat::{basics::*, service_info::*};
    //     use retroshare_compat_derive::{from_retroshare_wire, to_retroshare_wire};

    //     let mut a = vec![
    //         // 2, 0, 32, 1, 0, 0, 0, 55, // header
    //         // 0, 1, 0, 0, 0, 47, // TL
    //         0, 1, 0, 0, 0, 41, // RsTlvGenericMapRef header
    //         0, 1, 0, 0, 0, 10, // RsTlvParamRef key header
    //         2, 16, 17, 0, //  RsTlvParamRef key
    //         0, 1, 0, 0, 0, 25, // RsTlvParamRef value header
    //         0, 0, 0, 3, // RsTlvParamRef value: String len
    //         114, 116, 116, // RsTlvParamRef value: String
    //         2, 16, 17, 0, // RsTlvParamRef value: service type
    //         0, 1, 0, 0, // RsTlvParamRef value: version major/minor
    //         0, 1, 0, 0, // RsTlvParamRef value: min version major/minor
    //     ];

    //     // let mut pairs: Vec<RsTlvGenericPairRef<u32, RsServiceInfo>> = Vec::new();
    //     // pairs.push(RsTlvGenericPairRef {
    //     //     m_key: RsTlvParamRef {
    //     //         m_param: 0x02101100,
    //     //     },
    //     //     m_value: RsTlvParamRef {
    //     //         m_param: RsServiceInfo {
    //     //             m_service_name: String::from("rtt"),
    //     //             m_min_version_major: 1,
    //     //             m_min_version_minor: 0,
    //     //             m_version_major: 1,
    //     //             m_version_minor: 0,
    //     //             m_service_type: 0x02101100,
    //     //         },
    //     //     },
    //     // });
    //     // let b = RsServiceInfoListItem {
    //     //     m_service_info: RsTlvGenericMapRef {
    //     //         m_ref_map: pairs,
    //     //     },
    //     // };
    //     // let ser = to_retroshare_wire(&b).expect("failed to serialize");
    //     // assert_eq!(a, ser);

    //     // let b: RsServiceInfoListItem = from_retroshare_wire(&mut a).expect("failed to deserialize");
    //     // let c = to_retroshare_wire(&b).expect("failed to serialize");
    //     // dbg!(a, b, c);
    //     // assert_eq!(a, b);
    // }
}
