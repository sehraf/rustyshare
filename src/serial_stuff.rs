use byteorder::{ByteOrder, NetworkEndian};
use std::{
    // convert::TryInto,
    // io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    // sync::Arc,
    vec,
};

use crate::{
    parser::{self, headers::Header},
    services::Service,
};

#[allow(dead_code)]
pub fn read_u8(data: &Vec<u8>, offset: &mut usize) -> u8 {
    const SIZE: usize = 1;
    let r = data[*offset..*offset + SIZE][0];
    *offset += SIZE;
    r
}
#[allow(dead_code)]
pub fn read_u16(data: &Vec<u8>, offset: &mut usize) -> u16 {
    const SIZE: usize = 2;
    let r = NetworkEndian::read_u16(&data[*offset..*offset + SIZE]);
    // println!("{:?}, {:?}", &data[*offset..*offset + SIZE], r);
    *offset += SIZE;
    r
}
#[allow(dead_code)]
pub fn read_u32(data: &Vec<u8>, offset: &mut usize) -> u32 {
    const SIZE: usize = 4;
    let r = NetworkEndian::read_u32(&data[*offset..*offset + SIZE]);
    *offset += SIZE;
    r
}
#[allow(dead_code)]
pub fn read_u64(data: &Vec<u8>, offset: &mut usize) -> u64 {
    const SIZE: usize = 8;
    let r = NetworkEndian::read_u64(&data[*offset..*offset + SIZE]);
    *offset += SIZE;
    r
}
#[allow(dead_code)]
pub fn read_string(data: &Vec<u8>, offset: &mut usize) -> String {
    let str_len: usize = read_u32(data, offset) as usize;
    let s = String::from_utf8(data[*offset..*offset + str_len].to_owned()).unwrap();
    *offset += str_len;
    return s;
}
pub fn read_string_typed(data: &Vec<u8>, offset: &mut usize, typ: &u16) -> String {
    let t = read_u16(&data, offset); // type
    let s = read_u32(&data, offset); // len
    assert_eq!(t, *typ);
    assert_eq!(s >= 6, true);
    let str_len = s as usize - 6; // remove tlv header length
    let string = String::from_utf8(data[*offset..*offset + str_len].to_owned()).unwrap();
    *offset += str_len;
    string
}
pub fn read_tlv_ip_addr(data: &Vec<u8>, offset: &mut usize) -> Option<SocketAddr> {
    // onyl peek values!
    let mut offset_copy = offset.clone();

    let t = read_u16(&data, &mut offset_copy); // type
    let s = read_u32(&data, &mut offset_copy); // len
    assert_eq!(t, 0x1072); // const uint16_t TLV_TYPE_ADDRESS       = 0x1072;

    if s == 6 {
        *offset = offset_copy;
        return None;
    }

    // type
    match read_u16(&data, &mut offset_copy) {
        // now use original offset!
        0x0085 => return read_tlv_ip_addr_v4(data, offset),
        0x0086 => return read_tlv_ip_addr_v6(data, offset),
        t => panic!("unkown ip type {:04X} size {:?}", t, s),
    }
}
pub fn read_tlv_ip_addr_v4(data: &Vec<u8>, offset: &mut usize) -> Option<SocketAddr> {
    let t = read_u16(&data, offset); // type
    let s = read_u32(&data, offset); // len
    assert_eq!(t, 0x1072); // const uint16_t TLV_TYPE_ADDRESS       = 0x1072;
    return match s {
        6 => None,
        // current header (6) + coming header (6) + ipv4 (4) + port(2)
        18 => {
            assert_eq!(read_u16(&data, offset), 0x0085); // type, const uint16_t TLV_TYPE_IPV4          = 0x0085;
            assert_eq!(read_u32(&data, offset), 12); // len
            let addr_loc_v4 = {
                let ip = read_u32(&data, offset).swap_bytes(); // why?!
                let port = read_u16(&data, offset).swap_bytes();
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
            };
            Some(addr_loc_v4)
        }
        m => panic!("unkown ipv4 size {:?}", m),
    };
}
pub fn read_tlv_ip_addr_v6(data: &Vec<u8>, offset: &mut usize) -> Option<SocketAddr> {
    let t = read_u16(&data, offset); // type
    let s = read_u32(&data, offset); // len
    assert_eq!(t, 0x1072); // const uint16_t TLV_TYPE_ADDRESS       = 0x1072;
    return match s {
        6 => None,
        // current header (6) + coming header (6) + ipv4 (16) + port(2)
        30 => {
            assert_eq!(read_u16(&data, offset), 0x0086); // type, const uint16_t TLV_TYPE_IPV6          = 0x0086;
            assert_eq!(read_u32(&data, offset), 24); // len
            let mut ip: u128 = 0;
            for _ in 0..4 {
                ip = ip.overflowing_shl(32).0;
                ip += read_u32(&data, offset) as u128;
            }
            let port = read_u16(&data, offset).swap_bytes(); // why?!
            let ip = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port);
            Some(ip)
        }
        m => panic!("unkown ipv6 size {:?}", m),
    };
}
pub fn read_peer_net_item(
    data: &Vec<u8>,
    offset: &mut usize,
) -> (
    crate::retroshare_compat::PgpId,
    String,
    crate::retroshare_compat::SslId,
    Vec<SocketAddr>,
) {
    // helper for reading a varying amount of bytes
    let read = |data: &Vec<u8>, offset: &mut usize, len: &usize| -> Vec<u8> {
        let d = data[*offset..*offset + len].to_owned();
        *offset += len;
        d
    };

    // RsTypeSerializer::serial_process(j,ctx,nodePeerId,"peerId") ;
    let mut peer_id: crate::retroshare_compat::SslId = [0; 16];
    peer_id.copy_from_slice(read(&data, offset, &16).as_slice());
    // RsTypeSerializer::serial_process(j,ctx,pgpId,"pgpId") ;
    let mut pgp_id: crate::retroshare_compat::PgpId = [0; 8];
    pgp_id.copy_from_slice(read(&data, offset, &8).as_slice());
    // RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_LOCATION,location,"location") ;
    // const uint16_t TLV_TYPE_STR_LOCATION  = 0x005c;
    let location = read_string_typed(&data, offset, &0x005c);

    // RsTypeSerializer::serial_process<uint32_t>(j,ctx,netMode,"netMode") ;
    let _net_mode = read_u32(&data, offset);
    // RsTypeSerializer::serial_process<uint16_t>(j,ctx,vs_disc,"vs_disc") ;
    let _vs_disc = read_u16(&data, offset);
    // RsTypeSerializer::serial_process<uint16_t>(j,ctx,vs_dht,"vs_dht") ;
    let _vs_dht = read_u16(&data, offset);

    // RsTypeSerializer::serial_process<uint32_t>(j,ctx,lastContact,"lastContact") ;
    let _last_contact = std::time::Duration::from_secs(read_u32(&data, offset) as u64);

    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,localAddrV4,"localAddrV4") ;
    let addr_loc_v4 = read_tlv_ip_addr(&data, offset);
    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,extAddrV4,"extAddrV4") ;
    let addr_ext_v4 = read_tlv_ip_addr(&data, offset);

    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,localAddrV6,"localAddrV6") ;
    let addr_loc_v6 = read_tlv_ip_addr(&data, offset);
    if addr_loc_v6.is_some() {
        assert_eq!(addr_loc_v6.unwrap().is_ipv4(), true);
    }
    // dbg!(addr_loc_v6);
    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,extAddrV6,"extAddrV6") ;
    let addr_ext_v6 = read_tlv_ip_addr(&data, offset);
    if addr_ext_v6.is_some() {
        assert_eq!(addr_ext_v6.unwrap().is_ipv4(), true);
    }
    // dbg!(addr_ext_v6);
    // RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_DYNDNS,dyndns,"dyndns") ;
    let _dyndns = read_string_typed(&data, offset, &0x0083); // const uint16_t TLV_TYPE_STR_DYNDNS    = 0x0083;
                                                             // dbg!(dyndns);

    // prepare ips
    let mut ips: Vec<SocketAddr> = vec![];
    {
        let tmp = vec![addr_ext_v4, addr_ext_v6, addr_loc_v4, addr_loc_v6];
        for ip in tmp {
            if ip.is_some() {
                ips.push(ip.unwrap());
            }
        }
    }

    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,localAddrList,"localAddrList") ;
    // typedef t_RsTlvList<RsTlvIpAddressInfo,TLV_TYPE_ADDRESS_SET> RsTlvIpAddrSet;
    let t = read_u16(&data, offset); // type
    let s = read_u32(&data, offset); // len
    assert_eq!(t, 0x1071); // const uint16_t TLV_TYPE_ADDRESS_SET   = 0x1071;
    let s = s as usize - 6; // remove tlv header
    let s_end = *offset + s;
    while *offset < s_end {
        // RsTlvIpAddressInfo
        let t = read_u16(&data, offset); // type
        let _ = read_u32(&data, offset); // len
        assert_eq!(t, 0x1070); // const uint16_t TLV_TYPE_ADDRESS_INFO  = 0x1070;
        let ip = read_tlv_ip_addr(&data, offset);
        let _seen_time = read_u64(&data, offset);
        let _source = read_u32(&data, offset);
        // dbg!(ip, seen_time, source);

        if ip.is_some() {
            ips.push(ip.unwrap());
        }
    }

    // RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,extAddrList,"extAddrList") ;
    // typedef t_RsTlvList<RsTlvIpAddressInfo,TLV_TYPE_ADDRESS_SET> RsTlvIpAddrSet;
    let t = read_u16(&data, offset); // type
    let s = read_u32(&data, offset); // len
    assert_eq!(t, 0x1071); // const uint16_t TLV_TYPE_ADDRESS_SET   = 0x1071;
    let s = s as usize - 6; // remove tlv header
    let s_end = *offset + s;
    while *offset < s_end {
        // RsTlvIpAddressInfo
        let t = read_u16(&data, offset); // type
        let _ = read_u32(&data, offset); // len
        assert_eq!(t, 0x1070); // const uint16_t TLV_TYPE_ADDRESS_INFO  = 0x1070;
        let ip = read_tlv_ip_addr(&data, offset);
        let _seen_time = read_u64(&data, offset);
        let _source = read_u32(&data, offset);
        // dbg!(ip, seen_time, source);

        if ip.is_some() {
            ips.push(ip.unwrap());
        }
    }

    // RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_DOMADDR,domain_addr,"domain_addr") ;
    let _hidden_addr = read_string_typed(&data, offset, &0x0084); // const uint16_t TLV_TYPE_STR_DOMADDR   = 0x0084;

    // RsTypeSerializer::serial_process<uint16_t>(j,ctx,domain_port,"domain_port") ;
    let _hidden_port = read_u16(&data, offset);

    // println!("{:?}", &data_dec[offset_2..offset + (s as usize)]);
    // assert_eq!(offset_2, offset + s as usize);

    (pgp_id, location, peer_id, ips)
}

#[allow(dead_code)]
pub fn write_u16(data: &mut Vec<u8>, offset: &mut usize, val: u16) {
    const SIZE: usize = 2;
    let mut buf: [u8; SIZE] = [0; SIZE];
    NetworkEndian::write_u16(&mut buf, val);
    data.extend_from_slice(&buf);
    *offset += SIZE;
}
#[allow(dead_code)]
pub fn write_u32(data: &mut Vec<u8>, offset: &mut usize, val: u32) {
    const SIZE: usize = 4;
    let mut buf: [u8; SIZE] = [0; SIZE];
    NetworkEndian::write_u32(&mut buf, val);
    data.extend_from_slice(&buf);
    *offset += SIZE;
}
#[allow(dead_code)]
pub fn write_u64(data: &mut Vec<u8>, offset: &mut usize, val: u64) {
    const SIZE: usize = 8;
    let mut buf: [u8; SIZE] = [0; SIZE];
    NetworkEndian::write_u64(&mut buf, val);
    data.extend_from_slice(&buf);
    *offset += SIZE;
}
#[allow(dead_code)]
pub fn write_string(data: &mut Vec<u8>, offset: &mut usize, val: &str) {
    write_u32(data, offset, val.len() as u32); // len
    data.extend_from_slice(val.as_bytes());
    *offset += val.len();
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

pub fn gen_service_info(
    services: std::collections::hash_map::Values<u16, Box<dyn Service>>,
) -> Vec<u8> {
    const TLV_HEADER_SIZE: usize = 6;
    let mut inner_data: Vec<Vec<u8>> = vec![];

    for service in services {
        // get all necessary data
        let info = service.get_service_info();
        let service_number = (0x02 as u32) << 24 | (service.get_id() as u32) << 8;
        let mut offset = 0;
        let mut data: Vec<u8> = vec![];
        let body_size = info.0.len() + 4 + 4 + 2 * 4;

        // wirte initial header (6 bytes)
        let complete_size = body_size + TLV_HEADER_SIZE /* info struct tlv header */ + 10 /* service number */ + TLV_HEADER_SIZE /* this header */;
        write_u16(&mut data, &mut offset, 1);
        write_u32(&mut data, &mut offset, complete_size as u32);

        // add service info (10 bytes)
        write_u16(&mut data, &mut offset, 1); // type
        write_u32(&mut data, &mut offset, 10); // len
        write_u32(&mut data, &mut offset, service_number);

        // add info struct
        write_u16(&mut data, &mut offset, 1); // type
        write_u32(&mut data, &mut offset, (body_size + TLV_HEADER_SIZE) as u32); // len

        // write name
        write_string(&mut data, &mut offset, &info.0);

        // write service number
        write_u32(&mut data, &mut offset, service_number);

        // write version numbers (8 bytes)
        write_u16(&mut data, &mut offset, info.1);
        write_u16(&mut data, &mut offset, info.2);
        write_u16(&mut data, &mut offset, info.3);
        write_u16(&mut data, &mut offset, info.4);

        inner_data.push(data);
    }

    // build last main header
    let mut finished: Vec<u8> = vec![];
    let mut offset = 0;
    let mut size_complete = 0;
    for chunk in &inner_data {
        size_complete += chunk.len();
    }
    let header = parser::headers::Header::Service {
        service: crate::services::service_info::SERVICE_INFO_SERVICE,
        sub_type: crate::services::service_info::SERVICE_INFO_SUB_TYPE,
        size: (8 + size_complete + TLV_HEADER_SIZE) as u32, // include 8 byte header size
    };
    finished.extend_from_slice(&header.to_bytes());
    write_u16(&mut finished, &mut offset, 1); // type
    write_u32(
        &mut finished,
        &mut offset,
        (size_complete + TLV_HEADER_SIZE) as u32,
    ); // len
    for chunk in inner_data {
        finished.extend(chunk);
    }

    finished
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

    while offset < data_size {
        // get header
        let mut header: [u8; 8] = [0; 8];
        header.copy_from_slice(&data[offset..offset + 8]);
        let (class, typ, sub_type, packet_size) = match (Header::Raw { data: header }.try_parse()) {
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
                            // 0x03 => {
                            //     // RsPeerNetItem
                            //     // let (pgp_id, location, peer_id, ips) =
                            //     let (_, location, _, _) =
                            //         read_peer_net_item(&data, &mut offset_inner);
                            //     println!("loaded RsPeerNetItem of location {}", location);
                            // }
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
    }
}

#[cfg(test)]
mod tests {
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
        let c = crate::serial_stuff::gen_service_info(services.get_services());
        assert_eq!(a, c);
    }
}

// use proc_macro;
// use proc_macro::TokenStream;

// #[proc_macro_derive(Serialize, attributes(serde))]
// pub fn derive_serialize(input: TokenStream) -> TokenStream {
//     let input = parse_macro_input!(input as DeriveInput);
//     // ser::expand_derive_serialize(&input)
//     //     .unwrap_or_else(to_compile_errors)
//     //     .into()
// }

// #[proc_macro_derive(Deserialize, attributes(serde))]
// pub fn derive_deserialize(input: TokenStream) -> TokenStream {
//     let input = parse_macro_input!(input as DeriveInput);
//     // de::expand_derive_deserialize(&input)
//     //     .unwrap_or_else(to_compile_errors)
//     //     .into()
// }
