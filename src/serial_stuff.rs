use log::{info, warn};
use retroshare_compat::{
    config::{
        ConfigKeyValueSet, PeerBandwidthLimitsItem, PeerNetItem, PeerServicePermissionItem,
        RsNodeGroupItem,
    },
    keyring::Keyring,
    serde::from_retroshare_wire,
};
use std::sync::Arc;

use crate::{
    model::{location::Location, person::Peer},
    parser::headers::{Header, HEADER_SIZE},
};

pub fn parse_general_cfg(data: &mut Vec<u8>) -> () {
    while !data.is_empty() {
        // get header
        let header: Vec<u8> = data.drain(..8).collect();
        let (class, ty, sub_type, packet_size) = match Header::from(&header) {
            Header::Class {
                class,
                ty: typ,
                sub_type,
                size,
            } => (class, typ, sub_type, size),
            _ => panic!("This should not happen! Expected a class header!"),
        };

        // dbg!(class, typ, sub_type);
        match class {
            // const uint8_t RS_PKT_CLASS_CONFIG    = 0x02;
            0x02 => {
                // RsTlvKeyValueSet
                match ty {
                    // const uint8_t RS_PKT_TYPE_GENERAL_CONFIG = 0x01;
                    0x01 => {
                        // RsGeneralConfigSerialiser
                        match sub_type {
                            // const uint8_t RS_PKT_SUBTYPE_KEY_VALUE = 0x01;
                            0x01 => {
                                // RsConfigKeyValueSet
                                let item: ConfigKeyValueSet = from_retroshare_wire(data).unwrap();
                                for (key, value) in item.0 {
                                    info!("loaded RsGeneralConfigSerialiser/RsConfigKeyValueSet: {}: {}", key, value);
                                }
                            }
                            sub_type => {
                                warn!(
                                    "RsGeneralConfigSerialiser: invalid sub type {sub_type:02X}!"
                                );
                                data.drain(..packet_size as usize - HEADER_SIZE);
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
                            sub_type => {
                                warn!("unable to handle RsGeneralConfigSerialiser/RS_PKT_TYPE_PEER_CONFIG type (sub_type {sub_type:02X})");
                                data.drain(..packet_size as usize - HEADER_SIZE);
                            }
                        }
                    }
                    // const uint8_t RS_PKT_TYPE_CACHE_CONFIG   = 0x03;
                    // const uint8_t RS_PKT_TYPE_FILE_CONFIG    = 0x04;
                    // const uint8_t RS_PKT_TYPE_PLUGIN_CONFIG  = 0x05;
                    // const uint8_t RS_PKT_TYPE_HISTORY_CONFIG = 0x06;
                    m => warn!("unable to handle RsGeneralConfigSerialiser type {:02X}", m),
                }
            }
            m => warn!("unable to handle RsGeneralConfigSerialiser class {:02X}", m),
        }
        // assert_eq!(offset, offset_inner);
    }
}

pub fn load_peers(data: &mut Vec<u8>, keys: &Keyring) -> (Vec<Arc<Peer>>, Vec<Arc<Location>>) {
    let mut persons: Vec<Arc<Peer>> = vec![];
    let mut locations: Vec<Arc<Location>> = vec![];

    while !data.is_empty() {
        // get header
        let header: Vec<u8> = data.drain(..8).collect();
        let (class, ty, sub_type, packet_size) = match Header::from(&header) {
            Header::Class {
                class,
                ty: typ,
                sub_type,
                size,
            } => (class, typ, sub_type, size),
            _ => panic!("This should not happen! Expected a class header!"),
        };

        match class {
            // const uint8_t RS_PKT_CLASS_BASE      = 0x01;
            // const uint8_t RS_PKT_CLASS_CONFIG    = 0x02;
            0x02 => match ty {
                // const uint8_t RS_PKT_TYPE_GENERAL_CONFIG = 0x01;
                0x01 => {
                    // RsGeneralConfigSerialiser
                    match sub_type {
                        // const uint8_t RS_PKT_SUBTYPE_KEY_VALUE = 0x01;
                        0x01 => {
                            let item: ConfigKeyValueSet = from_retroshare_wire(data).unwrap();
                            for (key, value) in item.0 {
                                info!("[load_peers] KEY_VALUE {}: {}", key, value);
                            }
                        }
                        sub_type => {
                            warn!(
                                "unable to handle RsGeneralConfigSerialiser sub type {sub_type:02X}"
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
                            let (pgp_id, location, peer_id, ips) = {
                                let item: PeerNetItem = from_retroshare_wire(data).unwrap();

                                (
                                    item.pgp_id,
                                    item.location.into(),
                                    Arc::new(item.node_peer_id),
                                    (
                                        item.local_addr_list.0.into_iter().map(|ip| ip).collect(),
                                        item.ext_addr_list.0.into_iter().map(|ip| ip).collect(),
                                    ),
                                )
                            };

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

                                info!("adding peer {:?} with location {:?}", &name, &location);

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
                                    Arc::new(peer.get_pgp_id().to_owned()),
                                    ips,
                                    peer.to_owned(),
                                ));

                                peer.add_location(loc.to_owned());
                                locations.push(loc);
                            }
                        }
                        // const uint8_t RS_PKT_SUBTYPE_PEER_GROUP_deprecated = 0x04;
                        // const uint8_t RS_PKT_SUBTYPE_PEER_PERMISSIONS      = 0x05;
                        0x5 => {
                            let item: PeerServicePermissionItem =
                                from_retroshare_wire(data).expect("failed to deserialize");
                            for entry in item.entries {
                                info!(
                                    "[load_peers] PEER_PERMISSIONS {}: {:#032b}",
                                    entry.0, entry.1
                                );
                            }
                        }
                        // const uint8_t RS_PKT_SUBTYPE_PEER_BANDLIMITS       = 0x06;
                        0x6 => {
                            let entries: PeerBandwidthLimitsItem =
                                from_retroshare_wire(data).expect("failed to deserialize");
                            info!("Bandwidth: {:?}", entries);
                        }
                        // const uint8_t RS_PKT_SUBTYPE_NODE_GROUP            = 0x07;
                        0x07 => {
                            let group: RsNodeGroupItem =
                                from_retroshare_wire(data).expect("failed to deserialize");
                            info!("group info: {:?}", group);
                        }
                        sub_type => {
                            warn!(
                                "unable to handle RsPeerConfigSerialiser sub type {sub_type:02X}"
                            );
                            data.drain(..packet_size as usize - HEADER_SIZE);
                        }
                    }
                }
                // const uint8_t RS_PKT_TYPE_CACHE_CONFIG   = 0x03;
                // const uint8_t RS_PKT_TYPE_FILE_CONFIG    = 0x04;
                // const uint8_t RS_PKT_TYPE_PLUGIN_CONFIG  = 0x05;
                // const uint8_t RS_PKT_TYPE_HISTORY_CONFIG = 0x06;
                ty => warn!("unable to handle type {ty:02X}"),
            },
            class => warn!("unable to handle class {class:02X}"),
        }
    }

    // summarize
    println!("loaded the following:");
    for person in &persons {
        println!(" - person '{}'", person.get_name());
        let locs = person.get_locations();
        for loc in locs.iter() {
            println!("   - location '{}'", loc.get_name());
        }
    }

    (persons, locations)
}

#[cfg(test)]
mod tests {
    use byteorder::{ByteOrder, NetworkEndian};

    use crate::parser::headers::Header;

    fn write_u16(data: &mut Vec<u8>, offset: &mut usize, val: u16) {
        const SIZE: usize = 2;
        let mut buf: [u8; SIZE] = [0; SIZE];
        NetworkEndian::write_u16(&mut buf, val);
        data.extend_from_slice(&buf);
        *offset += SIZE;
    }

    fn write_u32(data: &mut Vec<u8>, offset: &mut usize, val: u32) {
        const SIZE: usize = 4;
        let mut buf: [u8; SIZE] = [0; SIZE];
        NetworkEndian::write_u32(&mut buf, val);
        data.extend_from_slice(&buf);
        *offset += SIZE;
    }

    fn gen_slice_probe() -> Vec<u8> {
        use crate::services::ServiceType;

        // vec![0x02, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x08]
        let header = Header::Service {
            service: ServiceType::SliceProbe,
            sub_type: 0xcc,
            size: 8,
        };
        let mut item: Vec<u8> = Vec::new();
        item.extend_from_slice(&header.to_bytes());
        item
    }

    fn gen_service_info_rtt() -> Vec<u8> {
        let mut data: Vec<u8> = vec![];
        let header = Header::Service {
            service: crate::services::ServiceType::ServiceInfo,
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
        // println!("{:?}", &data);
        data
    }

    #[test]
    fn slice_probe() {
        let a = gen_slice_probe();
        let b = vec![0x02, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x08];
        assert_eq!(a, b);
    }

    #[test]
    fn service_info_probe() {
        use crate::services::{rtt::Rtt, Services};
        let a = gen_service_info_rtt();
        let b = vec![
            2, 0, 32, 1, 0, 0, 0, 55, 0, 1, 0, 0, 0, 47, 0, 1, 0, 0, 0, 41, 0, 1, 0, 0, 0, 10, 2,
            16, 17, 0, 0, 1, 0, 0, 0, 25, 0, 0, 0, 3, 114, 116, 116, 2, 16, 17, 0, 0, 1, 0, 0, 0,
            1, 0, 0,
        ];
        assert_eq!(a, b);

        let mut services = Services::new();
        let rtt = Box::new(Rtt::new());
        services.add_service(rtt);
        let list = services.get_service_infos();
        let c = crate::services::service_info::gen_service_info(&list).to_bytes();
        assert_eq!(a, c);
    }
}
