use ::serde::{Deserialize, Serialize};

use crate::tlv::{tags::*, tlv_map::TlvMapWithPair, Tlv};

// struct RsServiceInfo : RsSerializable
// {
// 	RsServiceInfo();
// 	RsServiceInfo(
// 		const uint16_t service_type,
// 		const std::string& service_name,
// 		const uint16_t version_major,
// 		const uint16_t version_minor,
// 		const uint16_t min_version_major,
// 		const uint16_t min_version_minor);

// 	static unsigned int RsServiceInfoUIn16ToFullServiceId(uint16_t serviceType);

// 	std::string mServiceName;
// 	uint32_t    mServiceType;
// 	// current version, we running.
// 	uint16_t    mVersionMajor;
// 	uint16_t    mVersionMinor;
// 	// minimum version can communicate with.
// 	uint16_t    mMinVersionMajor;
// 	uint16_t    mMinVersionMinor;

// 	// RsSerializable interface
// 	void serial_process(RsGenericSerializer::SerializeJob j, RsGenericSerializer::SerializeContext &ctx) {
// 		RS_SERIAL_PROCESS(mServiceName);
// 		RS_SERIAL_PROCESS(mServiceType);
// 		RS_SERIAL_PROCESS(mVersionMajor);
// 		RS_SERIAL_PROCESS(mVersionMinor);
// 		RS_SERIAL_PROCESS(mMinVersionMajor);
// 		RS_SERIAL_PROCESS(mMinVersionMinor);
// 	}
// };

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RsServiceInfo {
    pub m_service_name: String,
    pub m_service_type: u32,
    pub m_version_major: u16,
    pub m_version_minor: u16,
    pub m_min_version_major: u16,
    pub m_min_version_minor: u16,
}

impl RsServiceInfo {
    pub fn new(id: u16, name: &str) -> Self {
        // TODO put this somewhere sound (with proper types)
        let service_number = (0x02 as u32) << 24 | (id as u32) << 8;

        RsServiceInfo {
            m_service_name: name.to_owned(),
            m_service_type: service_number,

            // TODO currently RS makes no use of these and they are all like this for each service
            m_version_major: 1,
            m_version_minor: 0,
            m_min_version_major: 1,
            m_min_version_minor: 0,
        }
    }
}

// class RsServiceInfoListItem: public RsItem
// {
// 	public:
// 	RsServiceInfoListItem()  :RsItem(RS_PKT_VERSION_SERVICE, RS_SERVICE_TYPE_SERVICEINFO, RS_PKT_SUBTYPE_SERVICELIST_ITEM)
// 	{
// 		setPriorityLevel(QOS_PRIORITY_RS_SERVICE_INFO_ITEM);
// 		return;
// 	}

//     virtual ~RsServiceInfoListItem(){}
// 	virtual void clear();

// 	virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 	std::map<uint32_t, RsServiceInfo> mServiceInfo;
// };

// impl From<TlvIpAddrSet> for TlvIpAddressInfo {
//     fn from(s: TlvIpAddrSet) -> Self {
//         s.0.into_iter().map(|ip| ip).collect()
//     }
// }
// make_tlv_id_map_type!(
//     TlvServiceInfoMapRef[TLV_SERVICE_INFO_TAG_MAP],
//     Pair[TLV_SERVICE_INFO_TAG_PAIR]<u32[TLV_SERVICE_INFO_TAG_KEY], RsServiceInfo[TLV_SERVICE_INFO_TAG_VALUE]>
// );
pub type TlvServiceInfoMapRef = TlvMapWithPair<
    TLV_SERVICE_INFO_TAG_MAP,
    TLV_SERVICE_INFO_TAG_PAIR,
    Tlv<TLV_SERVICE_INFO_TAG_KEY, u32>,
    Tlv<TLV_SERVICE_INFO_TAG_VALUE, RsServiceInfo>,
>;

impl From<Vec<RsServiceInfo>> for TlvServiceInfoMapRef {
    fn from(v: Vec<RsServiceInfo>) -> Self {
        Self(
            v.into_iter()
                .map(|info| (info.m_service_type.to_owned().into(), info.into()))
                .collect(),
        )
    }
}

#[cfg(test)]
mod test_tlv_map {
    use std::collections::HashMap;

    use crate::{
        read_u16, read_u32,
        serde::{from_retroshare_wire_result, to_retroshare_wire_result},
        services::service_info::TlvServiceInfoMapRef,
        tlv::TLV_HEADER_SIZE,
        write_u16, write_u32,
    };

    use super::RsServiceInfo;

    fn read_rs_service_info(payload: &mut Vec<u8>, services: &mut HashMap<u32, RsServiceInfo>) {
        // let mut offset = 0;
        // RsTlvGenericMapRef<uint32_t, RsServiceInfo> FUN!
        let _ = read_u16(payload); // type = 1
        let _ = read_u32(payload); // len

        while 0 < payload.len() {
            // let _old = payload.len();

            // RsTlvGenericPairRef moar FUN
            let _ = read_u16(payload); // type = 1
            let _ = read_u32(payload); // len

            // RsTlvParamRef we are getting there ...
            // key
            let _ = read_u16(payload); // type = 1
            let _ = read_u32(payload); // len
            let servcie_num = read_u32(payload);
            // value
            let _ = read_u16(payload); // type = 1
            let len = read_u32(payload) as usize; // len

            // read struct
            // copy data
            let mut val = payload.drain(..len - TLV_HEADER_SIZE).collect();
            let info: RsServiceInfo =
                from_retroshare_wire_result(&mut val).expect("failed to deserialise");

            services.insert(servcie_num, info);

            // offset += old - payload.len();
        }
    }

    fn write_rs_service_info(services: &Vec<RsServiceInfo>) -> Vec<u8> {
        let mut inner_data: Vec<Vec<u8>> = vec![];

        for service in services {
            let mut data: Vec<u8> = vec![];
            /*
             body_size =
              - name: len (4 bytes) + text (n-bytes)
              - type: u32 (4 bytes)
              - version: u16 + u16 (4 bytes)
              - version min: u16 + u16 (4 bytes)
            */
            let body_size = 4 + service.m_service_name.len() + 4 + 2 * 4;

            // wirte initial header (6 bytes)
            let complete_size = body_size + TLV_HEADER_SIZE /* info struct tlv header */ + 10 /* service number */ + TLV_HEADER_SIZE /* this header */;
            write_u16(&mut data, 1);
            write_u32(&mut data, complete_size as u32);

            // add service info (10 bytes)
            write_u16(&mut data, 1); // type
            write_u32(&mut data, TLV_HEADER_SIZE as u32 + 4); // len
            write_u32(&mut data, service.m_service_type);

            // add info struct
            write_u16(&mut data, 1); // type
            write_u32(&mut data, (TLV_HEADER_SIZE + body_size) as u32); // len

            // write actual service info
            let mut val = to_retroshare_wire_result(service).expect("failed to serialize");
            data.append(&mut val);

            inner_data.push(data);
        }

        let payload_inner: Vec<_> = inner_data.into_iter().flatten().collect();

        let mut payload = vec![];
        write_u16(&mut payload, 1); // type
        write_u32(&mut payload, (payload_inner.len() + TLV_HEADER_SIZE) as u32);
        payload.extend(payload_inner);

        payload
    }

    #[test]
    fn test_service_info() {
        let services = vec![
            RsServiceInfo {
                m_min_version_major: 1,
                m_min_version_minor: 2,
                m_service_name: "Dummy1".into(),
                m_service_type: 3,
                m_version_major: 4,
                m_version_minor: 5,
            },
            // RsServiceInfo {
            //     m_min_version_major: 6,
            //     m_min_version_minor: 7,
            //     m_service_name: "Dummy2".into(),
            //     m_service_type: 8,
            //     m_version_major: 9,
            //     m_version_minor: 0,
            // },
        ];

        let mut ser_old = write_rs_service_info(&services);

        let si: TlvServiceInfoMapRef = services.into();
        let mut ser = to_retroshare_wire_result(&si).unwrap();

        assert_eq!(ser, ser_old);

        let expected = hex::decode("00010000003200010000002c00010000000a0000000300010000001c0000000644756d6d7931000000030004000500010002").unwrap();

        assert_eq!(ser, expected);

        let mut de_old = HashMap::new();
        read_rs_service_info(&mut ser_old, &mut de_old);
        let de: TlvServiceInfoMapRef = from_retroshare_wire_result(&mut ser).unwrap();

        assert_eq!(de, si);
        assert_eq!(
            si.0,
            de_old
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect()
        );
    }
}
