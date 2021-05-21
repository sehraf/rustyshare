use ::serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    serde::{from_retroshare_wire, to_retroshare_wire},
    tlv::TLV_HEADER_SIZE,
    *,
};

// use crate::{basics::*,
//     rs_tlv_serde,
// //     de_rs_tlv, ser_rs_tlv
// };

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

#[derive(Serialize, Deserialize, Debug)]
pub struct RsServiceInfo {
    pub m_service_name: String,
    pub m_service_type: u32,
    pub m_version_major: u16,
    pub m_version_minor: u16,
    pub m_min_version_major: u16,
    pub m_min_version_minor: u16,
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

// pub(crate) type RsTlvServiceInfoMapRef = RsTlvGenericMapRef<u32, RsServiceInfo>;
// #[derive(Serialize, Deserialize, Debug)]
// pub struct RsServiceInfoListItem {
//     // #[serde(serialize_with = "ser_rs_tlv", deserialize_with = "de_rs_tlv")]
//     #[serde(with="rs_tlv_serde")]
//     pub m_service_info: RsTlvServiceInfoMapRef,
// }

pub fn read_rs_service_info(payload: &mut Vec<u8>, services: &mut HashMap<u32, RsServiceInfo>) {
    let mut offset = 0;
    // RsTlvGenericMapRef<uint32_t, RsServiceInfo> FUN!
    let _ = read_u16(payload); // type = 1
    let _ = read_u32(payload); // len

    while offset < payload.len() {
        let old = payload.len();

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
        let info: RsServiceInfo = from_retroshare_wire(&mut val).expect("failed to deserialise");

        services.insert(servcie_num, info);

        offset += old - payload.len();
    }
}

pub fn write_rs_service_info(services: &Vec<RsServiceInfo>) -> Vec<u8> {
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
        let mut val = to_retroshare_wire(service).expect("failed to serialize");
        data.append(&mut val);

        inner_data.push(data);
    }

    inner_data.into_iter().flatten().collect()
}
