use ::serde::{Deserialize, Serialize};
use std::fmt;

use crate::{
    basics::*,
    serde::{from_retroshare_wire, to_retroshare_wire},
    tlv::{
        tlv_ip_addr::{TlvIpAddrSet, TlvIpAddress},
        tlv_set::TlvPgpIdSet,
        tlv_string::StringTagged,
    },
    *,
};

// enum class RsGossipDiscoveryItemType : uint8_t
// {
// 	PGP_LIST           = 0x1,
// 	PGP_CERT           = 0x2,		// deprecated
// 	CONTACT            = 0x5,
// 	IDENTITY_LIST      = 0x6,
// 	PGP_CERT_BINARY    = 0x9,
// };

#[repr(u8)]
pub enum GossipDiscoveryItemType {
    PgpList = 0x1,
    PgpCert = 0x2, // deprecated
    Contact = 0x5,
    IdentityList = 0x6,
    PgpCertBinary = 0x9,
}

// /**
//  * This enum is underlined by uint32_t for historical reasons.
//  * We are conscious that uint32_t is an overkill for so few possible values but,
//  * changing here it at this point would break binary serialized item
//  * retro-compatibility.
//  */
// enum class RsGossipDiscoveryPgpListMode : uint32_t
// {
// 	NONE    = 0x0,
// 	FRIENDS = 0x1,
// 	GETCERT = 0x2
// };

#[repr(u32)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum GossipDiscoveryPgpListMode {
    None = 0x00000000,
    Friends = 0x00000001,
    Getcert = 0x00000002,
}

// const uint32_t RS_VS_DISC_OFF		= 0x0000;
// const uint32_t RS_VS_DISC_MINIMAL	= 0x0001;
// const uint32_t RS_VS_DISC_FULL		= 0x0002;
#[repr(u16)] // this is a RS bug!!
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum VsDisc {
    Off = 0x0000,
    Minimal = 0x0001,
    Full = 0x0002,
}

impl Default for VsDisc {
    fn default() -> Self {
        VsDisc::Off
    }
}

// const uint32_t RS_VS_DHT_OFF		= 0x0000;
// const uint32_t RS_VS_DHT_PASSIVE	= 0x0001;
// const uint32_t RS_VS_DHT_FULL	= 0x0002;
#[repr(u16)] // this is a RS bug!!
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum VsDht {
    Off = 0x0000,
    Passive = 0x0001,
    Full = 0x0002,
}

impl Default for VsDht {
    fn default() -> Self {
        VsDht::Off
    }
}

// class RsDiscPgpListItem: public RsDiscItem
// {
// public:

// 	RsDiscPgpListItem() : RsDiscItem(RsGossipDiscoveryItemType::PGP_LIST)
// 	{ setPriorityLevel(QOS_PRIORITY_RS_DISC_PGP_LIST); }

// 	void clear() override;
// 	void serial_process(
// 	        RsGenericSerializer::SerializeJob j,
// 	        RsGenericSerializer::SerializeContext& ctx ) override;

// 	RsGossipDiscoveryPgpListMode mode;
// 	RsTlvPgpIdSet pgpIdSet;
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscPgpListItem {
    pub mode: GossipDiscoveryPgpListMode,
    pub pgp_id_set: TlvPgpIdSet,
}

// pub fn read_disc_pgp_list_item(data: &mut Vec<u8>) -> DiscPgpListItem {
//     let mode = read_u32(data);
//     // let pgp_id_set = TlvPgpIdSet::read(data);
//     let pgp_id_set = from_retroshare_wire(data).expect("failed to deserialize");

//     let mode = match mode {
//         0 => GossipDiscoveryPgpListMode::None,
//         1 => GossipDiscoveryPgpListMode::Friends,
//         2 => GossipDiscoveryPgpListMode::Getcert,
//         m => {
//             panic!("mode {} does not match GossipDiscoveryPgpListMode", m);
//         }
//     };

//     DiscPgpListItem { mode, pgp_id_set }
// }

// pub fn write_disc_pgp_list_item(item: &DiscPgpListItem) -> Vec<u8> {
//     let mut data = vec![];

//     write_u32(&mut data, item.mode as u32);
//     data.append(&mut to_retroshare_wire(&item.pgp_id_set).expect("failed to serialize"));

//     data
// }

// class RsDiscPgpKeyItem: public RsDiscItem
// {
// public:

// 	RsDiscPgpKeyItem() :
// 	    RsDiscItem(RsGossipDiscoveryItemType::PGP_CERT_BINARY),
// 	    bin_data(nullptr), bin_len(0)
// 	{ setPriorityLevel(QOS_PRIORITY_RS_DISC_PGP_CERT); }

// 	~RsDiscPgpKeyItem() override { free(bin_data); }
// 	void clear() override;

// 	void serial_process(
// 	        RsGenericSerializer::SerializeJob j,
// 	        RsGenericSerializer::SerializeContext& ctx ) override;

// 	/// duplicate information for practical reasons
// 	RsPgpId pgpKeyId;

// 	unsigned char* bin_data;
// 	uint32_t bin_len;
// };

// pub struct RsDiscPgpKeyItem {
//     pgpKeyId: RsPgpId,
//     // bin_len: u32, implicit by vec
//     bin_data: Vec<u8>,
// }

// class RS_DEPRECATED_FOR(RsDiscPgpKeyItem) RsDiscPgpCertItem: public RsDiscItem
// {
// public:
//     RsDiscPgpCertItem() : RsDiscItem(RsGossipDiscoveryItemType::PGP_CERT)
//     { setPriorityLevel(QOS_PRIORITY_RS_DISC_PGP_CERT); }

//     void clear() override
//     {
//         pgpId.clear();
//         pgpCert.clear();
//     }
//     void serial_process(RsGenericSerializer::SerializeJob j, RsGenericSerializer::SerializeContext& ctx) override
//     {
//         RsTypeSerializer::serial_process(j,ctx,pgpId,"pgpId") ;
//         RsTypeSerializer::serial_process(j,ctx,TLV_TYPE_STR_PGPCERT,pgpCert,"pgpCert") ;
//     }

//     RsPgpId pgpId;
//     std::string pgpCert;
// };

// class RsDiscContactItem: public RsDiscItem
// {
// public:

// 	RsDiscContactItem() : RsDiscItem(RsGossipDiscoveryItemType::CONTACT)
// 	{ setPriorityLevel(QOS_PRIORITY_RS_DISC_CONTACT); }

// 	void clear() override;
// 	void serial_process(
// 	        RsGenericSerializer::SerializeJob j,
// 	        RsGenericSerializer::SerializeContext& ctx ) override;

// 	RsPgpId pgpId;
// 	RsPeerId sslId;

// 	// COMMON
// 	std::string location;
// 	std::string version;

// 	uint32_t    netMode;			/* Mandatory */
// 	uint16_t    vs_disc;		    	/* Mandatory */
// 	uint16_t    vs_dht;		    	/* Mandatory */
// 	uint32_t    lastContact;

// 	bool   isHidden;			/* not serialised */
// 	// HIDDEN.
// 	std::string hiddenAddr;
// 	uint16_t    hiddenPort;

// 	// STANDARD.

// 	RsTlvIpAddress currentConnectAddress ;	// used to check!

// 	RsTlvIpAddress localAddrV4;		/* Mandatory */
// 	RsTlvIpAddress extAddrV4;		/* Mandatory */
// 	RsTlvIpAddress localAddrV6;		/* Mandatory */
// 	RsTlvIpAddress extAddrV6;		/* Mandatory */
// 	std::string dyndns;

// 	RsTlvIpAddrSet localAddrList;
// 	RsTlvIpAddrSet extAddrList;
// };

// #[derive(Serialize, Deserialize, Debug)]
#[derive(Debug, Default)]
pub struct DiscContactItem {
    pub pgp_id: PgpId,
    pub ssl_id: SslId,

    // COMMON
    pub location: StringTagged<0x005c>, // TLV String!
    pub version: StringTagged<0x005f>,  // TLV String!

    pub net_mode: u32, /* Mandatory */
    pub vs_disc: u16,  /* Mandatory */
    pub vs_dht: u16,   /* Mandatory */
    pub last_contact: u32,

    // #[serde(skip)]
    pub is_hidden: bool, /* not serialised */
    // HIDDEN.
    pub hidden_addr: StringTagged<0x0084>, // TLV String!
    pub hidden_port: u16,

    // STANDARD.
    // not serialized here!
    pub current_connect_address: TlvIpAddress, // used to check!

    pub local_addr_v4: TlvIpAddress, /* Mandatory */
    pub ext_addr_v4: TlvIpAddress,   /* Mandatory */
    pub local_addr_v6: TlvIpAddress, /* Mandatory */
    pub ext_addr_v6: TlvIpAddress,   /* Mandatory */
    // current_connect_address is serialized here!
    pub dyndns: StringTagged<0x0083>, // TLV String!

    pub local_addr_list: TlvIpAddrSet,
    pub ext_addr_list: TlvIpAddrSet,
}

impl fmt::Display for DiscContactItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RsDiscContactItem: [\n")?;
        write!(f, "\tpgp_id: {}\n", self.pgp_id)?;
        write!(f, "\tssl_id: {}\n", self.ssl_id)?;
        write!(f, "\tlocation: {}\n", self.location)?;
        write!(f, "\tversion: {}\n", self.version)?;

        write!(f, "\tnet_mode: {}\n", self.net_mode)?;
        write!(f, "\tvs_disc: {:?}\n", self.vs_disc)?;
        write!(f, "\tvs_dht: {:?}\n", self.vs_dht)?;
        write!(f, "\tlast_contact: {}\n", self.last_contact)?;

        write!(f, "\tis_hidden: {}\n", self.is_hidden)?;
        write!(f, "\thidden_addr: {}\n", self.hidden_addr)?;
        write!(f, "\thidden_port: {}\n", self.hidden_port)?;

        write!(f, "\tlocal_addr_v4: {}\n", self.local_addr_v4.0)?;
        write!(f, "\text_addr_v4: {}\n", self.ext_addr_v4.0)?;
        write!(f, "\tlocal_addr_v6: {}\n", self.local_addr_v6.0)?;
        write!(f, "\text_addr_v6: {}\n", self.ext_addr_v6.0)?;
        write!(
            f,
            "\tcurrent_connect_address: {}\n",
            self.current_connect_address.0
        )?;
        write!(f, "\tdyndns: {}\n", self.dyndns)?;

        write!(f, "\tlocal_addr_list: {:?}\n", self.local_addr_list)?;
        write!(f, "\text_addr_list: {:?}\n", self.ext_addr_list)?;
        write!(f, "]")
    }
}

pub fn read_rs_disc_contact_item(payload: &mut Vec<u8>) -> DiscContactItem {
    let mut item = DiscContactItem::default();

    item.pgp_id = from_retroshare_wire(payload).unwrap();
    item.ssl_id = from_retroshare_wire(payload).unwrap();
    item.location = from_retroshare_wire(payload).unwrap();
    item.version = from_retroshare_wire(payload).unwrap();

    item.net_mode = from_retroshare_wire(payload).unwrap();
    item.vs_disc = from_retroshare_wire(payload).unwrap();
    item.vs_dht = from_retroshare_wire(payload).unwrap();
    item.last_contact = from_retroshare_wire(payload).unwrap();

    // check is the entry is for a hidden node or clearnet
    let mut copy = payload[..2].to_vec();
    if read_u16(&mut copy) == 0x0084 {
        item.hidden_addr = from_retroshare_wire(payload).unwrap();
        item.hidden_port = from_retroshare_wire(payload).unwrap();
    } else {
        item.local_addr_v4 = from_retroshare_wire(payload).unwrap();
        item.ext_addr_v4 = from_retroshare_wire(payload).unwrap();
        item.local_addr_v6 = from_retroshare_wire(payload).unwrap();
        item.ext_addr_v6 = from_retroshare_wire(payload).unwrap();
        item.current_connect_address = from_retroshare_wire(payload).unwrap();
        item.dyndns = from_retroshare_wire(payload).unwrap();

        item.local_addr_list = from_retroshare_wire(payload).unwrap();
        item.ext_addr_list = from_retroshare_wire(payload).unwrap();
    }

    item
}

pub fn write_rs_disc_contact_item(payload: &mut Vec<u8>, item: &DiscContactItem) {
    payload.append(&mut to_retroshare_wire(&item.pgp_id).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.ssl_id).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.location).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.version).expect("failed to serialize"));

    payload.append(&mut to_retroshare_wire(&item.net_mode).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.vs_disc).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.vs_dht).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.last_contact).expect("failed to serialize"));

    // TODO add support for hidden nodes

    payload.append(&mut to_retroshare_wire(&item.local_addr_v4.0).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.ext_addr_v4.0).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.local_addr_v6.0).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.ext_addr_v6.0).expect("failed to serialize"));
    payload.append(
        &mut to_retroshare_wire(&item.current_connect_address.0).expect("failed to serialize"),
    );

    payload.append(&mut to_retroshare_wire(&item.dyndns).expect("failed to serialize"));

    payload.append(&mut to_retroshare_wire(&item.local_addr_list).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire(&item.ext_addr_list).expect("failed to serialize"));
}

// class RsDiscIdentityListItem: public RsDiscItem
// {
// 	std::list<RsGxsId> ownIdentityList;
// };

#[derive(Serialize, Deserialize, Debug)]
pub struct DiscIdentityListItem {
    pub own_identity_list: Vec<GxsId>,
}

impl fmt::Display for DiscIdentityListItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;

        write!(f, "RsDiscIdentityListItem: [")?;
        for id in &self.own_identity_list {
            if !first {
                write!(f, ", ")?;
            } else {
                first = false;
            }
            write!(f, "{}", hex::encode(id.0))?;
        }
        write!(f, "]")
    }
}
