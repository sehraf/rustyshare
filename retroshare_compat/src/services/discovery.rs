use ::serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;

use crate::{
    basics::*,
    serde::{
        from_retroshare_wire, from_retroshare_wire_result, to_retroshare_wire,
        to_retroshare_wire_result,
    },
    tlv::{
        tags::*,
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
#[derive(Debug, Default, PartialEq)]
pub struct DiscContactItem {
    pub pgp_id: PgpId,
    pub ssl_id: SslId,

    // COMMON
    pub location: StringTagged<TLV_TYPE_STR_LOCATION>, // TLV String!
    pub version: StringTagged<TLV_TYPE_STR_VERSION>,   // TLV String!

    pub net_mode: u32, /* Mandatory */
    pub vs_disc: u16,  /* Mandatory */
    pub vs_dht: u16,   /* Mandatory */
    pub last_contact: u32,

    // #[serde(skip)]
    pub is_hidden: bool, /* not serialised */

    // hidden.
    pub hidden_addr: StringTagged<TLV_TYPE_STR_DOMADDR>, // TLV String!
    pub hidden_port: u16,

    // non hidden
    pub local_addr_v4: TlvIpAddress,               /* Mandatory */
    pub ext_addr_v4: TlvIpAddress,                 /* Mandatory */
    pub local_addr_v6: TlvIpAddress,               /* Mandatory */
    pub ext_addr_v6: TlvIpAddress,                 /* Mandatory */
    pub current_connect_address: TlvIpAddress,     // used to check!
    pub dyndns: StringTagged<TLV_TYPE_STR_DYNDNS>, // TLV String!

    pub local_addr_list: TlvIpAddrSet,
    pub ext_addr_list: TlvIpAddrSet,
}

impl Serialize for DiscContactItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser = vec![];

        ser.append(&mut to_retroshare_wire(&self.pgp_id));
        ser.append(&mut to_retroshare_wire(&self.ssl_id));
        ser.append(&mut to_retroshare_wire(&self.location));
        ser.append(&mut to_retroshare_wire(&self.version));

        ser.append(&mut to_retroshare_wire(&self.net_mode));
        ser.append(&mut to_retroshare_wire(&self.vs_disc));
        ser.append(&mut to_retroshare_wire(&self.vs_dht));
        ser.append(&mut to_retroshare_wire(&self.last_contact));

        if self.is_hidden {
            ser.append(&mut to_retroshare_wire(&self.hidden_addr));
            ser.append(&mut to_retroshare_wire(&self.hidden_port));
        } else {
            ser.append(&mut to_retroshare_wire(&self.local_addr_v4.0));
            ser.append(&mut to_retroshare_wire(&self.ext_addr_v4.0));
            ser.append(&mut to_retroshare_wire(&self.local_addr_v6.0));
            ser.append(&mut to_retroshare_wire(&self.ext_addr_v6.0));
            ser.append(&mut to_retroshare_wire(&self.current_connect_address.0));

            ser.append(&mut to_retroshare_wire(&self.dyndns));

            ser.append(&mut to_retroshare_wire(&self.local_addr_list));
            ser.append(&mut to_retroshare_wire(&self.ext_addr_list));
        }

        serializer.serialize_bytes(ser.as_slice())
    }
}

impl<'de> Deserialize<'de> for DiscContactItem {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OwnVisitor();

        impl OwnVisitor {
            #[inline(always)]
            fn read_or_default<'de, T>(should_read: bool, mut bytes: &mut Vec<u8>) -> T
            where
                T: DeserializeOwned + Default,
            {
                if should_read {
                    from_retroshare_wire(&mut bytes)
                } else {
                    Default::default()
                }
            }
        }

        impl<'de> Visitor<'de> for OwnVisitor {
            type Value = DiscContactItem;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a DiscContactItem")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                let mut bytes = v.to_vec();

                let pgp_id = from_retroshare_wire(&mut bytes);
                let ssl_id = from_retroshare_wire(&mut bytes);
                let location = from_retroshare_wire(&mut bytes);
                let version = from_retroshare_wire(&mut bytes);
                let net_mode = from_retroshare_wire(&mut bytes);
                let vs_disc = from_retroshare_wire(&mut bytes);
                let vs_dht = from_retroshare_wire(&mut bytes);
                let last_contact = from_retroshare_wire(&mut bytes);

                // check is the entry is for a hidden node or clearnet
                let is_hidden = read_u16(&mut bytes[..2].to_vec()) == TLV_TYPE_STR_DOMADDR;

                // hidden
                let hidden_addr = OwnVisitor::read_or_default(is_hidden, &mut bytes);
                let hidden_port = OwnVisitor::read_or_default(is_hidden, &mut bytes);

                // non hidden
                let local_addr_v4 = OwnVisitor::read_or_default(!is_hidden, &mut bytes);
                let ext_addr_v4 = OwnVisitor::read_or_default(!is_hidden, &mut bytes);
                let local_addr_v6 = OwnVisitor::read_or_default(!is_hidden, &mut bytes);
                let ext_addr_v6 = OwnVisitor::read_or_default(!is_hidden, &mut bytes);
                let current_connect_address = OwnVisitor::read_or_default(!is_hidden, &mut bytes);
                let dyndns = OwnVisitor::read_or_default(!is_hidden, &mut bytes);
                let local_addr_list = OwnVisitor::read_or_default(!is_hidden, &mut bytes);
                let ext_addr_list = OwnVisitor::read_or_default(!is_hidden, &mut bytes);

                Ok(DiscContactItem {
                    pgp_id,
                    ssl_id,
                    location,
                    version,
                    net_mode,
                    vs_disc,
                    vs_dht,
                    last_contact,

                    is_hidden,
                    hidden_addr,
                    hidden_port,

                    local_addr_v4,
                    ext_addr_v4,
                    local_addr_v6,
                    ext_addr_v6,
                    current_connect_address,
                    dyndns,
                    local_addr_list,
                    ext_addr_list,
                })
            }
        }

        unimplemented!("this implementation is broken!");
        #[allow(unreachable_code)]
        _deserializer.deserialize_bytes(OwnVisitor())
    }
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

    item.pgp_id = from_retroshare_wire_result(payload).unwrap();
    item.ssl_id = from_retroshare_wire_result(payload).unwrap();
    item.location = from_retroshare_wire_result(payload).unwrap();
    item.version = from_retroshare_wire_result(payload).unwrap();

    item.net_mode = from_retroshare_wire_result(payload).unwrap();
    item.vs_disc = from_retroshare_wire_result(payload).unwrap();
    item.vs_dht = from_retroshare_wire_result(payload).unwrap();
    item.last_contact = from_retroshare_wire_result(payload).unwrap();

    // check is the entry is for a hidden node or clearnet
    let mut copy = payload[..2].to_vec();
    if read_u16(&mut copy) == TLV_TYPE_STR_DOMADDR {
        item.hidden_addr = from_retroshare_wire_result(payload).unwrap();
        item.hidden_port = from_retroshare_wire_result(payload).unwrap();
    } else {
        item.local_addr_v4 = from_retroshare_wire_result(payload).unwrap();
        item.ext_addr_v4 = from_retroshare_wire_result(payload).unwrap();
        item.local_addr_v6 = from_retroshare_wire_result(payload).unwrap();
        item.ext_addr_v6 = from_retroshare_wire_result(payload).unwrap();
        item.current_connect_address = from_retroshare_wire_result(payload).unwrap();
        item.dyndns = from_retroshare_wire_result(payload).unwrap();

        item.local_addr_list = from_retroshare_wire_result(payload).unwrap();
        item.ext_addr_list = from_retroshare_wire_result(payload).unwrap();
    }

    item
}

pub fn write_rs_disc_contact_item(payload: &mut Vec<u8>, item: &DiscContactItem) {
    payload.append(&mut to_retroshare_wire_result(&item.pgp_id).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire_result(&item.ssl_id).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire_result(&item.location).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire_result(&item.version).expect("failed to serialize"));

    payload.append(&mut to_retroshare_wire_result(&item.net_mode).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire_result(&item.vs_disc).expect("failed to serialize"));
    payload.append(&mut to_retroshare_wire_result(&item.vs_dht).expect("failed to serialize"));
    payload
        .append(&mut to_retroshare_wire_result(&item.last_contact).expect("failed to serialize"));

    // TODO add support for hidden nodes
    if item.is_hidden {
        payload.append(
            &mut to_retroshare_wire_result(&item.hidden_addr).expect("failed to serialize"),
        );
        payload.append(
            &mut to_retroshare_wire_result(&item.hidden_port).expect("failed to serialize"),
        );
    } else {
        payload.append(
            &mut to_retroshare_wire_result(&item.local_addr_v4.0).expect("failed to serialize"),
        );
        payload.append(
            &mut to_retroshare_wire_result(&item.ext_addr_v4.0).expect("failed to serialize"),
        );
        payload.append(
            &mut to_retroshare_wire_result(&item.local_addr_v6.0).expect("failed to serialize"),
        );
        payload.append(
            &mut to_retroshare_wire_result(&item.ext_addr_v6.0).expect("failed to serialize"),
        );
        payload.append(
            &mut to_retroshare_wire_result(&item.current_connect_address.0)
                .expect("failed to serialize"),
        );

        payload.append(&mut to_retroshare_wire_result(&item.dyndns).expect("failed to serialize"));

        payload.append(
            &mut to_retroshare_wire_result(&item.local_addr_list).expect("failed to serialize"),
        );
        payload.append(
            &mut to_retroshare_wire_result(&item.ext_addr_list).expect("failed to serialize"),
        );
    }
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

#[cfg(test)]
mod test_discovery {
    use crate::{
        serde::{from_retroshare_wire, to_retroshare_wire},
        services::discovery::read_rs_disc_contact_item,
    };

    use super::{write_rs_disc_contact_item, DiscContactItem};

    #[test]
    #[should_panic]
    fn test_disc_contact_item() {
        let orig = DiscContactItem::default();

        let mut ser_old = vec![];
        write_rs_disc_contact_item(&mut ser_old, &orig);
        let mut ser = to_retroshare_wire(&orig);

        assert_eq!(ser, ser_old);

        let de_old = read_rs_disc_contact_item(&mut ser);

        let de: DiscContactItem = from_retroshare_wire(&mut ser_old);

        assert_eq!(de, de_old);
        assert_eq!(de, orig)
    }

    #[test]
    #[should_panic]
    fn test_disc_contact_item_hidden() {
        let mut orig = DiscContactItem::default();
        orig.is_hidden = true;

        let mut ser_old = vec![];
        write_rs_disc_contact_item(&mut ser_old, &orig);
        let mut ser = to_retroshare_wire(&orig);

        assert_eq!(ser, ser_old);

        let de_old = read_rs_disc_contact_item(&mut ser);

        let de: DiscContactItem = from_retroshare_wire(&mut ser_old);

        assert_eq!(de, de_old);
        assert_eq!(de, orig)
    }
}
