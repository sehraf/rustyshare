use std::collections::HashMap;

use bitflags::bitflags;
use bitflags_serde_shim::impl_serde_for_bitflags;
use serde::{Deserialize, Serialize};

use crate::{
    basics::{NodeGroupId, PeerId, PgpId},
    tlv::{
        tags::*,
        tlv_ip_addr::{TlvIpAddrSet, TlvIpAddress},
        tlv_map::TlvMapWithPair,
        tlv_set::TlvPgpIdSet,
        tlv_string::StringTagged,
    },
};

pub const RS_PKT_TYPE_GENERAL_CONFIG: u8 = 0x01;
pub const RS_PKT_TYPE_PEER_CONFIG: u8 = 0x02;
pub const RS_PKT_TYPE_CACHE_CONFIG: u8 = 0x03;
pub const RS_PKT_TYPE_FILE_CONFIG: u8 = 0x04;
pub const RS_PKT_TYPE_PLUGIN_CONFIG: u8 = 0x05;
pub const RS_PKT_TYPE_HISTORY_CONFIG: u8 = 0x06;

//      /* GENERAL CONFIG SUBTYPES */
pub const RS_PKT_SUBTYPE_KEY_VALUE: u8 = 0x01;

//      /* PEER CONFIG SUBTYPES */
pub const RS_PKT_SUBTYPE_PEER_STUN: u8 = 0x02;
pub const RS_PKT_SUBTYPE_PEER_NET: u8 = 0x03;
#[allow(non_upper_case_globals)]
pub const RS_PKT_SUBTYPE_PEER_GROUP_deprecated: u8 = 0x04;
pub const RS_PKT_SUBTYPE_PEER_PERMISSIONS: u8 = 0x05;
pub const RS_PKT_SUBTYPE_PEER_BANDLIMITS: u8 = 0x06;
pub const RS_PKT_SUBTYPE_NODE_GROUP: u8 = 0x07;

//      /* FILE CONFIG SUBTYPES */
pub const RS_PKT_SUBTYPE_FILE_TRANSFER: u8 = 0x01;
#[allow(non_upper_case_globals)]
pub const RS_PKT_SUBTYPE_FILE_ITEM_deprecated: u8 = 0x02;
pub const RS_PKT_SUBTYPE_FILE_ITEM: u8 = 0x03;

//  /**************************************************************************/
//  class RsPeerNetItem: public RsItem
//  {
//  public:
//      RsPeerNetItem()
//        :RsItem(RS_PKT_VERSION1, RS_PKT_CLASS_CONFIG,
//                RS_PKT_TYPE_PEER_CONFIG,
//                RS_PKT_SUBTYPE_PEER_NET)
//        , netMode(0), vs_disc(0), vs_dht(0), lastContact(0), domain_port(0)
//      {}

//      virtual ~RsPeerNetItem(){}
//      virtual void clear();

//      virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//      /* networking information */
//      RsPeerId    nodePeerId;                   /* Mandatory */
//      RsPgpId     pgpId;                        /* Mandatory */
//      std::string location;                     /* Mandatory */
//      uint32_t    netMode;                      /* Mandatory */
//      uint16_t    vs_disc;                      /* Mandatory */
//      uint16_t    vs_dht;                       /* Mandatory */
//      uint32_t    lastContact;                  /* Mandatory */
//      RsTlvIpAddress localAddrV4;            	/* Mandatory */
//      RsTlvIpAddress extAddrV4;           	/* Mandatory */
//      RsTlvIpAddress localAddrV6;            	/* Mandatory */
//      RsTlvIpAddress extAddrV6;            	/* Mandatory */
//      std::string dyndns;

//      RsTlvIpAddrSet localAddrList;
//      RsTlvIpAddrSet extAddrList;

//      // for proxy connection.
//      std::string domain_addr;
//      uint16_t    domain_port;
//  };
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNetItem {
    pub node_peer_id: PeerId,                          /* Mandatory */
    pub pgp_id: PgpId,                                 /* Mandatory */
    pub location: StringTagged<TLV_TYPE_STR_LOCATION>, /* Mandatory */

    pub net_mode: u32,     /* Mandatory */
    pub vs_disc: u16,      /* Mandatory */
    pub vs_dht: u16,       /* Mandatory */
    pub last_contact: u32, /* Mandatory */

    pub local_addr_v4: TlvIpAddress, /* Mandatory */
    pub ext_addr_v4: TlvIpAddress,   /* Mandatory */
    pub local_addr_v6: TlvIpAddress, /* Mandatory */
    pub ext_addr_v6: TlvIpAddress,   /* Mandatory */

    pub dyndns: StringTagged<TLV_TYPE_STR_DYNDNS>,

    pub local_addr_list: TlvIpAddrSet,
    pub ext_addr_list: TlvIpAddrSet,

    pub domain_addr: StringTagged<TLV_TYPE_STR_DOMADDR>,
    pub domain_port: u16,
}

bitflags! {
    pub struct ServicePermissionFlags: u32 {
        const DIRECT_DL  = 0x00000008;  // Accept to directly DL from this peer (breaks anonymity)
        const ALLOW_PUSH = 0x00000010;  // Auto-DL files recommended by this peer
        const REQUIRE_WL = 0x00000020;  // Require white list clearance for connection
        const DEFAULT    = Self::DIRECT_DL.bits ;
        const ALL        = Self::DIRECT_DL.bits | Self::ALLOW_PUSH.bits | Self::REQUIRE_WL.bits;
    }
}

impl_serde_for_bitflags!(ServicePermissionFlags);

//  // This item should be merged with the next item, but that is not backward compatible.
//  class RsPeerServicePermissionItem : public RsItem
//  {
//      public:
//          RsPeerServicePermissionItem() : RsItem(RS_PKT_VERSION1, RS_PKT_CLASS_CONFIG, RS_PKT_TYPE_PEER_CONFIG, RS_PKT_SUBTYPE_PEER_PERMISSIONS) {}
//          virtual ~RsPeerServicePermissionItem() {}

//          virtual void clear()
//          {
//              pgp_ids.clear() ;
//              service_flags.clear() ;
//          }
//          virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//          /* Mandatory */
//          std::vector<RsPgpId> pgp_ids ;
//          std::vector<ServicePermissionFlags> service_flags ;
//  };
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerServicePermissionItem {
    pub entries: Vec<(PgpId, ServicePermissionFlags)>,
}

//  class RsPeerBandwidthLimitsItem : public RsItem
//  {
//      public:
//          RsPeerBandwidthLimitsItem() : RsItem(RS_PKT_VERSION1, RS_PKT_CLASS_CONFIG, RS_PKT_TYPE_PEER_CONFIG, RS_PKT_SUBTYPE_PEER_BANDLIMITS) {}
//          virtual ~RsPeerBandwidthLimitsItem() {}

//          virtual void clear()
//          {
//              peers.clear() ;
//          }
//          virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//          /* Mandatory */
//          std::map<RsPgpId,PeerBandwidthLimits> peers ;
//  };

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerBandwidthLimits {
    max_up_rate_kbs: u32,
    max_dl_rate_kbs: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerBandwidthLimitsItem(HashMap<PgpId, PeerBandwidthLimits>);

bitflags! {
    #[derive(Default)]
    pub struct NodeGroupFlags: u32 {
        const NONE     = 0x0000;
        const STANDARD = 0x0001;
    }
}

impl_serde_for_bitflags!(NodeGroupFlags);

//  class RsNodeGroupItem: public RsItem
//  {
//      /* Mandatory */
//      RsNodeGroupId id;
//      std::string name;
//      uint32_t    flag;

//      RsTlvPgpIdSet pgpList;
//  };

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NodeGroupItem {
    _dummy: u32,
    id: NodeGroupId,
    name: StringTagged<TLV_TYPE_STR_NAME>,
    flag: NodeGroupFlags,

    pgp_list: TlvPgpIdSet,
}

//  class RsPeerStunItem: public RsItem
//  {
//  public:
//      RsPeerStunItem()
//          :RsItem(RS_PKT_VERSION1, RS_PKT_CLASS_CONFIG,
//                  RS_PKT_TYPE_PEER_CONFIG,
//                  RS_PKT_SUBTYPE_PEER_STUN) {}
//      virtual ~RsPeerStunItem(){}
//      virtual void clear() { stunList.TlvClear() ;}

//      virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//      RsTlvPeerIdSet stunList;		  /* Mandatory */
//  };

//  class RsPeerConfigSerialiser: public RsConfigSerializer
//  {
//      public:
//      RsPeerConfigSerialiser() :RsConfigSerializer(RS_PKT_CLASS_CONFIG,RS_PKT_TYPE_PEER_CONFIG) {}

//      virtual     ~RsPeerConfigSerialiser(){}

//      virtual RsItem *create_item(uint8_t item_type, uint8_t item_subtype) const ;
//  };

//  /**************************************************************************/
//  class RsFileTransfer: public RsItem
//  {
//      public:
//          RsFileTransfer() :RsItem(RS_PKT_VERSION1, RS_PKT_CLASS_CONFIG, RS_PKT_TYPE_FILE_CONFIG, RS_PKT_SUBTYPE_FILE_TRANSFER)
//          {
//              state = 0;
//              in = 0;
//              transferred = 0;
//              crate = 0;
//              trate = 0;
//              lrate = 0;
//              ltransfer = 0;
//              flags = 0;
//              chunk_strategy = 0;
//          }
//          virtual ~RsFileTransfer(){}
//          virtual void clear();

//          virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//          RsTlvFileItem file;
//          RsTlvPeerIdSet allPeerIds;

//          RsPeerId cPeerId;

//          uint16_t state;
//          uint16_t in;

//          uint64_t transferred;
//          uint32_t crate;
//          uint32_t trate;

//          uint32_t lrate;
//          uint32_t ltransfer;

//          // chunk information
//          uint32_t flags ;
//          uint32_t chunk_strategy ;				// strategy flags for chunks
//          CompressedChunkMap compressed_chunk_map ;	// chunk availability (bitwise)
//  };

//  /**************************************************************************/
//  const uint32_t RS_FILE_CONFIG_CLEANUP_DELETE = 0x0001;

//  class RsFileConfigItem: public RsItem
//  {
//  public:
//      RsFileConfigItem() :RsItem(RS_PKT_VERSION1, RS_PKT_CLASS_CONFIG, RS_PKT_TYPE_FILE_CONFIG, RS_PKT_SUBTYPE_FILE_ITEM), flags(0) {}
//      virtual ~RsFileConfigItem() {}
//      virtual void clear() { parent_groups.TlvClear(); }

//      virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//      RsTlvFileItem file;
//      uint32_t flags;
//      RsTlvNodeGroupIdSet parent_groups ;
//  };
//  /**************************************************************************/
//  class RsFileConfigSerialiser: public RsConfigSerializer
//  {
//      public:
//      RsFileConfigSerialiser() :RsConfigSerializer(RS_PKT_CLASS_CONFIG, RS_PKT_TYPE_FILE_CONFIG) { }
//      virtual     ~RsFileConfigSerialiser() {}

//      virtual RsItem *create_item(uint8_t item_type, uint8_t item_subtype) const ;
//  };

//  /**************************************************************************/
//  /* Config items that are used generally */
//  class RsConfigKeyValueSet: public RsItem
//  {
//  public:
//      RsConfigKeyValueSet()  :RsItem(RS_PKT_VERSION1, RS_PKT_CLASS_CONFIG, RS_PKT_TYPE_GENERAL_CONFIG, RS_PKT_SUBTYPE_KEY_VALUE) {}
//      virtual ~RsConfigKeyValueSet(){}
//      virtual void clear() { tlvkvs.TlvClear();}

//      virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//      RsTlvKeyValueSet tlvkvs;
//  };

// #[derive(Debug, Default, Serialize, Deserialize)]
// pub struct ConfigKeyValueSet {
//     pub tlvkvs: Tlv<
//         TLV_TYPE_KEYVALUESET,
//         Tlv<
//             TLV_TYPE_KEYVALUE,
//             (
//                 StringTagged<TLV_TYPE_STR_KEY>,
//                 StringTagged<TLV_TYPE_STR_VALUE>,
//             ),
//         >,
//     >,
// }
// make_tlv_id_map_type!(
//     ConfigKeyValueSet[TLV_TYPE_KEYVALUESET], Pair[TLV_TYPE_KEYVALUE]<StringTagged<TLV_TYPE_STR_KEY>, StringTagged<TLV_TYPE_STR_VALUE>>
// );
pub type ConfigKeyValueSet = TlvMapWithPair<
    TLV_TYPE_KEYVALUESET,
    TLV_TYPE_KEYVALUE,
    StringTagged<TLV_TYPE_STR_KEY>,
    StringTagged<TLV_TYPE_STR_VALUE>,
>;

//  class RsGeneralConfigSerialiser: public RsConfigSerializer
//  {
//      public:
//      RsGeneralConfigSerialiser() :RsConfigSerializer(RS_PKT_CLASS_CONFIG, RS_PKT_TYPE_GENERAL_CONFIG) {}

//      virtual RsItem *create_item(uint8_t item_type, uint8_t item_subtype) const ;
//  };

//  #endif /* RS_CONFIG_ITEMS_SERIALISER_H */
