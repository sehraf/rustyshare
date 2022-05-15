use crate::{
    basics::*,
    read_u32,
    serde::from_retroshare_wire,
    tlv::{string::StringTagged, *},
};

// class RsNodeGroupItem: public RsItem
// {
// public:
//     RsNodeGroupItem(): RsItem(RS_PKT_VERSION1, RS_PKT_CLASS_CONFIG, RS_PKT_TYPE_PEER_CONFIG, RS_PKT_SUBTYPE_NODE_GROUP), flag(0) {}
//     virtual ~RsNodeGroupItem() {}

//     virtual void clear() { pgpList.TlvClear();}

//     explicit RsNodeGroupItem(const RsGroupInfo&) ;

// 	virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//    // /* set data from RsGroupInfo to RsPeerGroupItem */
//    // void set(RsGroupInfo &groupInfo);
//    // /* get data from RsGroupInfo to RsPeerGroupItem */
//    // void get(RsGroupInfo &groupInfo);

//     /* Mandatory */
//     RsNodeGroupId id;
//     std::string name;
//     uint32_t    flag;

//     RsTlvPgpIdSet pgpList;
// };

#[derive(Debug, Default)]
pub struct RsNodeGroupItem {
    id: NodeGroupId,
    name: StringTagged<0x0051>,
    flag: u32,

    pgp_list: TlvPgpIdSet,
}

// RsTypeSerializer::serial_process<uint32_t>(j,ctx,v,"dummy field 0") ;
// RsTypeSerializer::serial_process          (j,ctx,id,"id") ;
// RsTypeSerializer::serial_process          (j,ctx,TLV_TYPE_STR_NAME,name,"name") ;
// RsTypeSerializer::serial_process<uint32_t>(j,ctx,flag,"flag") ;
// RsTypeSerializer::serial_process<RsTlvItem>(j,ctx,pgpList,"pgpList") ;
pub fn read_rs_node_group_item(data: &mut Vec<u8>) -> RsNodeGroupItem {
    let mut item = RsNodeGroupItem::default();

    read_u32(data);
    item.id = from_retroshare_wire(data).expect("failed to deserialize");
    item.name = from_retroshare_wire(data).expect("failed to deserialize");
    item.flag = from_retroshare_wire(data).expect("failed to deserialize");
    item.pgp_list = TlvPgpIdSet::read(data);

    item
}
