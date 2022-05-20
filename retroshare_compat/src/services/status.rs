use std::fmt::Display;

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

// const uint32_t RS_STATUS_OFFLINE  = 0x0000;
// const uint32_t RS_STATUS_AWAY     = 0x0001;
// const uint32_t RS_STATUS_BUSY     = 0x0002;
// const uint32_t RS_STATUS_ONLINE   = 0x0003;
// const uint32_t RS_STATUS_INACTIVE = 0x0004;
#[repr(u32)]
#[derive(Debug, Serialize_repr, Deserialize_repr)]
pub enum StatusValue {
    Offline = 0x0000,
    Away = 0x0001,
    Busy = 0x0002,
    Online = 0x0003,
    Inactive = 0x0004,
}

// impl From<u32> for StatusValue {
//     fn from(val: u32) -> Self {
//         match val {
//             0x0000 => StatusValue::Offline,
//             0x0001 => StatusValue::Away,
//             0x0002 => StatusValue::Busy,
//             0x0003 => StatusValue::Online,
//             0x0004 => StatusValue::Inactive,
//             value => panic!("unknown status value {value}"),
//         }
//     }
// }

// impl From<StatusValue> for u32 {
//     fn from(status: StatusValue) -> Self {
//         match status {
//             StatusValue::Offline => 0x0000,
//             StatusValue::Away => 0x0001,
//             StatusValue::Busy => 0x0002,
//             StatusValue::Online => 0x0003,
//             StatusValue::Inactive => 0x0004,
//         }
//     }
// }

impl Display for StatusValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use StatusValue::*;

        match self {
            Offline => write!(f, "offline"),
            Away => write!(f, "away"),
            Busy => write!(f, "busy"),
            Online => write!(f, "online"),
            Inactive => write!(f, "inactive"),
        }
    }
}

// class RsStatusItem: public RsItem
// {
// public:
// 	RsStatusItem()  :RsItem(RS_PKT_VERSION_SERVICE, RS_SERVICE_TYPE_STATUS,  RS_PKT_SUBTYPE_DEFAULT)
// 	{
// 		setPriorityLevel(QOS_PRIORITY_RS_STATUS_ITEM);
// 	}
//     virtual ~RsStatusItem() {}
//     virtual void clear() {}

// 	virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx)
//     {
//         RsTypeSerializer::serial_process<uint32_t>(j,ctx,sendTime,"sendTime") ;
//         RsTypeSerializer::serial_process<uint32_t>(j,ctx,status  ,"status") ;
//     }

// 	uint32_t sendTime;
// 	uint32_t status;

// 	/* not serialised */
// 	uint32_t recvTime;
// };
#[derive(Serialize, Deserialize, Debug)]
pub struct StatusItem {
    #[serde(rename(serialize = "sendTime", deserialize = "sendTime"))]
    pub send_time: u32,
    pub status: StatusValue,
}
