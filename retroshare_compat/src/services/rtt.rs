use serde::{Deserialize, Serialize};

// class RsRttPingItem: public RsRttItem
// {
// 	public:
// 		RsRttPingItem()
// 		  : RsRttItem(RS_PKT_SUBTYPE_RTT_PING)
// 		  , mSeqNo(0), mPingTS(0)
// 		{}

//         virtual ~RsRttPingItem(){}
//         virtual void clear(){}

// 		virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 		uint32_t mSeqNo;
// 		uint64_t mPingTS;
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct RttPingItem {
    #[serde(rename(serialize = "mSeqNo", deserialize = "mSeqNo"))]
    pub seq_no: u32,
    #[serde(rename(serialize = "mPingTS", deserialize = "mPingTS"))]
    pub ping_ts: u64,
}

// class RsRttPongItem: public RsRttItem
// {
// 	public:
// 		RsRttPongItem()
// 		  : RsRttItem(RS_PKT_SUBTYPE_RTT_PONG)
// 		  , mSeqNo(0), mPingTS(0), mPongTS(0)
// 		{}

//         virtual ~RsRttPongItem(){}
//         virtual void clear(){}

// 		virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 		uint32_t mSeqNo;
// 		uint64_t mPingTS;
// 		uint64_t mPongTS;
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct RttPongItem {
    pub ping: RttPingItem,
    #[serde(rename(serialize = "mPongTS", deserialize = "mPongTS"))]
    pub pong_ts: u64,
}