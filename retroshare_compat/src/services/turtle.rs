use ::serde::{Deserialize, Serialize};
use std::fmt;

use crate::basics::*;

// typedef Sha1CheckSum  RsFileHash ;
// typedef RsFileHash 	TurtleFileHash ;
type TurtleFileHash = Sha1CheckSum;

// class RsTurtleOpenTunnelItem: public RsTurtleItem
// {
// 	public:
//         RsTurtleOpenTunnelItem() : RsTurtleItem(RS_TURTLE_SUBTYPE_OPEN_TUNNEL), request_id(0), partial_tunnel_id(0), depth(0) { setPriorityLevel(QOS_PRIORITY_RS_TURTLE_OPEN_TUNNEL) ;}

// 		TurtleFileHash file_hash ;	 // hash to match
// 		uint32_t request_id ;		 // randomly generated request id.
// 		uint32_t partial_tunnel_id ; // uncomplete tunnel id. Will be completed at destination.
// 		uint16_t depth ;			 // Used for limiting search depth.

//         void clear() { file_hash.clear() ;}
// 	protected:
// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);
// };
#[derive(Serialize, Deserialize, Debug)]
pub struct TurtleOpenTunnelItem {
    pub file_hash: TurtleFileHash,
    pub request_id: u32,
    pub partial_tunnel_id: u32,
    pub depth: u16,
}

impl fmt::Display for TurtleOpenTunnelItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TurtleOpenTunnelItem [req_id: {:08x}, part_id: {:08x}, depth: {}, hash: {}]",
            self.request_id, self.partial_tunnel_id, self.depth, self.file_hash
        )
    }
}

// class RsTurtleTunnelOkItem: public RsTurtleItem
// {
// 	public:
//         RsTurtleTunnelOkItem() : RsTurtleItem(RS_TURTLE_SUBTYPE_TUNNEL_OK), tunnel_id(0), request_id(0) { setPriorityLevel(QOS_PRIORITY_RS_TURTLE_TUNNEL_OK) ;}

// 		uint32_t tunnel_id ;		// id of the tunnel. Should be identical for a tunnel between two same peers for the same hash.
// 		uint32_t request_id ;	// randomly generated request id corresponding to the intial request.

//         void clear() {}
// 	protected:
// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);
// };
#[derive(Serialize, Deserialize, Debug)]
pub struct TurtleTunnelOkItem {
    pub tunnel_id: u32,
    pub request_id: u32,
}

impl fmt::Display for TurtleTunnelOkItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TurtleOpenTunnelItem [id: {:08x}, req_id: {:08x}]",
            self.tunnel_id, self.request_id,
        )
    }
}

// class RsTurtleGenericTunnelItem: public RsTurtleItem
// {
// 	public:
//         RsTurtleGenericTunnelItem(uint8_t sub_packet_id) : RsTurtleItem(sub_packet_id), direction(0), tunnel_id(0) { setPriorityLevel(QOS_PRIORITY_RS_TURTLE_GENERIC_ITEM);}
//         virtual ~RsTurtleGenericTunnelItem() {}

// 		typedef uint32_t Direction ;
// 		static const Direction DIRECTION_CLIENT = 0x001 ;
// 		static const Direction DIRECTION_SERVER = 0x002 ;

// 		/// Does this packet stamps tunnels when it passes through ?
// 		/// This is used for keeping trace weither tunnels are active or not.

// 		virtual bool shouldStampTunnel() const = 0 ;

// 		/// All tunnels derived from RsTurtleGenericTunnelItem should have a tunnel id to
// 		/// indicate which tunnel they are travelling through.

// 		virtual TurtleTunnelId tunnelId() const { return tunnel_id ; }

// 		/// Indicate weither the packet is a client packet (goign back to the
// 		/// client) or a server packet (going to the server. Typically file
// 		/// requests are server packets, whereas file data are client packets.

// 		virtual Direction travelingDirection() const { return direction ; }
// 		virtual void setTravelingDirection(Direction d) { direction = d; }

// 		Direction direction ;	// This does not need to be serialised. It's only used by the client services, optionnally,
// 										// and is set by the turtle router according to which direction the item travels.

// 		uint32_t tunnel_id ;		// Id of the tunnel to travel through
// };

// class RsTurtleGenericDataItem: public RsTurtleGenericTunnelItem
// {
// 	public:
//         RsTurtleGenericDataItem() : RsTurtleGenericTunnelItem(RS_TURTLE_SUBTYPE_GENERIC_DATA), data_size(0), data_bytes(0) { setPriorityLevel(QOS_PRIORITY_RS_TURTLE_GENERIC_DATA);}
// 		virtual ~RsTurtleGenericDataItem() { if(data_bytes != NULL) free(data_bytes) ; }

// 		virtual bool shouldStampTunnel() const { return true ; }

// 		uint32_t data_size ;
// 		void *data_bytes ;

//         void clear()
//         {
//             free(data_bytes) ;
//             data_bytes = NULL ;
//             data_size = 0;
//         }
// 	protected:
// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);
// };

#[derive(Serialize, Deserialize, Debug)]
pub struct TurtleGenericDataItem {
    pub tunnel_id: u32,
    // pub data_size: u32, // part of data
    pub data: Vec<u8>,
}

impl fmt::Display for TurtleGenericDataItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TurtleGenericDataItem [id: {:08x}, size: {}]",
            self.tunnel_id,
            self.data.len(),
        )
    }
}
