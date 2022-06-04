use log::warn;

pub mod bwctrl;
pub mod chat;
pub mod discovery;
pub mod rtt;
pub mod service_info;
pub mod status;
pub mod turtle;

// const SERVICE_FILE_INDEX: u16 = 0x0001;
const SERVICE_DISCOVERY: u16 = 0x0011;
const SERVICE_CHAT: u16 = 0x0012;
// const SERVICE_MSG: u16 = 0x0013;
const SERVICE_TURTLE: u16 = 0x0014;
// const SERVICE_TUNNEL: u16 = 0x0015;
const SERVICE_HEARTBEAT: u16 = 0x0016;
// const SERVICE_FILE_TRANSFER: u16 = 0x0017;
// const SERVICE_GROUTER: u16 = 0x0018;
// const SERVICE_FILE_DATABASE: u16 = 0x0019;
const SERVICE_SERVICE_INFO: u16 = 0x0020;
const SERVICE_BWCTRL: u16 = 0x0021;
// const SERVICE_MAIL: u16 = 0x0022;
// const SERVICE_DIRECT_MAIL: u16 = 0x0023;
// const SERVICE_DISTANT_MAIL: u16 = 0x0024;
// const SERVICE_GWEMAIL_MAIL: u16 = 0x0025;
// const SERVICE_SERVICE_CONTROL: u16 = 0x0026;
// const SERVICE_DISTANT_CHAT: u16 = 0x0027;
// const SERVICE_GXS_TUNNEL: u16 = 0x0028;
// const SERVICE_BANLIST: u16 = 0x0101;
const SERVICE_STATUS: u16 = 0x0102;
// const SERVICE_FRIEND_SERVER: u16 = 0x0103;

/// Rs Network Exchange Service
// const SERVICE_TYPE_NXS            = 0x0200;
pub const SERVICE_GXS_GXSID: u16 = 0x0211;
pub const SERVICE_GXS_PHOTO: u16 = 0x0212;
pub const SERVICE_GXS_WIKI: u16 = 0x0213;
pub const SERVICE_GXS_WIRE: u16 = 0x0214;
pub const SERVICE_GXS_FORUMS: u16 = 0x0215;
pub const SERVICE_GXS_POSTED: u16 = 0x0216;
pub const SERVICE_GXS_CHANNELS: u16 = 0x0217;
pub const SERVICE_GXS_GXSCIRCLE: u16 = 0x0218;

const SERVICE_RTT: u16 = 0x1011;

/// Special type only used for signaling
const SLICE_PROBE: u16 = 0xaabb;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceType {
    Unknown = 0xffff,

    BwCtrl = SERVICE_BWCTRL,
    Chat = SERVICE_CHAT,
    Discovery = SERVICE_DISCOVERY,
    Heartbeat = SERVICE_HEARTBEAT,
    Rtt = SERVICE_RTT,
    ServiceInfo = SERVICE_SERVICE_INFO,
    Status = SERVICE_STATUS,
    Turtle = SERVICE_TURTLE,

    GxsId = SERVICE_GXS_GXSID,
    Photo = SERVICE_GXS_PHOTO,
    Wiki = SERVICE_GXS_WIKI,
    Wire = SERVICE_GXS_WIRE,
    Forums = SERVICE_GXS_FORUMS,
    Posted = SERVICE_GXS_POSTED,
    Channels = SERVICE_GXS_CHANNELS,
    GxsCircle = SERVICE_GXS_GXSCIRCLE,

    SliceProbe = SLICE_PROBE,
}

impl From<&u16> for ServiceType {
    fn from(t: &u16) -> Self {
        use ServiceType::*;

        match *t {
            SERVICE_BWCTRL => BwCtrl,
            SERVICE_CHAT => Chat,
            SERVICE_DISCOVERY => Discovery,
            SERVICE_HEARTBEAT => Heartbeat,
            SERVICE_RTT => Rtt,
            SERVICE_SERVICE_INFO => ServiceInfo,
            SERVICE_STATUS => Status,
            SERVICE_TURTLE => Turtle,

            SERVICE_GXS_GXSID => GxsId,
            SERVICE_GXS_PHOTO => Photo,
            SERVICE_GXS_WIKI => Wiki,
            SERVICE_GXS_WIRE => Wire,
            SERVICE_GXS_FORUMS => Forums,
            SERVICE_GXS_POSTED => Posted,
            SERVICE_GXS_CHANNELS => Channels,
            SERVICE_GXS_GXSCIRCLE => GxsCircle,

            SLICE_PROBE => SliceProbe,

            x @ _ => {
                warn!("unknown service {x}");
                Unknown
            }
        }
    }
}

impl From<u16> for ServiceType {
    fn from(t: u16) -> Self {
        (&t).into()
    }
}

impl From<ServiceType> for u16 {
    fn from(s: ServiceType) -> Self {
        use ServiceType::*;

        match s {
            Unknown => panic!("service type 'unknown' cannot be converted"),

            BwCtrl => SERVICE_BWCTRL,
            Chat => SERVICE_CHAT,
            Discovery => SERVICE_DISCOVERY,
            Heartbeat => SERVICE_HEARTBEAT,
            Rtt => SERVICE_RTT,
            ServiceInfo => SERVICE_SERVICE_INFO,
            Status => SERVICE_STATUS,
            Turtle => SERVICE_TURTLE,

            GxsId => SERVICE_GXS_GXSID,
            Photo => SERVICE_GXS_PHOTO,
            Wiki => SERVICE_GXS_WIKI,
            Wire => SERVICE_GXS_WIRE,
            Forums => SERVICE_GXS_FORUMS,
            Posted => SERVICE_GXS_POSTED,
            Channels => SERVICE_GXS_CHANNELS,
            GxsCircle => SERVICE_GXS_GXSCIRCLE,

            SliceProbe => SLICE_PROBE,
        }
    }
}
