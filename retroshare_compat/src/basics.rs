use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
};

// namespace _RsIdSize
// {
// constexpr uint32_t SSL_ID          = 16;   // = CERT_SIGN
// constexpr uint32_t CERT_SIGN       = 16;   // = SSL_ID
// constexpr uint32_t PGP_ID          =  8;
// constexpr uint32_t PGP_FINGERPRINT = 20;
// constexpr uint32_t SHA1            = 20;
// constexpr uint32_t SHA256          = 32;
// }

const SSL_ID: usize = 16; // = CERT_SIGN
const CERT_SIGN: usize = 16; // = SSL_ID
const PGP_ID: usize = 8;
const PGP_FINGERPRINT: usize = 20;
const SHA1: usize = 20;
const SHA256: usize = 32;

// using RsPeerId          = t_RsGenericIdType<_RsIdSize::SSL_ID         , false, RsGenericIdType::SSL            >;
// using RsPgpId           = t_RsGenericIdType<_RsIdSize::PGP_ID         , true,  RsGenericIdType::PGP_ID         >;
// using Sha1CheckSum      = t_RsGenericIdType<_RsIdSize::SHA1           , false, RsGenericIdType::SHA1           >;
// using Sha256CheckSum    = t_RsGenericIdType<_RsIdSize::SHA256         , false, RsGenericIdType::SHA256         >;
// using RsPgpFingerprint  = t_RsGenericIdType<_RsIdSize::PGP_FINGERPRINT, true,  RsGenericIdType::PGP_FINGERPRINT>;
// using Bias20Bytes       = t_RsGenericIdType<_RsIdSize::SHA1           , true,  RsGenericIdType::BIAS_20_BYTES  >;
// using RsGxsGroupId      = t_RsGenericIdType<_RsIdSize::CERT_SIGN      , false, RsGenericIdType::GXS_GROUP      >;
// using RsGxsMessageId    = t_RsGenericIdType<_RsIdSize::SHA1           , false, RsGenericIdType::GXS_MSG        >;
// using RsGxsId           = t_RsGenericIdType<_RsIdSize::CERT_SIGN      , false, RsGenericIdType::GXS_ID         >;
// using RsGxsCircleId     = t_RsGenericIdType<_RsIdSize::CERT_SIGN      , false, RsGenericIdType::GXS_CIRCLE     >;
// using RsGxsTunnelId     = t_RsGenericIdType<_RsIdSize::SSL_ID         , false, RsGenericIdType::GXS_TUNNEL     >;
// using DistantChatPeerId = t_RsGenericIdType<_RsIdSize::SSL_ID         , false, RsGenericIdType::DISTANT_CHAT   >;
// using RsNodeGroupId     = t_RsGenericIdType<_RsIdSize::CERT_SIGN      , false, RsGenericIdType::NODE_GROUP     >;

macro_rules! make_generic_id_type {
    ($name:ident, $width:expr) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub struct $name(pub [u8; $width]);

        impl Default for $name {
            fn default() -> Self {
                Self([0u8; $width])
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}: {}", stringify!($name), hex::encode(self.0))
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }

        impl Deref for $name {
            type Target = [u8; $width];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

make_generic_id_type!(PeerId, SSL_ID);
make_generic_id_type!(PgpId, PGP_ID);
make_generic_id_type!(Sha1CheckSum, SHA1);
make_generic_id_type!(Sha256CheckSum, SHA256);
make_generic_id_type!(PgpFingerprint, PGP_FINGERPRINT);
make_generic_id_type!(Bias20Bytes, SHA1);
make_generic_id_type!(GxsGroupId, CERT_SIGN);
make_generic_id_type!(GxsMessageId, SHA1);
make_generic_id_type!(GxsId, CERT_SIGN);
make_generic_id_type!(GxsCircleId, CERT_SIGN);
make_generic_id_type!(GxsTunnelId, SSL_ID);
make_generic_id_type!(DistantChatPeerId, SSL_ID);
make_generic_id_type!(NodeGroupId, CERT_SIGN);

// struct PeerBandwidthLimits : RsSerializable
// {
// 	uint32_t max_up_rate_kbs;
// 	uint32_t max_dl_rate_kbs;
// };

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerBandwidthLimits {
    max_up_rate_kbs: u32,
    max_dl_rate_kbs: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RsPeerBandwidthLimitsItem(HashMap<PgpId, PeerBandwidthLimits>);
