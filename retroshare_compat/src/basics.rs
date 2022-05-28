use hex::FromHex;
use rusqlite::types::FromSql;
use serde::{Deserialize, Serialize};
use std::{
    convert::{Infallible, TryInto},
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
};

use crate::tlv::tlv_string::StringTagged;

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

macro_rules! gen_generic_id_type {
    ($name:ident, $width:expr) => {
        #[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
        pub struct $name(pub [u8; $width]);

        impl Default for $name {
            fn default() -> Self {
                Self([0u8; $width])
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }

        // manually implement `Debug` to use hex representation
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.0))
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

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(s: Vec<u8>) -> Self {
                if s.len() != $width {
                    println!("lenght mismatch! {s:?} is expected to be {} wide", $width);
                    panic!();
                }
                Self(s.try_into().unwrap())
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                hex::decode(s).expect("faild to decode").into()
            }
        }

        impl From<&String> for $name {
            fn from(s: &String) -> Self {
                hex::decode(s).expect("faild to decode").into()
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                hex::decode(s).expect("faild to decode").into()
            }
        }

        impl<const TAG: u16> From<StringTagged<TAG>> for $name {
            fn from(s: StringTagged<TAG>) -> Self {
                hex::decode(s).expect("faild to decode").into()
            }
        }

        impl From<[u8; $width]> for $name {
            fn from(a: [u8; $width]) -> Self {
                Self(a)
            }
        }

        // impl From<&[u8; $width]> for $name {
        //     fn from(a: &[u8; $width]) -> Self {
        //         assert_eq!(a.len(), $width);
        //         Self(a.to_owned())
        //     }
        // }

        // used by rusqlite
        impl FromSql for $name {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                Ok(value.as_str()?.into())
            }
        }

        impl FromHex for $name {
            type Error = Infallible;

            fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
                let s = String::from_utf8_lossy(hex.as_ref());
                assert_eq!(s.len(), $width * 2);
                Ok(Self::from(s.as_ref()))
            }
        }
    };
}

gen_generic_id_type!(SslId, SSL_ID);
gen_generic_id_type!(PgpId, PGP_ID);
gen_generic_id_type!(Sha1CheckSum, SHA1);
gen_generic_id_type!(Sha256CheckSum, SHA256);
gen_generic_id_type!(PgpFingerprint, PGP_FINGERPRINT);
gen_generic_id_type!(Bias20Bytes, SHA1);
gen_generic_id_type!(GxsGroupId, CERT_SIGN);
gen_generic_id_type!(GxsMessageId, SHA1);
gen_generic_id_type!(GxsId, CERT_SIGN);
gen_generic_id_type!(GxsCircleId, CERT_SIGN);
gen_generic_id_type!(GxsTunnelId, SSL_ID);
gen_generic_id_type!(DistantChatPeerId, SSL_ID);
gen_generic_id_type!(NodeGroupId, CERT_SIGN);

pub type PeerId = SslId;
pub type FileHash = Sha1CheckSum;

impl From<GxsGroupId> for GxsId {
    fn from(g: GxsGroupId) -> Self {
        g.0.into()
    }
}

/// This macro generates wrapper structs for the WebUI
/// For example, `SslId` is transported as a map `{"sslId: <...>}"}`
#[macro_export]
macro_rules! gen_type_wrapped {
    ($name:ident, $wrapped_name:ident, $wrapped_type:ty) => {
        #[allow(non_snake_case)]
        #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            $wrapped_name: $wrapped_type,
        }

        impl std::ops::Deref for $name {
            type Target = $wrapped_type;

            fn deref(&self) -> &Self::Target {
                &self.$wrapped_name
            }
        }

        impl From<$wrapped_type> for $name {
            fn from(x: $wrapped_type) -> Self {
                Self { $wrapped_name: x }
            }
        }

        impl From<$name> for $wrapped_type {
            fn from(x: $name) -> Self {
                x.$wrapped_name
            }
        }
    };
    ($name:ident, $wrapped_name:ident, $wrapped_type:ty, HEX) => {
        #[allow(non_snake_case)]
        #[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            #[serde(with = "hex")]
            $wrapped_name: $wrapped_type,
        }

        impl std::ops::Deref for $name {
            type Target = $wrapped_type;

            fn deref(&self) -> &Self::Target {
                &self.$wrapped_name
            }
        }

        impl From<$wrapped_type> for $name {
            fn from(x: $wrapped_type) -> Self {
                Self { $wrapped_name: x }
            }
        }

        impl From<$name> for $wrapped_type {
            fn from(x: $name) -> Self {
                x.$wrapped_name
            }
        }
    };
}

/// This macro generates hex'ed structs for the WebUI
#[macro_export]
macro_rules! gen_type_hex {
    ($name:ident, $wrapped:ident) => {
        #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Default)]
        #[serde(rename_all = "camelCase")]
        pub struct $name(#[serde(with = "hex")] $wrapped);

        impl std::ops::Deref for $name {
            type Target = $wrapped;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl From<$wrapped> for $name {
            fn from(x: $wrapped) -> Self {
                Self(x)
            }
        }

        impl From<$name> for $wrapped {
            fn from(x: $name) -> Self {
                x.0
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                let x: $wrapped = hex::decode(s).expect("faild to decode").into();
                Self(x)
            }
        }

        impl From<&String> for $name {
            fn from(s: &String) -> Self {
                let x: $wrapped = hex::decode(s).expect("faild to decode").into();
                Self(x)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                let x: $wrapped = hex::decode(s).expect("faild to decode").into();
                Self(x)
            }
        }
    };
}

macro_rules! gen_webui_types {
    ($name:ident, $hex:ident, $wrapped:ident) => {
        gen_type_hex!($hex, $name);
        gen_type_wrapped!($wrapped, $name, $name, HEX);
    };
}

gen_webui_types!(SslId, SslIdHex, SslIdWrapped);
gen_webui_types!(PeerId, PeerIdHex, PeerIdWrapped);
gen_webui_types!(PgpId, PgpIdHex, PgpIdWrapped);
gen_webui_types!(GxsId, GxsIdHex, GxsIdWrapped);
gen_webui_types!(
    DistantChatPeerId,
    DistantChatPeerIdHex,
    DistantChatPeerIdWrapped
);
gen_webui_types!(GxsGroupId, GxsGroupIdHex, GxsGroupIdWrapped);
gen_webui_types!(GxsCircleId, GxsCircleIdHex, GxsCircleIdWrapped);

// struct PeerBandwidthLimits : RsSerializable
// {
// 	uint32_t max_up_rate_kbs;
// 	uint32_t max_dl_rate_kbs;
// };
