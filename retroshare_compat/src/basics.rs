use hex::FromHex;
use rusqlite::types::FromSql;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::{Infallible, TryInto},
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
                Ok(Self::from(s.as_ref()))
            }
        }
    };
}

make_generic_id_type!(SslId, SSL_ID);
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

pub type PeerId = SslId;
pub type FileHash = Sha1CheckSum;

/// This macro generates wrapper structs for the WebUI
/// For example, `SslId` is transported as a map `{"sslId: <...>}"}`
macro_rules! make_type_wrapped {
    ($name:ident, $wrapped:ident) => {
        #[allow(non_snake_case)]
        #[derive(Debug, Deserialize, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            #[serde(with = "hex")]
            $wrapped: $wrapped,
        }

        impl Deref for $name {
            type Target = $wrapped;

            fn deref(&self) -> &Self::Target {
                &self.$wrapped
            }
        }

        impl From<$wrapped> for $name {
            fn from(x: $wrapped) -> Self {
                Self { $wrapped: x }
            }
        }
    };
}

/// This macro generates hex'ed structs for the WebUI
macro_rules! make_type_hex {
    ($name:ident, $wrapped:ident) => {
        #[derive(Debug, Deserialize, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name(#[serde(with = "hex")] $wrapped);

        impl Deref for $name {
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
    };
}

macro_rules! make_webui_types {
    ($name:ident, $hex:ident, $wrapped:ident) => {
        make_type_hex!($hex, $name);
        make_type_wrapped!($wrapped, $name);
    };
}

make_webui_types!(SslId, SslIdHex, SslIdWrapped);
make_webui_types!(PgpId, PgpIdHex, PgpIdWrapped);

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
