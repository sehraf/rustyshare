use std::{
    collections::HashSet,
    fmt::{self, Debug, Display},
    ops::{Deref, DerefMut},
};

use bitflags::bitflags;
use bitflags_serde_shim::impl_serde_for_bitflags;
use rusqlite::{types::FromSql, ToSql};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    basics::{GxsGroupId, GxsId},
    read_u16, read_u32,
    serde::{from_retroshare_wire_result, to_retroshare_wire_result},
    tlv::tags::*,
    write_u16, write_u32,
};

use super::{tlv_map::TlvMap, tlv_string::StringTagged, Tlv, Tlv2, TlvBinaryData, TLV_HEADER_SIZE};

// class RsTlvKeySignature: public RsTlvItem
// {
// 		void	ShallowClear(); /* clears signData - but doesn't delete */
// 		RsGxsId keyId;		// Mandatory :
// 		RsTlvBinaryData signData; 	// Mandatory :
// };

// BUG this is a RS bug, the GxsId is serialized as a string
// Use a newtype to handle it easier.
#[derive(Default, PartialEq, Eq, Serialize, Clone, Deserialize, Hash)]
// pub struct KeyId(StringTagged<TLV_TYPE_STR_KEYID>);
pub struct KeyId(Tlv2<TLV_TYPE_STR_KEYID, GxsId>);

impl Deref for KeyId {
    type Target = GxsId;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0 .0))
    }
}

impl From<KeyId> for GxsId {
    fn from(id: KeyId) -> Self {
        *id.0.to_owned()
    }
}

impl From<GxsId> for KeyId {
    fn from(id: GxsId) -> Self {
        Self(id.into())
    }
}

impl From<KeyId> for GxsGroupId {
    fn from(id: KeyId) -> Self {
        (*id.0.to_owned()).into()
    }
}

impl From<GxsGroupId> for KeyId {
    fn from(id: GxsGroupId) -> Self {
        Self(GxsId::from(id.0).into())
    }
}

impl From<[u8; 16]> for KeyId {
    fn from(x: [u8; 16]) -> Self {
        Self(GxsId::from(x).into())
    }
}

impl PartialEq<GxsId> for KeyId {
    fn eq(&self, other: &GxsId) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.deref())
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TlvKeySignatureInner {
    #[serde(rename(serialize = "keyId", deserialize = "keyId"))]
    pub key_id: KeyId,
    #[serde(rename(serialize = "signData", deserialize = "signData"))]
    pub sign_data: TlvBinaryData<TLV_TYPE_SIGN_RSA_SHA1>,
}

impl TlvKeySignatureInner {
    pub fn new(key_id: KeyId) -> Self {
        Self {
            key_id,
            sign_data: vec![].into(),
        }
    }
}

pub type TlvKeySignature = Tlv<TLV_TYPE_KEYSIGNATURE, TlvKeySignatureInner>;

// static const uint32_t INDEX_AUTHEN_IDENTITY     = 0x00000010; // identity
// static const uint32_t INDEX_AUTHEN_PUBLISH      = 0x00000020; // publish key
// static const uint32_t INDEX_AUTHEN_ADMIN        = 0x00000040; // admin key
#[repr(u32)]
#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq, Eq, Hash, Clone)]
pub enum KeySignType {
    IndexAuthenIdentity = 0x00000010,
    IndexAuthenPublish = 0x00000020,
    IndexAuthenAdmin = 0x00000040,
}

impl Default for KeySignType {
    fn default() -> Self {
        KeySignType::IndexAuthenIdentity // ?!
    }
}

// class RsTlvKeySignatureSet : public RsTlvItem
// {
//     std::map<SignType, RsTlvKeySignature> keySignSet; // mandatory
// };
pub type TlvKeySignatureSet =
    TlvMap<TLV_TYPE_KEYSIGNATURESET, Tlv<TLV_TYPE_KEYSIGNATURETYPE, KeySignType>, TlvKeySignature>;

impl FromSql for TlvKeySignatureSet {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match value.as_bytes_or_null()? {
            Some(bytes) => Ok(from_retroshare_wire_result(&mut bytes.into())
                .map_err(|err| rusqlite::types::FromSqlError::Other(Box::new(err)))?),
            None => Ok(Self::default()),
        }
    }
}

impl ToSql for TlvKeySignatureSet {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        if self.0.is_empty() {
            Ok(rusqlite::types::Null.into())
        } else {
            Ok(to_retroshare_wire_result(self)
                .map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into()))?
                .into())
        }
    }
}

bitflags! {
    // #[derive(Default)]
    pub struct TlvKeyFlags: u32 {
        const TYPE_PUBLIC_ONLY    = 0x0001;
        const TYPE_FULL           = 0x0002;
        #[deprecated]
        const DISTRIBUTE_PUBLIC   = 0x0010; // was used as PUBLISH flag. Probably a typo.
        const DISTRIBUTE_PUBLISH  = 0x0020;
        const DISTRIBUTE_ADMIN    = 0x0040;
        const DISTRIBUTE_IDENTITY = 0x0080;
    }
}

impl_serde_for_bitflags!(TlvKeyFlags);

// class RsTlvRSAKey: public RsTlvItem
// {
//     uint32_t getKeyTypeTlv(void *data, uint32_t size, uint32_t *offset) const;

//     RsGxsId keyId;		// Mandatory :
//     uint32_t keyFlags;		// Mandatory ;
//     uint32_t startTS;		// Mandatory :
//     uint32_t endTS;		// Mandatory :
//     RsTlvBinaryData keyData; 	// Mandatory :
// };

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Clone)]
pub struct TlvRSAKeyInner {
    pub key_id: KeyId,                                  // Mandatory :
    pub key_flags: TlvKeyFlags,                         // Mandatory ;
    pub start_ts: u32,                                  // Mandatory :
    pub end_ts: u32,                                    // Mandatory :
    pub key_data: TlvBinaryData<TLV_TYPE_KEY_EVP_PKEY>, // Mandatory :
}
type TlvRSAKey = Tlv<TLV_TYPE_SECURITY_KEY, TlvRSAKeyInner>;

// The two classes below are by design incompatible, making it impossible to pass a private key as a public key

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TlvPublicRSAKey(TlvRSAKey);

impl Deref for TlvPublicRSAKey {
    type Target = TlvRSAKeyInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TlvPublicRSAKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

impl From<TlvRSAKey> for TlvPublicRSAKey {
    fn from(key: TlvRSAKey) -> Self {
        // this must be checked before (TODO? use try_into?)
        assert!(key.key_flags.contains(TlvKeyFlags::TYPE_PUBLIC_ONLY));
        Self(key.into())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TlvPrivateRSAKey(TlvRSAKey);

impl Deref for TlvPrivateRSAKey {
    type Target = TlvRSAKeyInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<TlvRSAKey> for TlvPrivateRSAKey {
    fn from(key: TlvRSAKey) -> Self {
        // this must be checked before (TODO? use try_into?)
        assert!(key.key_flags.contains(TlvKeyFlags::TYPE_FULL));
        Self(key.into())
    }
}

impl DerefMut for TlvPrivateRSAKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

// class RsTlvSecurityKeySet: public RsTlvItem
// {
// 	std::string groupId;					// Mandatory :
// 	std::map<RsGxsId, RsTlvPublicRSAKey> public_keys;	// Mandatory :
// 	std::map<RsGxsId, RsTlvPrivateRSAKey> private_keys;	// Mandatory :
// };

#[derive(Debug, Default, Clone)]
pub struct TlvSecurityKeySet {
    pub group_id: StringTagged<TLV_TYPE_STR_GROUPID>,
    pub public_keys: HashSet<TlvPublicRSAKey>,
    pub private_keys: HashSet<TlvPrivateRSAKey>,
}

// need do manually implement TlvSecurityKeySet since both member `public_keys` and `private_keys` cannot be distinguished once serialized

impl Serialize for TlvSecurityKeySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];

        bytes.extend(to_retroshare_wire_result(&self.group_id).expect("failed to serialize"));

        for pub_key in &self.public_keys {
            bytes.extend(to_retroshare_wire_result(pub_key).expect("failed to serialize"));
        }
        for priv_key in &self.private_keys {
            bytes.extend(to_retroshare_wire_result(priv_key).expect("failed to serialize"));
        }

        let mut ser = vec![];
        write_u16(&mut ser, TLV_TYPE_SECURITYKEYSET);
        write_u32(&mut ser, (bytes.len() + TLV_HEADER_SIZE) as u32);
        ser.extend_from_slice(&bytes);

        serializer.serialize_bytes(ser.as_slice())
    }
}

impl<'de> Deserialize<'de> for TlvSecurityKeySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TlvVisitor();

        impl<'de> Visitor<'de> for TlvVisitor {
            type Value = TlvSecurityKeySet;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "TLV")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                // let mut item = $name(HashMap::new());
                let tag = read_u16(&mut v[0..2].to_owned());
                if tag != TLV_TYPE_SECURITYKEYSET {
                    return Err(::serde::de::Error::custom(crate::serde::Error::WrongTag));
                }
                let len = read_u32(&mut v[2..6].to_owned()) as usize;
                assert!(len >= TLV_HEADER_SIZE);
                assert!(len == v.len());

                let mut bytes: Vec<_> = v[6..len].into();

                let group_id =
                    from_retroshare_wire_result(&mut bytes).expect("failed to deserialize");
                let mut private_keys = HashSet::new();
                let mut public_keys = HashSet::new();

                while !bytes.is_empty() {
                    let key: TlvRSAKey =
                        from_retroshare_wire_result(&mut bytes).expect("failed to deserialize");
                    match key.key_flags {
                        flags if flags.contains(TlvKeyFlags::TYPE_PUBLIC_ONLY) => {
                            public_keys.insert(key.into());
                        }
                        flags if flags.contains(TlvKeyFlags::TYPE_FULL) => {
                            private_keys.insert(key.into());
                        }
                        flags @ _ => {
                            log::error!("unknown flags {flags:?} for TlvRSAKey");
                            return Err(::serde::de::Error::custom(crate::serde::Error::WrongTag));
                        }
                    }
                }

                Ok(TlvSecurityKeySet {
                    group_id,
                    private_keys,
                    public_keys,
                })
            }
        }

        deserializer.deserialize_byte_buf(TlvVisitor())
    }
}

impl FromSql for TlvSecurityKeySet {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let mut bytes = value.as_bytes()?.into();
        let obj = from_retroshare_wire_result(&mut bytes)
            .map_err(|err| rusqlite::types::FromSqlError::Other(Box::new(err)))?;
        Ok(obj)
    }
}

impl ToSql for TlvSecurityKeySet {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(to_retroshare_wire_result(self)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into()))?
            .into())
    }
}
