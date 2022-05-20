use std::{collections::HashSet, fmt};

use rusqlite::types::FromSql;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    basics::GxsId,
    read_u16, read_u32,
    serde::{from_retroshare_wire, to_retroshare_wire},
    tlv::tags::*,
    write_u16, write_u32,
};

use super::{tlv_map::TlvMap, tlv_string::StringTagged, Tlv, Tlv2, TLV_HEADER_SIZE};

pub type TlvBinaryData<const TAG: u16> = Tlv2<TAG, Vec<u8>>;

// class RsTlvKeySignature: public RsTlvItem
// {
// 		void	ShallowClear(); /* clears signData - but doesn't delete */
// 		RsGxsId keyId;		// Mandatory :
// 		RsTlvBinaryData signData; 	// Mandatory :
// };

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TlvKeySignatureInner {
    #[serde(rename(serialize = "keyId", deserialize = "keyId"))]
    key_id: Tlv<TLV_TYPE_STR_KEYID, GxsId>,
    #[serde(rename(serialize = "signData", deserialize = "signData"))]
    sign_data: TlvBinaryData<TLV_TYPE_SIGN_RSA_SHA1>,
}

pub type TlvKeySignature = Tlv<TLV_TYPE_KEYSIGNATURE, TlvKeySignatureInner>;

// static const uint32_t INDEX_AUTHEN_IDENTITY     = 0x00000010; // identity
// static const uint32_t INDEX_AUTHEN_PUBLISH      = 0x00000020; // publish key
// static const uint32_t INDEX_AUTHEN_ADMIN        = 0x00000040; // admin key
#[repr(u32)]
#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq, Eq, Hash, Clone)]
pub enum SignType {
    IndexAuthenIdentity = 0x00000010,
    IndexAuthenPublish = 0x00000020,
    IndexAuthenAdmin = 0x00000040,
}

impl Default for SignType {
    fn default() -> Self {
        SignType::IndexAuthenIdentity // ?!
    }
}

// class RsTlvKeySignatureSet : public RsTlvItem
// {
//     std::map<SignType, RsTlvKeySignature> keySignSet; // mandatory
// };
pub type TlvKeySignatureSet =
    TlvMap<TLV_TYPE_KEYSIGNATURESET, Tlv<TLV_TYPE_KEYSIGNATURETYPE, SignType>, TlvKeySignature>;

impl FromSql for TlvKeySignatureSet {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match value.as_bytes_or_null()? {
            Some(bytes) => Ok(from_retroshare_wire(&mut bytes.into())
                .map_err(|err| rusqlite::types::FromSqlError::Other(Box::new(err)))?),
            None => Ok(Self::default()),
        }
    }
}

// class RsTlvRSAKey: public RsTlvItem
// {
//     uint32_t getKeyTypeTlv(void *data, uint32_t size, uint32_t *offset) const;

//     RsGxsId keyId;		// Mandatory :
//     uint32_t keyFlags;		// Mandatory ;
//     uint32_t startTS;		// Mandatory :
//     uint32_t endTS;		// Mandatory :
//     RsTlvBinaryData keyData; 	// Mandatory :
// };

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct TlvRSAKeyInner {
    pub key_id: Tlv<TLV_TYPE_STR_KEYID, GxsId>, // Mandatory :
    pub key_flags: u32,                         // Mandatory ;
    pub start_ts: u32,                          // Mandatory :
    pub end_ts: u32,                            // Mandatory :
    pub key_data: TlvBinaryData<TLV_TYPE_KEY_EVP_PKEY>, // Mandatory :
}
type TlvRSAKey = Tlv<TLV_TYPE_SECURITY_KEY, TlvRSAKeyInner>;

// // The two classes below are by design incompatible, making it impossible to pass a private key as a public key

// class RsTlvPrivateRSAKey: public RsTlvRSAKey
// {
// public:
// 	RsTlvPrivateRSAKey():RsTlvRSAKey() {}
// 	virtual ~RsTlvPrivateRSAKey() {}

// 	virtual bool checkKey() const  ;
// };

pub type TlvPrivateRSAKey = TlvRSAKey;

// class RsTlvPublicRSAKey: public RsTlvRSAKey
// {
// public:
// 	RsTlvPublicRSAKey():RsTlvRSAKey() {}
// 	virtual ~RsTlvPublicRSAKey() {}

// 	virtual bool checkKey() const  ;
// };

pub type TlvPublicRSAKey = TlvRSAKey;

// class RsTlvSecurityKeySet: public RsTlvItem
// {
// 	std::string groupId;					// Mandatory :
// 	std::map<RsGxsId, RsTlvPublicRSAKey> public_keys;	// Mandatory :
// 	std::map<RsGxsId, RsTlvPrivateRSAKey> private_keys;	// Mandatory :
// };

#[derive(Debug, Default)]
pub struct TlvSecurityKeySet {
    group_id: StringTagged<TLV_TYPE_STR_GROUPID>,
    public_keys: HashSet<TlvPublicRSAKey>,
    private_keys: HashSet<TlvPrivateRSAKey>,
}

// neet do manually implement TlvSecurityKeySet since both member `public_keys` and `private_keys` cannot be distingquised once serialized

impl Serialize for TlvSecurityKeySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];

        bytes.extend(to_retroshare_wire(&self.group_id).expect("failed to serialize"));

        for pub_key in &self.public_keys {
            bytes.extend(to_retroshare_wire(pub_key).expect("failed to serialize"));
        }
        for priv_key in &self.private_keys {
            bytes.extend(to_retroshare_wire(priv_key).expect("failed to serialize"));
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

                let group_id = from_retroshare_wire(&mut bytes).expect("failed to deserialize");
                let mut private_keys = HashSet::new();
                let mut public_keys = HashSet::new();

                while !bytes.is_empty() {
                    let key: TlvRSAKey =
                        from_retroshare_wire(&mut bytes).expect("failed to deserialize");
                    match key.key_flags & RSTLV_KEY_TYPE_MASK {
                        RSTLV_KEY_TYPE_PUBLIC_ONLY => {
                            public_keys.insert(key);
                        }
                        RSTLV_KEY_TYPE_FULL => {
                            private_keys.insert(key);
                        }
                        flags @ _ => {
                            log::error!("unkown flags {flags} for TlvRSAKey");
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
        let obj = from_retroshare_wire(&mut bytes)
            .map_err(|err| rusqlite::types::FromSqlError::Other(Box::new(err)))?;
        Ok(obj)
    }
}
