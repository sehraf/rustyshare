// HeY kIdS tHiS iS fUn
// RsTlvGenericMapRef<K, V>
//  - RsTlvGenericPairRef<K, V>
//     - RsTlvParamRef<K> key(mKeyType, mKey);
//        - Tlv
//     - RsTlvParamRef<V> value(mValueType, mValue);
//        - Tlv

// UNLESS IT IS DIFFERENT ...
// RsTlvKeySignatureSet<K, V>
//  - RsTlvParamRef<K> key(mKeyType, mKey);
//     - Tlv
//  - RsTlvParamRef<V> value(mValueType, mValue);
//     - Tlv

use std::{collections::HashMap, hash::Hash, marker::PhantomData};

use serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    read_u16, read_u32,
    serde::{from_retroshare_wire_result, to_retroshare_wire_result},
    write_u16, write_u32,
};

use super::{Tlv, TLV_HEADER_SIZE};

pub type TlvGenericPairRef<const TAG: u16, K, V> = Tlv<TAG, (K, V)>;

#[derive(Debug, Default, Clone)]
pub struct TlvMap<const TAG: u16, K, V>(pub HashMap<K, V>)
where
    K: PartialEq + Eq + Hash;

impl<const TAG: u16, K, V> Serialize for TlvMap<TAG, K, V>
where
    K: PartialEq + Eq + Clone + Serialize + Hash,
    V: Clone + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];

        for (key, val) in &self.0 {
            let pair: (K, V) = (key.to_owned(), val.to_owned());
            bytes.extend(to_retroshare_wire_result(&pair).expect("failed to serialize"));
        }

        let mut ser = vec![];
        write_u16(&mut ser, TAG);
        write_u32(&mut ser, (bytes.len() + TLV_HEADER_SIZE) as u32);
        ser.extend_from_slice(&bytes);

        serializer.serialize_bytes(ser.as_slice())
    }
}

impl<'de, const TAG: u16, K, V> Deserialize<'de> for TlvMap<TAG, K, V>
where
    K: PartialEq + Eq + DeserializeOwned + Hash,
    V: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TlvVisitor<const TAG: u16, K, V>(PhantomData<(K, V)>);

        impl<'de, const TAG: u16, K, V> Visitor<'de> for TlvVisitor<TAG, K, V>
        where
            K: PartialEq + Eq + DeserializeOwned + Hash,
            V: DeserializeOwned,
        {
            type Value = TlvMap<TAG, K, V>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "TLV")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                let mut item = HashMap::new();
                let tag = read_u16(&mut v[0..2].to_owned());
                if tag != TAG {
                    return Err(::serde::de::Error::custom(crate::serde::Error::WrongTag));
                }
                let len = read_u32(&mut v[2..6].to_owned()) as usize;
                assert!(len >= TLV_HEADER_SIZE);
                assert!(len == v.len());

                let mut bytes: Vec<_> = v[6..len].into();
                while !bytes.is_empty() {
                    let pair: (K, V) =
                        from_retroshare_wire_result(&mut bytes).expect("failed to deserialize");

                    item.insert(pair.0, pair.1);
                }

                Ok(TlvMap(item))
            }
        }

        deserializer.deserialize_byte_buf(TlvVisitor(PhantomData))
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct TlvMapWithPair<const TAG: u16, const TAG_PAIR: u16, K, V>(pub HashMap<K, V>)
where
    K: PartialEq + Eq + Hash,
    V: PartialEq;

impl<const TAG: u16, const TAG_PAIR: u16, K, V> Serialize for TlvMapWithPair<TAG, TAG_PAIR, K, V>
where
    K: PartialEq + Eq + Clone + Serialize + Hash,
    V: PartialEq + Clone + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];

        for (key, val) in &self.0 {
            let pair: TlvGenericPairRef<TAG_PAIR, K, V> = (key.to_owned(), val.to_owned()).into();
            bytes.extend(to_retroshare_wire_result(&pair).expect("failed to serialize"));
        }

        let mut ser = vec![];
        write_u16(&mut ser, TAG);
        write_u32(&mut ser, (bytes.len() + TLV_HEADER_SIZE) as u32);
        ser.extend_from_slice(&bytes);

        serializer.serialize_bytes(ser.as_slice())
    }
}

impl<'de, const TAG: u16, const TAG_PAIR: u16, K, V> Deserialize<'de>
    for TlvMapWithPair<TAG, TAG_PAIR, K, V>
where
    K: PartialEq + Eq + DeserializeOwned + Hash,
    V: PartialEq + DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TlvVisitor<const TAG: u16, const TAG_PAIR: u16, K, V>(PhantomData<(K, V)>);

        impl<'de, const TAG: u16, const TAG_PAIR: u16, K, V> Visitor<'de>
            for TlvVisitor<TAG, TAG_PAIR, K, V>
        where
            K: PartialEq + Eq + DeserializeOwned + Hash,
            V: PartialEq + DeserializeOwned,
        {
            type Value = TlvMapWithPair<TAG, TAG_PAIR, K, V>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "TLV")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                let mut item = HashMap::new();
                let tag = read_u16(&mut v[0..2].to_owned());
                if tag != TAG {
                    return Err(::serde::de::Error::custom(crate::serde::Error::WrongTag));
                }
                let len = read_u32(&mut v[2..6].to_owned()) as usize;
                assert!(len >= TLV_HEADER_SIZE);
                assert!(len == v.len());

                let mut bytes: Vec<_> = v[6..len].into();
                while !bytes.is_empty() {
                    let pair: TlvGenericPairRef<TAG_PAIR, K, V> =
                        from_retroshare_wire_result(&mut bytes).expect("failed to deserialize");

                    item.insert(pair.0 .0, pair.0 .1);
                }

                Ok(TlvMapWithPair(item))
            }
        }

        deserializer.deserialize_byte_buf(TlvVisitor(PhantomData))
    }
}
