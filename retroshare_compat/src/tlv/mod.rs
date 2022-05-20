use std::{
    fmt::{self, Display},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    read_u16, read_u32,
    serde::{from_retroshare_wire, to_retroshare_wire},
    write_u16, write_u32,
};

pub mod tags;
pub mod tlv_ip_addr;
pub mod tlv_keys;
pub mod tlv_map;
pub mod tlv_set;
pub mod tlv_string;

pub const TLV_HEADER_SIZE: usize = 6;

/// Generic TLV type that expects the innter `T` to **not include a size** when being serialized.
///
/// This is usefull for wrapping stucts into TLV, for exmaple, `type Test = Tlv<0x1337, u8>`
#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Tlv<const TAG: u16, T>(pub T);

impl<const TAG: u16, T> Serialize for Tlv<TAG, T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = to_retroshare_wire(&self.0).expect("failed to serialize");

        let mut ser = vec![];
        write_u16(&mut ser, TAG);
        write_u32(&mut ser, (bytes.len() + TLV_HEADER_SIZE) as u32);
        ser.extend_from_slice(&bytes);

        serializer.serialize_bytes(ser.as_slice())
    }
}

impl<'de, const TAG: u16, T> Deserialize<'de> for Tlv<TAG, T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TlvVisitor<const TAG: u16, T>(PhantomData<T>);

        impl<'de, const TAG: u16, T> Visitor<'de> for TlvVisitor<TAG, T>
        where
            T: DeserializeOwned,
        {
            type Value = Tlv<TAG, T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "TLV")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let tag = read_u16(&mut v[0..2].to_owned());
                if tag != TAG {
                    return Err(::serde::de::Error::custom(crate::serde::Error::WrongTag));
                }
                let len = read_u32(&mut v[2..6].to_owned()) as usize;
                assert!(len >= TLV_HEADER_SIZE);
                assert!(len == v.len());

                let mut bytes = v[6..len].into();
                let s: T = from_retroshare_wire(&mut bytes).expect("failed to deserialize");

                Ok(Tlv(s))
            }
        }

        deserializer.deserialize_byte_buf(TlvVisitor(PhantomData))
    }
}

impl<const TAG: u16, T> Deref for Tlv<TAG, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const TAG: u16, T> DerefMut for Tlv<TAG, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const TAG: u16, T> Display for Tlv<TAG, T>
where
    T: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const TAG: u16, T> From<T> for Tlv<TAG, T> {
    fn from(t: T) -> Self {
        Self(t)
    }
}

// https://doc.rust-lang.org/error-index.html#E0210
// impl<const TAG: u16, T> From<Tlv<TAG, T>> for T {
//     fn from(t: Tlv<TAG, T>) -> Self {
//         t.0
//     }
// }

// impl<const TAG: u16, T> Into<T> for Tlv<TAG, T> {
//     fn into(self) -> T {
//         self.0
//     }
// }

/// Generic TLV type that expects the innter `T` to **contain its byte size** when being serialized.
///
/// This is usefull for wrapping stucts into TLV, for exmaple, `type Test = Tlv2<0x1337, String>`
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Tlv2<const TAG: u16, T>(T);

impl<const TAG: u16, T: Serialize> Serialize for Tlv2<TAG, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = to_retroshare_wire(&self.0).expect("failed to serialize");

        // remove length
        // let bytes: Vec<_> = bytes.drain(4..).collect();
        let _: Vec<_> = bytes.drain(..4).collect();

        let mut ser = vec![];
        write_u16(&mut ser, TAG);
        write_u32(&mut ser, (bytes.len() + TLV_HEADER_SIZE) as u32);
        ser.extend(bytes);

        serializer.serialize_bytes(ser.as_slice())
    }
}

impl<'de, const TAG: u16, T: DeserializeOwned> Deserialize<'de> for Tlv2<TAG, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Tlv2Visitor<const TAG: u16, T>(PhantomData<T>);

        impl<'de, const TAG: u16, T: DeserializeOwned> Visitor<'de> for Tlv2Visitor<TAG, T> {
            type Value = Tlv2<TAG, T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a Tlv2")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let tag = read_u16(&mut v[0..2].to_owned());
                if tag != TAG {
                    return Err(::serde::de::Error::custom(crate::serde::Error::WrongTag));
                }
                let len = read_u32(&mut v[2..6].to_owned()) as usize;
                assert!(len >= TLV_HEADER_SIZE);
                assert!(len == v.len());

                let mut bytes = vec![];
                write_u32(&mut bytes, (len - TLV_HEADER_SIZE) as u32);
                bytes.extend_from_slice(&v[6..len]);

                let s = from_retroshare_wire(&mut bytes).expect("failed to deserialize");

                Ok(Tlv2(s))
            }
        }

        deserializer.deserialize_bytes(Tlv2Visitor(PhantomData))
    }
}

impl<const TAG: u16, T> Deref for Tlv2<TAG, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const TAG: u16, T> DerefMut for Tlv2<TAG, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const TAG: u16, T> Display for Tlv2<TAG, T>
where
    T: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const TAG: u16, T> From<T> for Tlv2<TAG, T> {
    fn from(a: T) -> Self {
        Self(a)
    }
}

#[cfg(test)]
mod test_tlv {
    use std::collections::HashSet;

    use crate::{
        basics::SslId,
        serde::{from_retroshare_wire, to_retroshare_wire},
        tlv::{tlv_set::TlvPeerIdSet, Tlv, Tlv2, TLV_HEADER_SIZE},
        write_u16, write_u32,
    };
    use serde::{Deserialize, Serialize};

    macro_rules! do_it {
        ($tag:expr, $val:expr, $expected:expr) => {
            let mut expected = vec![];
            write_u16(&mut expected, $tag);
            write_u32(
                &mut expected,
                (std::mem::size_of_val(&$val) + TLV_HEADER_SIZE) as u32,
            );
            expected.append(&mut $expected);

            let orig: Tlv<$tag, _> = Tlv($val);
            let ser = to_retroshare_wire(&orig).unwrap();
            println!("{ser:?}");

            assert_eq!(ser, expected);
        };
    }

    macro_rules! do_it_not {
        ($tag:expr, $val:expr, $expected:expr) => {
            let mut expected = vec![];
            write_u16(&mut expected, $tag);
            write_u32(
                &mut expected,
                (std::mem::size_of_val(&$val) + TLV_HEADER_SIZE) as u32,
            );
            expected.append(&mut $expected);

            let orig: Tlv<$tag, _> = Tlv($val);
            let ser = to_retroshare_wire(&orig).unwrap();
            println!("{ser:?}");

            assert_ne!(ser, expected);
        };
    }

    #[test]
    fn test_tlv_good() {
        do_it!(
            0x1337,
            [1, 2, 3, 4, 5] as [u8; 5],
            hex::decode("0102030405").unwrap()
        );
        do_it!(
            0x1338,
            [1, 2, 3, 4, 5] as [u16; 5],
            hex::decode("00010002000300040005").unwrap()
        );

        // ints
        do_it!(0x1478, 0x42u8, hex::decode("42").unwrap());
        do_it!(0x1478, 0x4200u16, hex::decode("4200").unwrap());
        do_it!(0x1478, 0x4200i16, hex::decode("4200").unwrap());
        do_it!(0x1478, 0x42000000u32, hex::decode("42000000").unwrap());
        do_it!(
            0x1478,
            0x4200000000000000u64,
            hex::decode("4200000000000000").unwrap()
        );
    }

    #[test]
    fn test_tlv_bad() {
        // anything that stores a length internaly doesn't work
        // String
        do_it_not!(
            0x5c,
            String::from("laptop-giomium"),
            hex::decode("6c6170746f702d67696f6d69756d").unwrap()
        );

        // HashSet
        // TlvPeerIdSet
        #[derive(Serialize, Deserialize)]
        pub struct Dummy(HashSet<SslId>);
        let a1 = Dummy { 0: HashSet::new() };
        let a2 = TlvPeerIdSet {
            ..Default::default()
        };
        let b = a2.write();
        do_it_not!(0x1021, a1, b.into());
    }

    #[test]
    fn test_tlv_with_length_cut() {
        type TestType = Tlv2<0x1337, Vec<u8>>;

        let orig = TestType {
            0: vec![1, 2, 3, 4, 5, 6],
        };

        let expected = hex::decode("13370000000c010203040506").unwrap();

        let mut ser = to_retroshare_wire(&orig).unwrap();

        assert_eq!(ser, expected);

        let de: TestType = from_retroshare_wire(&mut ser).unwrap();

        assert_eq!(orig, de);
    }
}
