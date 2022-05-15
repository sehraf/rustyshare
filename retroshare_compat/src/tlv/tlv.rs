use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};

use crate::serde::{from_retroshare_wire, to_retroshare_wire};

pub struct Tlv<T, const ID: u16> {
    inner: T,
}

impl<T: Serialize, const ID: u16> Serialize for Tlv<T, ID> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let inner = to_retroshare_wire(&self.inner).unwrap();
        let _len = inner.len() as u32;

        let mut state = serializer.serialize_struct("Tlv", 2)?;
        state.serialize_field("tag", &ID)?;
        // state.serialize_field("len", &len)?;
        state.serialize_field("val", &inner)?;

        state.end()
    }
}

// struct TlvVisitorU16;

// impl<'de> Visitor<'de> for TlvVisitorU16 {
//     type Value = u16;

//     fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
//         formatter.write_str("u16")
//     }

//     fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
//     where
//         E: serde::de::Error,
//     {
//         Ok(v)
//     }
// }

// struct TlvVisitorU32;

// impl<'de> Visitor<'de> for TlvVisitorU32 {
//     type Value = u32;

//     fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
//         formatter.write_str("u32")
//     }

//     fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
//     where
//         E: serde::de::Error,
//     {
//         Ok(v)
//     }
// }

// struct TlvVisitorVec;

// impl<'de> Visitor<'de> for TlvVisitorVec {
//     type Value = Vec<u8>;

//     fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
//         formatter.write_str("Vec<u8>")
//     }

//     fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
//     where
//         E: serde::de::Error,
//     {
//         Ok(Vec::from(v))
//     }
// }

// struct TlvVisitor<T, ID>;

// impl<'de, T, const ID: u16> Visitor<'de> for TlvVisitor<T, ID> {
//     type Value = Tlv<T, ID>;

//     fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
//         formatter.write_str("TLV")
//     }

//     fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
//     where
//         V: SeqAccess<'de>,
//     {
//         let tag = seq
//             .next_element()?
//             .ok_or_else(|| de::Error::invalid_length(0, &self))?;
//         let len = seq
//             .next_element()?
//             .ok_or_else(|| de::Error::invalid_length(1, &self))?;
//         let val = seq
//             .next_element()?
//             .ok_or_else(|| de::Error::invalid_length(1, &self))?;

//         let inner: T = from_retroshare_wire(&mut val).unwrap();

//         Ok(Self::Value { inner })
//     }
// }

// impl<'de, T: Serialize + Deserialize<'de>, const ID: u16> Deserialize<'de> for Tlv<T, ID> {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         // let tag = deserializer.deserialize_u16(TlvVisitorU16)?;
//         // let len = deserializer.deserialize_u32(TlvVisitorU32)?;
//         // let mut val = deserializer.deserialize_bytes(TlvVisitorVec)?;

//         // let inner: T = from_retroshare_wire(&mut val).unwrap();

//         // Ok(Self { inner })

//         const FIELDS: &'static [&'static str] = &["tag", "len", "val"];
//         let a = deserializer.deserialize_struct("tlv", FIELDS, TlvVisitor)?;
//     }
// }

#[cfg(test)]
mod tests_tlv {
    use std::collections::HashSet;

    use super::Tlv;
    use crate::{basics::SslId, serde::to_retroshare_wire, tlv::TlvPeerIdSet};
    use serde::{Deserialize, Serialize};

    macro_rules! do_it {
        ($tag:expr, $val:expr, $expected:expr) => {
            let orig: Tlv<_, $tag> = Tlv { inner: $val };
            let ser = to_retroshare_wire(&orig).unwrap();
            println!("{ser:?}");
            assert_eq!(ser, $expected);
        };
    }

    macro_rules! do_it_not {
        ($tag:expr, $val:expr, $expected:expr) => {
            let orig: Tlv<_, $tag> = Tlv { inner: $val };
            let ser = to_retroshare_wire(&orig).unwrap();
            println!("{ser:?}");
            assert_ne!(ser, $expected);
        };
    }

    #[test]
    fn test_string_typed() {
        // let s = "test123";
        // let tag = 0x1337;

        // let mut data = vec![];

        // write_string_typed(&mut data, &s, tag);

        // let expected = vec![
        //     0x13, 0x37, 0x00, 0x00, 0x00, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33,
        // ];
        // assert_eq!(&data, &expected);

        // assert_eq!(read_string_typed(&mut data, tag), s);

        // {
        //     let orig: Tlv<[u8; 5], 0x1337> = Tlv {
        //         inner: [1, 2, 3, 4, 5],
        //     };

        //     let expected = vec![
        //         0x13, 0x37, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
        //     ];

        //     let ser = to_retroshare_wire(&orig).unwrap();
        //     println!("{ser:?}");
        //     assert_eq!(ser, expected);
        // }

        do_it!(
            0x1337,
            [1, 2, 3, 4, 5] as [u8; 5],
            vec![0x13, 0x37, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,]
        );

        // Strings do not work, since encoding a string adds a len "internally" which gets doubled with the len of the resulting vector
        do_it_not!(
            0x5c,
            String::from("laptop-giomium"),
            hex::decode("005c000000146c6170746f702d67696f6d69756d").unwrap()
        );

        // TlvPeerIdSet
        #[derive(Serialize, Deserialize)]
        pub struct Dummy(HashSet<SslId>);
        let a1 = Dummy { 0: HashSet::new() };
        let a2 = TlvPeerIdSet {
            ..Default::default()
        };
        let b = a2.write();
        do_it_not!(0x1021, a1, b);
    }
}
