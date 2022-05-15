use std::{fmt, marker::PhantomData};

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    read_u16, read_u32,
    serde::{from_retroshare_wire, to_retroshare_wire},
    write_u16, write_u32,
};

use super::TLV_HEADER_SIZE;

pub struct Tlv<const TAG: u16, T>(T);

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
    T: Deserialize<'de> + Copy + Clone,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TlvVisitor<const TAG: u16, T>(PhantomData<T>);

        impl<'de, const TAG: u16, T> Visitor<'de> for TlvVisitor<TAG, T>
        where
            T: Deserialize<'de> + Copy + Clone,
        {
            type Value = Tlv<TAG, T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "TLV")
            }

            // fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            // where
            //     E: serde::de::Error,
            // {
            //     let tag = read_u16(&mut v[0..2].to_owned());
            //     assert_eq!(tag, TAG);
            //     let len = read_u32(&mut v[2..6].to_owned()) as usize;
            //     assert!(len >= TLV_HEADER_SIZE);
            //     assert!(len == v.len());

            //     let mut bytes = v[6..len].into();
            //     let s: T = from_retroshare_wire(&mut bytes).expect("failed to deserialize");

            //     Ok(Tlv(s))
            // }

            // fn visit_byte_buf<E>(self, mut v: Vec<u8>) -> Result<Self::Value, E>
            // where
            //     E: serde::de::Error,
            // {
            //     let tag = read_u16(&mut v);
            //     assert_eq!(tag, TAG);
            //     let len = read_u32(&mut v) as usize;
            //     assert!(len >= TLV_HEADER_SIZE);
            //     assert!(len == v.len());

            //     let s: T = from_retroshare_wire(&mut v).expect("failed to deserialize");

            //     Ok(Tlv(s))
            // }

            // fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            // where
            //     E: serde::de::Error,
            // {
            //     let tag = read_u16(&mut v[0..2].to_owned());
            //     assert_eq!(tag, TAG);
            //     let len = read_u32(&mut v[2..6].to_owned()) as usize;
            //     assert!(len >= TLV_HEADER_SIZE);
            //     assert!(len == v.len());

            //     // let mut bytes = v[6..len].into();
            //     let s: T = from_retroshare_wire(v).expect("failed to deserialize");

            //     Ok(Tlv(s))
            // }
        }

        deserializer.deserialize_byte_buf(TlvVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests_tlv {
    use std::collections::HashSet;

    use super::Tlv;
    use crate::{basics::SslId, serde::to_retroshare_wire, tlv::TlvPeerIdSet};
    use serde::{Deserialize, Serialize};

    macro_rules! do_it {
        ($tag:expr, $val:expr, $expected:expr) => {
            let orig: Tlv<_, $tag> = Tlv($val);
            let ser = to_retroshare_wire(&orig).unwrap();
            println!("{ser:?}");
            assert_eq!(ser, $expected);
        };
    }

    macro_rules! do_it_not {
        ($tag:expr, $val:expr, $expected:expr) => {
            let orig: Tlv<_, $tag> = Tlv($val);
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
