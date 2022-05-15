#[cfg(not(feature = "cookie-nom"))]
use byteorder::{ByteOrder, NetworkEndian};
#[cfg(feature = "cookie-nom")]
use cookie_factory;
#[cfg(feature = "cookie-nom")]
use nom;

pub mod serde;
pub mod tlv;

// pub mod bwctrl;
pub mod basics;
pub mod events;
pub mod groups;
pub mod gxs;
pub mod keyring;
pub mod peers;
pub mod services;
pub mod sqlite;

// write
#[cfg(not(feature = "cookie-nom"))]
macro_rules! gen_writer {
    ($name:ident, $type:ty, $byte_width:expr) => {
        pub fn $name(data: &mut Vec<u8>, val: $type) {
            const SIZE: usize = $byte_width;
            let mut buf: [u8; SIZE] = [0; SIZE];
            NetworkEndian::$name(&mut buf, val);
            data.extend_from_slice(&buf);
        }
    };
}
#[cfg(not(feature = "cookie-nom"))]
gen_writer!(write_u16, u16, 2);
#[cfg(not(feature = "cookie-nom"))]
gen_writer!(write_u32, u32, 4);
#[cfg(not(feature = "cookie-nom"))]
gen_writer!(write_u64, u64, 8);

#[cfg(feature = "cookie-nom")]
macro_rules! gen_writer {
    ($name:ident, $type:ty, $type2: ident, $byte_width:expr) => {
        pub fn $name(data: &mut Vec<u8>, val: $type) {
            cookie_factory::gen(cookie_factory::bytes::$type2(val), data).unwrap();
        }
    };
}
#[cfg(feature = "cookie-nom")]
gen_writer!(write_u16, u16, be_u16, 2);
#[cfg(feature = "cookie-nom")]
gen_writer!(write_u32, u32, be_u32, 4);
#[cfg(feature = "cookie-nom")]
gen_writer!(write_u64, u64, be_u64, 8);

// reader
#[cfg(not(feature = "cookie-nom"))]
macro_rules! gen_reader {
    ($name:ident, $type:ty, $byte_width:expr) => {
        pub fn $name(data: &mut Vec<u8>) -> $type {
            const SIZE: usize = $byte_width;
            let d: Vec<u8> = data.drain(0..SIZE).collect();
            NetworkEndian::$name(d.as_slice())
        }
    };
}
#[cfg(not(feature = "cookie-nom"))]
gen_reader!(read_u16, u16, 2);
#[cfg(not(feature = "cookie-nom"))]
gen_reader!(read_u32, u32, 4);
#[cfg(not(feature = "cookie-nom"))]
gen_reader!(read_u64, u64, 8);

#[cfg(feature = "cookie-nom")]
macro_rules! gen_reader {
    ($name:ident, $type:ty, $type2: ident, $byte_width:expr) => {
        pub fn $name(data: &mut Vec<u8>) -> $type {
            const SIZE: usize = $byte_width;

            fn nom_read(data: &[u8]) -> nom::IResult<&[u8], $type> {
                nom::number::complete::$type2(data)
            }

            nom_read(data.drain(0..SIZE).collect::<Vec<u8>>().as_slice())
                .unwrap()
                .1
        }
    };
}

#[cfg(feature = "cookie-nom")]
gen_reader!(read_u16, u16, be_u16, 2);
#[cfg(feature = "cookie-nom")]
gen_reader!(read_u32, u32, be_u32, 4);
#[cfg(feature = "cookie-nom")]
gen_reader!(read_u64, u64, be_u64, 8);

#[cfg(not(feature = "cookie-nom"))]
pub fn read_string(data: &mut Vec<u8>) -> String {
    let str_len: usize = read_u32(data) as usize;
    String::from_utf8(data.drain(..str_len).collect()).unwrap()
}
#[cfg(not(feature = "cookie-nom"))]
pub fn write_string(data: &mut Vec<u8>, val: &str) {
    write_u32(data, val.len() as u32); // len
    data.extend_from_slice(val.as_bytes());
}

#[cfg(feature = "cookie-nom")]
pub fn write_string(data: &mut Vec<u8>, val: &str) {
    let gen_len = cookie_factory::bytes::be_u32(val.len() as u32);
    let gen_str = cookie_factory::combinator::string(val);
    let gen = cookie_factory::sequence::pair(gen_len, gen_str);
    cookie_factory::gen(gen, data).unwrap();
}
#[cfg(feature = "cookie-nom")]
pub fn read_string(data: &mut Vec<u8>) -> String {
    fn nom_read(data: &[u8]) -> nom::IResult<&[u8], String> {
        let res: nom::IResult<&[u8], u32> = nom::number::complete::be_u32(data);
        let (next, len) = res.unwrap();
        nom::combinator::map_res(nom::bytes::complete::take(len), |b: &[u8]| {
            String::from_utf8(b.to_vec())
        })(next)
    }
    nom_read(data.as_slice()).unwrap().1
}

#[cfg(test)]
mod tests_compat {
    use std::collections::HashMap;

    use crate::serde::{from_retroshare_wire, to_retroshare_wire};
    use ::serde::{Deserialize, Serialize};

    #[test]
    fn test_uints() {
        let u8 = 42 as u8;
        let mut ser = to_retroshare_wire(&u8).expect("failed to serialize");
        // println!("u8: {:02X?}", ser);
        assert_eq!(&ser, &vec![42]);
        let de: u8 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, u8);

        let u16 = 42 as u16;
        let mut ser = to_retroshare_wire(&u16).expect("failed to serialize");
        // println!("u16: {:02X?}", ser);
        assert_eq!(&ser, &vec![0, 42]);
        let de: u16 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, u16);

        let u32 = 42 as u32;
        let mut ser = to_retroshare_wire(&u32).expect("failed to serialize");
        // println!("u32: {:02X?}", ser);
        assert_eq!(&ser, &vec![0, 0, 0, 42]);
        let de: u32 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, u32);

        let u64 = 42 as u64;
        let mut ser = to_retroshare_wire(&u64).expect("failed to serialize");
        // println!("u64: {:02X?}", ser);
        assert_eq!(&ser, &vec![0, 0, 0, 0, 0, 0, 0, 42]);
        let de: u64 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, u64);
    }

    #[test]
    fn test_ints() {
        let i8 = -42 as i8;
        let mut ser = to_retroshare_wire(&i8).expect("failed to serialize");
        assert_eq!(&ser, &vec![0xD6]);
        let de: i8 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, i8);

        let i16 = -42 as i16;
        let mut ser = to_retroshare_wire(&i16).expect("failed to serialize");
        assert_eq!(&ser, &vec![0xFF, 0xD6]);
        let de: i16 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, i16);

        let i32 = -42 as i32;
        let mut ser = to_retroshare_wire(&i32).expect("failed to serialize");
        // println!("i32: {:02X?}", ser);
        assert_eq!(&ser, &vec![0xFF, 0xFF, 0xFF, 0xD6]);
        let de: i32 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, i32);

        let i64 = -42 as i64;
        let mut ser = to_retroshare_wire(&i64).expect("failed to serialize");
        assert_eq!(&ser, &vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xD6]);
        let de: i64 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, i64);
    }

    #[test]
    fn test_float() {
        let f = 42.420 as f32;
        let mut ser = to_retroshare_wire(&f).expect("failed to serialize");
        let de: f32 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, f);

        // not implemented
        let f = 42.420 as f64;
        let mut _ser = to_retroshare_wire(&f).expect_err("this is supposed to be unimplemented");
        // let de: f64 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        // assert_eq!(de, f);
    }

    #[test]
    fn test_string() {
        let foo = String::from("test");
        let mut ser = to_retroshare_wire(&foo).expect("failed to serialize");
        let de: String = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }

    #[test]
    fn test_struct() {
        #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
        pub struct SerialTest {
            a: u8,
            b: u16,
            c: i32,
            d: String,
        }

        let foo = SerialTest {
            a: 0x42,
            b: 0x69,
            c: -0x420,
            d: String::from("hello serde"),
        };
        let mut ser = to_retroshare_wire(&foo).expect("failed to serialize");
        // println!("{:02X?}", ser);
        let de: SerialTest = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }

    #[test]
    fn test_vec() {
        let foo: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut ser = to_retroshare_wire(&foo).expect("failed to serialize");
        let de: Vec<u8> = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }

    #[test]
    fn test_tuple() {
        let foo = (21 as u8, 42, String::from("tuple test"));
        let mut ser = to_retroshare_wire(&foo).expect("failed to serialize");
        let de: (u8, i32, String) = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }

    #[test]
    fn test_map() {
        let mut foo = std::collections::HashMap::new();
        // Review some books.
        foo.insert(
            "Adventures of Huckleberry Finn".to_string(),
            "My favorite book.".to_string(),
        );
        foo.insert(
            "Grimms' Fairy Tales".to_string(),
            "Masterpiece.".to_string(),
        );
        foo.insert(
            "Pride and Prejudice".to_string(),
            "Very enjoyable.".to_string(),
        );
        foo.insert(
            "The Adventures of Sherlock Holmes".to_string(),
            "Eye lyked it alot.".to_string(),
        );
        let mut ser = to_retroshare_wire(&foo).expect("failed to serialize");
        // println!("{:02X?}", ser);
        let de: HashMap<String, String> =
            from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }

    #[test]
    fn test_complex() {
        #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
        pub struct SerialTest {
            a: u32,
            b: Vec<String>,
            c: u32,
            d: String,
            e: u32,
            f: HashMap<u32, Vec<String>>,
            g: u32,
        }

        let mut map: HashMap<u32, Vec<String>> = HashMap::new();
        map.insert(0x1337, vec![String::from("This"), String::from("is")]);
        map.insert(0x1338, vec![String::from("yet")]);
        map.insert(
            0x1339,
            vec![
                String::from("another"),
                String::from("unexpected"),
                String::from("test!"),
            ],
        );

        let foo = SerialTest {
            a: 0xAAAAAAAA,
            b: vec![
                String::from("this"),
                String::from("is"),
                String::from("a"),
                String::from("test!"),
            ],
            c: 0xAAAAAAAA,
            d: String::from("hello serde"),
            e: 0xAAAAAAAA,
            f: map,
            g: 0xAAAAAAAA,
        };
        let mut ser = to_retroshare_wire(&foo).expect("failed to serialize");
        println!("{:02X?}", ser);
        let de: SerialTest = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }

    #[test]
    fn test_new_type_struct() {
        #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
        struct Test(u64);

        let foo = Test(0x42);
        let mut ser = to_retroshare_wire(&foo).expect("failed to serialize");
        let de: Test = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }
}

// #[cfg(test)]
// mod tests_tlv {
//     use crate::tlv::{
//         serde::{from_tlv, to_tlv},
//         *,
//     };
//     use ::serde::{Deserialize, Serialize};

//     #[test]
//     fn test_taged_string() {
//         impl RsTagged for String {
//             fn get_tag(&self) -> u16 {
//                 0x5c
//             }
//         }

//         const TAG: u16 = 0x5c;
//         let foo = String::from("laptop-giomium");
//         let mut ser = to_tlv(&foo, foo.get_tag()).expect("failed to serialize");

//         // verify correct serialization
//         let b = hex::decode("005c000000146c6170746f702d67696f6d69756d").unwrap();
//         assert_eq!(ser, b);

//         let de: String = from_tlv(&mut ser, TAG).expect("failed to deserialize");
//         assert_eq!(de, foo);
//     }

//     #[test]
//     fn test_struct() {
//         const TAG: u16 = 0x1337;

//         #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
//         struct NestedA {
//             a: u16,
//             b: u16,
//         }

//         #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
//         struct NestedB {
//             c: u32,
//             d: u32,
//         }

//         impl RsTagged for NestedA {
//             fn get_tag(&self) -> u16 {
//                 42
//             }
//         }

//         impl RsTagged for NestedB {
//             fn get_tag(&self) -> u16 {
//                 8456
//             }
//         }
//         #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
//         struct Test {
//             foo: NestedA,
//             bar: NestedB,
//         }

//         impl RsTagged for Test {
//             fn get_tag(&self) -> u16 {
//                 0x1337
//             }
//         }

//         let foo = Test {
//             foo: NestedA { a: 0x11, b: 0x99 },
//             bar: NestedB {
//                 c: 0xaaaa,
//                 d: 0xffff,
//             },
//         };
//         let mut ser = to_tlv(&foo, TAG).expect("failed to serialize");

//         println!("{}", hex::encode(ser.as_slice()));

//         let de: Test = from_tlv(&mut ser, TAG).expect("failed to deserialize");
//         assert_eq!(de, foo);
//     }

//     #[test]
//     fn test_tlv_ip_addr_set() {
//         let foo: TlvIpAddrSet = TlvIpAddrSet::default();
//         let mut ser: Vec<u8> = vec![];
//         write_tlv_ip_addr_set(&mut ser, &foo);
//         let de: TlvIpAddrSet = read_tlv_ip_addr_set(&mut ser);
//         assert_eq!(de, foo);
//     }
// }
