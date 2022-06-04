use byteorder::{ByteOrder, NetworkEndian};

pub mod basics;
pub mod config;
pub mod events;
pub mod gxs;
pub mod keyring;
pub mod peers;
pub mod serde;
pub mod services;
pub mod tlv;
pub mod webui;

// pub mod foo;

// write
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
gen_writer!(write_u16, u16, 2);
gen_writer!(write_u32, u32, 4);
gen_writer!(write_u64, u64, 8);

// reader
macro_rules! gen_reader {
    ($name:ident, $type:ty, $byte_width:expr) => {
        pub fn $name(data: &mut Vec<u8>) -> $type {
            const SIZE: usize = $byte_width;
            let d: Vec<u8> = data.drain(0..SIZE).collect();
            NetworkEndian::$name(d.as_slice())
        }
    };
}
gen_reader!(read_u16, u16, 2);
gen_reader!(read_u32, u32, 4);
gen_reader!(read_u64, u64, 8);

#[cfg(test)]
mod tests_compat {
    use std::collections::HashMap;

    use crate::serde::{from_retroshare_wire_result, to_retroshare_wire_result};
    use ::serde::{Deserialize, Serialize};

    #[test]
    fn test_uints() {
        let u8 = 42 as u8;
        let mut ser = to_retroshare_wire_result(&u8).expect("failed to serialize");
        // println!("u8: {:02X?}", ser);
        assert_eq!(&ser, &vec![42]);
        let de: u8 = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, u8);

        let u16 = 42 as u16;
        let mut ser = to_retroshare_wire_result(&u16).expect("failed to serialize");
        // println!("u16: {:02X?}", ser);
        assert_eq!(&ser, &vec![0, 42]);
        let de: u16 = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, u16);

        let u32 = 42 as u32;
        let mut ser = to_retroshare_wire_result(&u32).expect("failed to serialize");
        // println!("u32: {:02X?}", ser);
        assert_eq!(&ser, &vec![0, 0, 0, 42]);
        let de: u32 = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, u32);

        let u64 = 42 as u64;
        let mut ser = to_retroshare_wire_result(&u64).expect("failed to serialize");
        // println!("u64: {:02X?}", ser);
        assert_eq!(&ser, &vec![0, 0, 0, 0, 0, 0, 0, 42]);
        let de: u64 = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, u64);
    }

    #[test]
    fn test_ints() {
        let i8 = -42 as i8;
        let mut ser = to_retroshare_wire_result(&i8).expect("failed to serialize");
        assert_eq!(&ser, &vec![0xD6]);
        let de: i8 = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, i8);

        let i16 = -42 as i16;
        let mut ser = to_retroshare_wire_result(&i16).expect("failed to serialize");
        assert_eq!(&ser, &vec![0xFF, 0xD6]);
        let de: i16 = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, i16);

        let i32 = -42 as i32;
        let mut ser = to_retroshare_wire_result(&i32).expect("failed to serialize");
        // println!("i32: {:02X?}", ser);
        assert_eq!(&ser, &vec![0xFF, 0xFF, 0xFF, 0xD6]);
        let de: i32 = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, i32);

        let i64 = -42 as i64;
        let mut ser = to_retroshare_wire_result(&i64).expect("failed to serialize");
        assert_eq!(&ser, &vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xD6]);
        let de: i64 = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, i64);
    }

    #[test]
    fn test_float() {
        let f = 42.420 as f32;
        let mut ser = to_retroshare_wire_result(&f).expect("failed to serialize");
        let de: f32 = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, f);

        // not implemented
        let f = 42.420 as f64;
        let mut _ser =
            to_retroshare_wire_result(&f).expect_err("this is supposed to be unimplemented");
        // let de: f64 = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        // assert_eq!(de, f);
    }

    #[test]
    fn test_string() {
        let foo = String::from("test");
        let mut ser = to_retroshare_wire_result(&foo).expect("failed to serialize");
        let de: String = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
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
        let mut ser = to_retroshare_wire_result(&foo).expect("failed to serialize");
        // println!("{:02X?}", ser);
        let de: SerialTest = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }

    #[test]
    fn test_vec() {
        let foo: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut ser = to_retroshare_wire_result(&foo).expect("failed to serialize");
        let de: Vec<u8> = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }

    #[test]
    fn test_tuple() {
        let foo = (21 as u8, 42, String::from("tuple test"));
        let mut ser = to_retroshare_wire_result(&foo).expect("failed to serialize");
        let de: (u8, i32, String) =
            from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
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
        let mut ser = to_retroshare_wire_result(&foo).expect("failed to serialize");
        // println!("{:02X?}", ser);
        let de: HashMap<String, String> =
            from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
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
        let mut ser = to_retroshare_wire_result(&foo).expect("failed to serialize");
        println!("{:02X?}", ser);
        let de: SerialTest = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }

    #[test]
    fn test_new_type_struct() {
        #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
        struct Test(u64);

        let foo = Test(0x42);
        let mut ser = to_retroshare_wire_result(&foo).expect("failed to serialize");
        let de: Test = from_retroshare_wire_result(&mut ser).expect("failed to deserialize");
        assert_eq!(de, foo);
    }
}
