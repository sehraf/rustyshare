use std::fmt::{self, Display};

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::{read_u16, read_u32, write_u16, write_u32};

use super::TLV_HEADER_SIZE;

// manually implement StringTagged to be able to add some more traits

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct StringTagged<const TAG: u16>(String);

impl<const TAG: u16, T> From<T> for StringTagged<TAG>
where
    T: AsRef<str>,
{
    fn from(s: T) -> Self {
        Self(String::from(s.as_ref()))
    }
}

impl<const TAG: u16> From<StringTagged<TAG>> for String {
    fn from(s: StringTagged<TAG>) -> Self {
        s.0
    }
}

impl<const TAG: u16> Display for StringTagged<TAG> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<const TAG: u16> Serialize for StringTagged<TAG> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser = vec![];
        write_u16(&mut ser, TAG);
        write_u32(&mut ser, (self.0.len() + TLV_HEADER_SIZE) as u32);
        ser.extend_from_slice(self.0.as_bytes());

        serializer.serialize_bytes(ser.as_slice())
    }
}

impl<'de, const TAG: u16> Deserialize<'de> for StringTagged<TAG> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TaggedStringVisitor<const TAG: u16>();

        impl<'de, const TAG: u16> Visitor<'de> for TaggedStringVisitor<TAG> {
            type Value = StringTagged<TAG>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a tagged string")
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
                let s = String::from_utf8_lossy(&v[6..len]).to_string();

                Ok(StringTagged(s))
            }
        }

        deserializer.deserialize_bytes(TaggedStringVisitor())
    }
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};

    use crate::{
        serde::{from_retroshare_wire, to_retroshare_wire},
        tlv::Tlv2,
    };

    use super::StringTagged;

    #[test]
    fn string_tagged_struct() {
        #[derive(Debug, Serialize, Deserialize)]
        struct Dummy {
            a: u16,
            // #[serde(with = "crate::tlv::string")]
            tagged_string: StringTagged<0x1337>,
            z: u16,
        }

        let test = Dummy {
            a: 0xAAAA,
            tagged_string: "test123".into(),
            z: 0xBBBB,
        };

        let mut ser = to_retroshare_wire(&test).expect("failed to serialize");

        let expected = vec![
            0xAA, 0xAA, // a
            0x13, 0x37, // tag
            0x00, 0x00, 0x00, 0x0d, // len
            0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, // val
            0xBB, 0xBB, // z
        ];
        assert_eq!(&ser, &expected);

        let de: Dummy = from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(&de.tagged_string.0, &test.tagged_string.0);
    }

    #[test]
    fn string_tagged() {
        let tagged_string: StringTagged<0x1337> = "test123".into();
        let mut ser = to_retroshare_wire(&tagged_string).expect("failed to serialize");

        let expected = vec![
            0x13, 0x37, // tag
            0x00, 0x00, 0x00, 0x0d, // len
            0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, // val
        ];

        assert_eq!(&ser, &expected);

        let de: StringTagged<0x1337> =
            from_retroshare_wire(&mut ser).expect("failed to deserialize");
        assert_eq!(&de.0, &tagged_string.0);
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
