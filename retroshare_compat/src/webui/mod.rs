use std::time::Duration;

use serde::{de::Visitor, Deserialize, Deserializer, Serialize};

pub mod chat;
pub mod identity;

// Yay JavaScript and stuff...
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct XInt64<I> {
    xint64: I,
    xstr64: String,
}

impl From<i64> for XInt64<i64> {
    fn from(i: i64) -> Self {
        Self {
            xint64: i,
            xstr64: i.to_string(),
        }
    }
}

// In RS timestamps are i64
impl From<Duration> for XInt64<i64> {
    fn from(i: Duration) -> Self {
        let i = i.as_secs() as i64;
        Self {
            xint64: i,
            xstr64: i.to_string(),
        }
    }
}

impl From<u64> for XInt64<u64> {
    fn from(i: u64) -> Self {
        Self {
            xint64: i,
            xstr64: i.to_string(),
        }
    }
}

impl From<XInt64<i64>> for i64 {
    fn from(s: XInt64<i64>) -> Self {
        if s.xint64.to_string() != s.xstr64 {
            log::error!("XInt64 mismatch! {} vs {}", s.xint64, s.xstr64);
        }

        s.xint64
    }
}

impl From<XInt64<u64>> for u64 {
    fn from(s: XInt64<u64>) -> Self {
        if s.xint64.to_string() != s.xstr64 {
            log::error!("XInt64 mismatch! {} vs {}", s.xint64, s.xstr64);
        }

        s.xint64
    }
}

/// What is the problem?
///
/// The problem is that RS (de)serializes i64/u64 as special `{"xint64": <int>, "xstr64": <str>}` JSON values BUT is also compatible with just plain `<int>`.
/// This makes it hard to deserialize
///
/// Assumtion: This is only called on json data!
impl<'de> Deserialize<'de> for XInt64<i64> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OwnVisitor();

        impl<'de> Visitor<'de> for OwnVisitor {
            type Value = XInt64<i64>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a XInt64")
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.into())
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let v = v as i64;
                Ok(v.into())
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut int_val = None;
                let mut str_val = None;
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    match key.as_str() {
                        "xint64" => int_val = value.as_i64(),
                        "xstr64" => str_val = value.as_str().map(|opt| opt.to_string()),
                        _ => {
                            return Err(::serde::de::Error::custom(crate::serde::Error::Message(
                                "unexpected field".into(),
                            )))
                        }
                    }
                }

                if let (Some(xint64), Some(xstr64)) = (int_val, str_val) {
                    Ok(XInt64 { xint64, xstr64 })
                } else {
                    Err(::serde::de::Error::custom(crate::serde::Error::Message(
                        "missing field".into(),
                    )))
                }
            }
        }

        deserializer.deserialize_any(OwnVisitor())
    }
}
impl<'de> Deserialize<'de> for XInt64<u64> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OwnVisitor();

        impl<'de> Visitor<'de> for OwnVisitor {
            type Value = XInt64<u64>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a XInt64")
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.into())
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut int_val = None;
                let mut str_val = None;
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    match key.as_str() {
                        "xint64" => int_val = value.as_u64(),
                        "xstr64" => str_val = value.as_str().map(|opt| opt.to_string()),
                        _ => {
                            return Err(::serde::de::Error::custom(crate::serde::Error::Message(
                                "unexpected field".into(),
                            )))
                        }
                    }
                }

                if let (Some(xint64), Some(xstr64)) = (int_val, str_val) {
                    Ok(XInt64 { xint64, xstr64 })
                } else {
                    Err(::serde::de::Error::custom(crate::serde::Error::Message(
                        "missing field".into(),
                    )))
                }
            }
        }

        deserializer.deserialize_any(OwnVisitor())
    }
}

#[cfg(test)]
mod test_xint_64 {
    use super::XInt64;

    #[test]
    fn test_signed() {
        let orig = 42i64.into();
        let ser = serde_json::to_string(&orig).unwrap();
        let expected = "{\"xint64\":42,\"xstr64\":\"42\"}";

        assert_eq!(&ser, expected);

        let de: XInt64<i64> = serde_json::from_str(&ser).unwrap();

        assert_eq!(de, orig)
    }

    #[test]
    fn test_unsigned() {
        let orig = 42u64.into();
        let ser = serde_json::to_string(&orig).unwrap();
        let expected = "{\"xint64\":42,\"xstr64\":\"42\"}";

        assert_eq!(&ser, expected);

        let de: XInt64<u64> = serde_json::from_str(&ser).unwrap();

        assert_eq!(de, orig)
    }

    #[test]
    fn test_signed_short() {
        let orig = 42i64.into();
        let ser = "42";

        let de: XInt64<i64> = serde_json::from_str(&ser).unwrap();

        assert_eq!(de, orig)
    }

    #[test]
    fn test_unsigned_short() {
        let orig = 42u64.into();
        let ser = "42";

        let de: XInt64<u64> = serde_json::from_str(&ser).unwrap();

        assert_eq!(de, orig)
    }
}
