use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

mod de;
mod error;
mod ser;

pub use de::{
    from_retroshare_wire, from_retroshare_wire_result, LengthReader, RetroShareWireDeserializer,
};
pub use error::{Error, Result};
pub use ser::{to_retroshare_wire, to_retroshare_wire_result, RetroShareWireSerializer};

#[derive(Debug, Clone)]
pub struct Toggleable<T> {
    inner: T,
    on: bool,
}

impl<T> Toggleable<T> {
    pub fn new(t: T) -> Self {
        Self { inner: t, on: true }
    }

    pub fn turn_on(&mut self) {
        self.on = true
    }

    pub fn turn_off(&mut self) {
        self.on = false
    }
}

impl<T> Default for Toggleable<T>
where
    T: Default,
{
    fn default() -> Self {
        Self {
            inner: T::default(),
            on: true,
        }
    }
}

impl<T> Deref for Toggleable<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Toggleable<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> Serialize for Toggleable<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.on {
            let bytes = to_retroshare_wire_result(&self.inner).expect("failed to serialize");
            serializer.serialize_bytes(bytes.as_slice())
        } else {
            serializer.serialize_bytes(&[])
        }
    }
}

impl<'de, T> Deserialize<'de> for Toggleable<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct InnerVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for InnerVisitor<T>
        where
            T: DeserializeOwned,
        {
            type Value = Toggleable<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "Toggleable")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut bytes = v.into();
                let s: T = from_retroshare_wire_result(&mut bytes).expect("failed to deserialize");

                Ok(Toggleable { inner: s, on: true })
            }
        }

        deserializer.deserialize_byte_buf(InnerVisitor(PhantomData))
    }
}
