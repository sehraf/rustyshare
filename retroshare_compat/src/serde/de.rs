// Copyright 2018 Serde Developers
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::serde::error::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use serde::de::{
    self, Deserialize, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor,
};

pub struct RetroShareWireDeserializer<'de> {
    input: &'de mut Vec<u8>,
}

impl<'de> RetroShareWireDeserializer<'de> {
    pub fn from_retroshare_wire(input: &'de mut Vec<u8>) -> Self {
        RetroShareWireDeserializer { input }
    }
}

pub fn from_retroshare_wire_result<'a, T>(s: &'a mut Vec<u8>) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut deserializer = RetroShareWireDeserializer::from_retroshare_wire(s);
    let t = T::deserialize(&mut deserializer)?;
    Ok(t)
}

pub fn from_retroshare_wire<'a, T>(s: &'a mut Vec<u8>) -> T
where
    T: Deserialize<'a>,
{
    from_retroshare_wire_result(s).expect("failed to deserialize")
}

impl<'de> RetroShareWireDeserializer<'de> {
    fn read_len(&mut self) -> Result<usize> {
        // len is always a u32
        const SIZE: usize = 4;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let r = NetworkEndian::read_u32(d.as_slice());
        Ok(r as usize)
    }
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut RetroShareWireDeserializer<'de> {
    type Error = Error;

    // Look at the input data to decide what Serde data model type to
    // deserialize as. Not all data formats are able to support this operation.
    // Formats that support `deserialize_any` are known as self-describing.
    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Message(String::from(
            "any is not implemented/serializable",
        )))
    }

    fn deserialize_bool<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // visitor.visit_bool(self.parse_bool()?)
        Err(Error::Message(String::from(
            "bool is not implemented/deserializable",
        )))
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        const SIZE: usize = 1;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        visitor.visit_i8(d[0] as i8)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        const SIZE: usize = 2;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let r = NetworkEndian::read_i16(d.as_slice());
        visitor.visit_i16(r)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        const SIZE: usize = 4;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let r = NetworkEndian::read_i32(d.as_slice());
        visitor.visit_i32(r)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        const SIZE: usize = 8;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let r = NetworkEndian::read_i64(d.as_slice());
        visitor.visit_i64(r)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        const SIZE: usize = 1;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        visitor.visit_u8(d[0])
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        const SIZE: usize = 2;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let r = NetworkEndian::read_u16(d.as_slice());
        visitor.visit_u16(r)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        const SIZE: usize = 4;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let r = NetworkEndian::read_u32(d.as_slice());
        visitor.visit_u32(r)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        const SIZE: usize = 8;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let r = NetworkEndian::read_u64(d.as_slice());
        visitor.visit_u64(r)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // from RetroShare
        // f = 1.0f/ ( n/(float)(~(uint32_t)0)) - 1.0f ;
        const SIZE: usize = 4;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let n = NetworkEndian::read_u32(d.as_slice()); // can this be done with deserialize_u32?!
        let f: f32 = 1 as f32 / (n as f32 / (!(0 as u32) as f32)) - 1 as f32;
        visitor.visit_f32(f)
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Message(String::from(
            "f64 is not implemented/deserializable",
        )))
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Message(String::from(
            "char is not implemented/deserializable",
        )))
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let str_len = self.read_len()?;
        assert!(
            str_len <= self.input.len(),
            "String lenght {} is longer than input data {}!",
            str_len,
            self.input.len()
        );
        let d: Vec<u8> = self.input.drain(0..str_len).collect();
        let s = String::from_utf8(d).unwrap();
        visitor.visit_string(s)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // assume TLV!!
        let len = NetworkEndian::read_u32(&self.input[2..6]) as usize; // skip len!
        let bytes: Vec<u8> = self.input.drain(0..len).collect();
        visitor.visit_bytes(&bytes)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // assume TLV!!
        let len = NetworkEndian::read_u32(&self.input[2..6]) as usize; // skip len!
        let bytes: Vec<u8> = self.input.drain(0..len).collect();
        visitor.visit_bytes(&bytes)
    }

    fn deserialize_option<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // In Serde, unit means an anonymous value containing no data.
    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // Unit struct means a named value containing no data.
    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // self.deserialize_unit(visitor)
        unimplemented!()
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain. That means not
    // parsing anything other than the contained value.
    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
        // unimplemented!()
    }

    // Deserialization of compound types like sequences and maps happens by
    // passing the visitor an "Access" object that gives it the ability to
    // iterate through the data contained in the sequence.
    fn deserialize_seq<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let len = self.read_len()?;
        let value = visitor.visit_seq(CountReader::new(&mut self, len))?;
        Ok(value)
    }

    fn deserialize_tuple<V>(mut self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let value = visitor.visit_seq(DumpReader::new(&mut self))?;
        Ok(value)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // Much like `deserialize_seq` but calls the visitors `visit_map` method
    // with a `MapAccess` implementation, rather than the visitor's `visit_seq`
    // method with a `SeqAccess` implementation.
    fn deserialize_map<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let len = self.read_len()?;
        let value = visitor.visit_map(CountReader::new(&mut self, len))?;
        Ok(value)
    }

    fn deserialize_struct<V>(
        mut self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let value = visitor.visit_seq(DumpReader::new(&mut self))?;
        Ok(value)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // An identifier in Serde is the type that identifies a field of a struct or
    // the variant of an enum. In JSON, struct fields and enum variants are
    // represented as strings. In other formats they may be represented as
    // numeric indices.
    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // self.deserialize_str(visitor)
        unimplemented!()
    }

    // Like `deserialize_any` but indicates to the `Deserializer` that it makes
    // no difference which `Visitor` method is called because the data is
    // ignored.
    //
    // Some deserializers are able to implement this more efficiently than
    // `deserialize_any`, for example by rapidly skipping over matched
    // delimiters without paying close attention to the data in between.
    //
    // Some formats are not able to implement this at all. Formats that can
    // implement `deserialize_any` and `deserialize_ignored_any` are known as
    // self-describing.
    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
}

////////////////////////////////////////////////////////////////////////////////

// In order to handle commas correctly when deserializing a JSON array or map,
// we need to track whether we are on the first element or past the first
// element.

/// Dump reader that simply reads element after element with no size checks
struct DumpReader<'a, 'de: 'a> {
    de: &'a mut RetroShareWireDeserializer<'de>,
}

impl<'a, 'de> DumpReader<'a, 'de> {
    fn new(de: &'a mut RetroShareWireDeserializer<'de>) -> Self {
        DumpReader { de }
    }
}

impl<'de, 'a> SeqAccess<'de> for DumpReader<'a, 'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(&mut *self.de).map(Some)
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Count based reader that reads a fixed length
struct CountReader<'a, 'de: 'a> {
    de: &'a mut RetroShareWireDeserializer<'de>,
    left: usize,
}

impl<'a, 'de> CountReader<'a, 'de> {
    fn new(de: &'a mut RetroShareWireDeserializer<'de>, left: usize) -> Self {
        CountReader { de, left }
    }

    fn can_read(&mut self) -> bool {
        if self.left == 0 {
            return false;
        } else {
            self.left -= 1;
            return true;
        }
    }
}

// `SeqAccess` is provided to the `Visitor` to give it the ability to iterate
// through elements of the sequence.
impl<'de, 'a> SeqAccess<'de> for CountReader<'a, 'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        if !self.can_read() {
            return Ok(None);
        }
        seed.deserialize(&mut *self.de).map(Some)
    }
}

// `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// through entries of the map.
impl<'de, 'a> MapAccess<'de> for CountReader<'a, 'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        if !self.can_read() {
            return Ok(None);
        }
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        assert!(self.de.input.len() > 0, "no space left for key element");
        seed.deserialize(&mut *self.de)
    }
}

////////////////////////////////////////////////////////////////////////////////

pub struct LengthReader<'a, 'de: 'a> {
    de: &'a mut RetroShareWireDeserializer<'de>,
    len_start: usize,
    len_to_read: usize,
}

impl<'a, 'de> LengthReader<'a, 'de> {
    pub fn new(de: &'a mut RetroShareWireDeserializer<'de>, len_to_read: usize) -> Self {
        let len = de.input.len();
        LengthReader {
            de,
            len_start: len,
            len_to_read,
        }
    }

    fn can_read(&self) -> bool {
        let read = self.len_start - self.de.input.len();
        self.len_to_read > read
    }
}

// `SeqAccess` is provided to the `Visitor` to give it the ability to iterate
// through elements of the sequence.
impl<'de, 'a> SeqAccess<'de> for LengthReader<'a, 'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        if !self.can_read() {
            return Ok(None);
        }
        seed.deserialize(&mut *self.de).map(Some)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[allow(dead_code)]
struct Enum<'a, 'de: 'a> {
    de: &'a mut RetroShareWireDeserializer<'de>,
}

impl<'a, 'de> Enum<'a, 'de> {
    #[allow(dead_code)]
    fn new(de: &'a mut RetroShareWireDeserializer<'de>) -> Self {
        Enum { de }
    }
}

// `EnumAccess` is provided to the `Visitor` to give it the ability to determine
// which variant of the enum is supposed to be deserialized.
//
// Note that all enum deserialization methods in Serde refer exclusively to the
// "externally tagged" enum representation.
impl<'de, 'a> EnumAccess<'de> for Enum<'a, 'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V>(self, _seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
        // // The `deserialize_enum` method parsed a `{` character so we are
        // // currently inside of a map. The seed will be deserializing itself from
        // // the key of the map.
        // let val = seed.deserialize(&mut *self.de)?;
        // // Parse the colon separating map key from value.
        // if self.de.next_char()? == ':' {
        //     Ok((val, self))
        // } else {
        //     Err(Error::ExpectedMapColon)
        // }
        unimplemented!()
    }
}

// `VariantAccess` is provided to the `Visitor` to give it the ability to see
// the content of the single variant that it decided to deserialize.
impl<'de, 'a> VariantAccess<'de> for Enum<'a, 'de> {
    type Error = Error;

    // If the `Visitor` expected this variant to be a unit variant, the input
    // should have been the plain string case handled in `deserialize_enum`.
    fn unit_variant(self) -> Result<()> {
        // Err(Error::ExpectedString)
        unimplemented!()
    }

    // Newtype variants are represented in JSON as `{ NAME: VALUE }` so
    // deserialize the value here.
    fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        // seed.deserialize(self.de)
        unimplemented!()
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }` so
    // deserialize the sequence of data here.
    fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // de::Deserializer::deserialize_seq(self.de, visitor)
        unimplemented!()
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }` so
    // deserialize the inner map here.
    fn struct_variant<V>(self, _fields: &'static [&'static str], _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // de::Deserializer::deserialize_map(self.de, visitor)
        unimplemented!()
    }
}

////////////////////////////////////////////////////////////////////////////////
