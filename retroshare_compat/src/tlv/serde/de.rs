// Copyright 2018 Serde Developers
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::tlv::{
    serde::error::{Error, Result},
    TLV_HEADER_SIZE,
};
use byteorder::{ByteOrder, NetworkEndian};
use serde::de::{
    self, Deserialize, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor,
};
// use std::ops::{AddAssign, MulAssign, Neg};

pub struct Deserializer<'de> {
    input: &'de mut Vec<u8>,
    tag: u16,
}

impl<'de> Deserializer<'de> {
    // By convention, `Deserializer` constructors are named like `from_xyz`.
    // That way basic use cases are satisfied by something like
    // `serde_json::from_str(...)` while advanced use cases that require a
    // deserializer can make one with `serde_json::Deserializer::from_str(...)`.
    pub fn from_tlv(input: &'de mut Vec<u8>, tag: u16) -> Self {
        Deserializer { input, tag }
    }
}

// By convention, the public API of a Serde deserializer is one or more
// `from_xyz` methods such as `from_str`, `from_bytes`, or `from_reader`
// depending on what Rust types the deserializer is able to consume as input.
//
// This basic deserializer supports only `from_str`.
pub fn from_tlv<'a, T>(s: &'a mut Vec<u8>, tag: u16) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut deserializer = Deserializer::from_tlv(s, tag);
    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.is_empty() {
        Ok(t)
    } else {
        Err(Error::TrailingBytes)
    }
}

// SERDE IS NOT A PARSING LIBRARY. This impl block defines a few basic parsing
// functions from scratch. More complicated formats may wish to use a dedicated
// parsing library to help implement their Serde deserializer.
impl<'de> Deserializer<'de> {
    // // Look at the first character in the input without consuming it.
    // fn peek_char(&mut self) -> Result<char> {
    //     self.input.chars().next().ok_or(Error::Eof)
    // }

    // // Consume the first character in the input.
    // fn next_char(&mut self) -> Result<char> {
    //     let ch = self.peek_char()?;
    //     self.input = &self.input[ch.len_utf8()..];
    //     Ok(ch)
    // }

    // // Parse the JSON identifier `true` or `false`.
    // fn parse_bool(&mut self) -> Result<bool> {
    //     if self.input.starts_with("true") {
    //         self.input = &self.input["true".len()..];
    //         Ok(true)
    //     } else if self.input.starts_with("false") {
    //         self.input = &self.input["false".len()..];
    //         Ok(false)
    //     } else {
    //         Err(Error::ExpectedBoolean)
    //     }
    // }

    // Parse a group of decimal digits as an unsigned integer of type T.
    //
    // This implementation is a bit too lenient, for example `001` is not
    // allowed in JSON. Also the various arithmetic operations can overflow and
    // panic or return bogus data. But it is good enough for example code!
    // fn parse_unsigned<T>(&mut self) -> Result<T>
    // where
    //     T: AddAssign<T> + MulAssign<T> + From<u8>,
    // {
    //     let mut int = match self.next_char()? {
    //         ch @ '0'..='9' => T::from(ch as u8 - b'0'),
    //         _ => {
    //             return Err(Error::ExpectedInteger);
    //         }
    //     };
    //     loop {
    //         match self.input.chars().next() {
    //             Some(ch @ '0'..='9') => {
    //                 self.input = &self.input[1..];
    //                 int *= T::from(10);
    //                 int += T::from(ch as u8 - b'0');
    //             }
    //             _ => {
    //                 return Ok(int);
    //             }
    //         }
    //     }
    // }

    // Parse a possible minus sign followed by a group of decimal digits as a
    // signed integer of type T.
    // fn parse_signed<T>(&mut self) -> Result<T>
    // where
    //     T: Neg<Output = T> + AddAssign<T> + MulAssign<T> + From<i8>,
    // {
    //     // Optional minus sign, delegate to `parse_unsigned`, negate if negative.
    //     unimplemented!()
    // }

    // Parse a string until the next '"' character.
    //
    // Makes no attempt to handle escape sequences. What did you expect? This is
    // example code!
    // fn parse_string(&mut self) -> Result<&'de str> {
    //     if self.next_char()? != '"' {
    //         return Err(Error::ExpectedString);
    //     }
    //     match self.input.find('"') {
    //         Some(len) => {
    //             let s = &self.input[..len];
    //             self.input = &self.input[len + 1..];
    //             Ok(s)
    //         }
    //         None => Err(Error::Eof),
    //     }
    // }

    fn read_tag(&mut self) -> Result<u16> {
        // len is always a u32
        const SIZE: usize = 2;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let r = NetworkEndian::read_u16(d.as_slice());
        Ok(r)
    }

    fn read_len(&mut self) -> Result<usize> {
        // len is always a u32
        const SIZE: usize = 4;
        let d: Vec<u8> = self.input.drain(0..SIZE).collect();
        let r = NetworkEndian::read_u32(d.as_slice());
        Ok(r as usize)
    }
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = Error;

    // Look at the input data to decide what Serde data model type to
    // deserialize as. Not all data formats are able to support this operation.
    // Formats that support `deserialize_any` are known as self-describing.
    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        //     match self.peek_char()? {
        //         'n' => self.deserialize_unit(visitor),
        //         't' | 'f' => self.deserialize_bool(visitor),
        //         '"' => self.deserialize_str(visitor),
        //         '0'..='9' => self.deserialize_u64(visitor),
        //         '-' => self.deserialize_i64(visitor),
        //         '[' => self.deserialize_seq(visitor),
        //         '{' => self.deserialize_map(visitor),
        //         _ => Err(Error::Syntax),
        //     }
        Err(Error::Message(String::from(
            "any is not implemented/serializable",
        )))
    }

    // Uses the `parse_bool` parsing function defined above to read the JSON
    // identifier `true` or `false` from the input.
    //
    // Parsing refers to looking at the input and deciding that it contains the
    // JSON value `true` or `false`.
    //
    // Deserialization refers to mapping that JSON value into Serde's data
    // model by invoking one of the `Visitor` methods. In the case of JSON and
    // bool that mapping is straightforward so the distinction may seem silly,
    // but in other cases Deserializers sometimes perform non-obvious mappings.
    // For example the TOML format has a Datetime type and Serde's data model
    // does not. In the `toml` crate, a Datetime in the input is deserialized by
    // mapping it to a Serde data model "struct" type with a special name and a
    // single field containing the Datetime represented as a string.
    fn deserialize_bool<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // visitor.visit_bool(self.parse_bool()?)
        Err(Error::Message(String::from(
            "bool is not implemented/deserializable",
        )))
    }

    // The `parse_signed` function is generic over the integer type `T` so here
    // it is invoked with `T=i8`. The next 8 methods are similar.
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

    // Float parsing is stupidly hard.
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

    // Float parsing is stupidly hard.
    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Message(String::from(
            "f64 is not implemented/deserializable",
        )))
    }

    // The `Serializer` implementation on the previous page serialized chars as
    // single-character strings so handle that representation here.
    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // Parse a string, check that it is one character, call `visit_char`.
        Err(Error::Message(String::from(
            "char is not implemented/deserializable",
        )))
    }

    // Refer to the "Understanding deserializer lifetimes" page for information
    // about the three deserialization flavors of strings in Serde.
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // read tag
        let tag = self.read_tag()?;
        assert_eq!(tag, self.tag, "tag missmatch {} vs {}", tag, self.tag);

        // read len
        let len = self.read_len()?;

        // calculate actual string len
        let str_len = len - TLV_HEADER_SIZE;
        assert!(
            str_len <= self.input.len(),
            "String (tag: {:02x?}) lenght {} is longer than input data {}!",
            tag,
            str_len,
            self.input.len()
        );

        // read string
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

    // The `Serializer` implementation on the previous page serialized byte
    // arrays as JSON arrays of bytes. Handle that representation here.
    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    // An absent optional is represented as the JSON `null` and a present
    // optional is represented as just the contained value.
    //
    // As commented in `Serializer` implementation, this is a lossy
    // representation. For example the values `Some(())` and `None` both
    // serialize as just `null`. Unfortunately this is typically what people
    // expect when working with JSON. Other formats are encouraged to behave
    // more intelligently if possible.
    fn deserialize_option<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // if self.input.starts_with("null") {
        //     self.input = &self.input["null".len()..];
        //     visitor.visit_none()
        // } else {
        //     visitor.visit_some(self)
        // }
        unimplemented!()
    }

    // In Serde, unit means an anonymous value containing no data.
    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // if self.input.starts_with("null") {
        //     self.input = &self.input["null".len()..];
        //     visitor.visit_unit()
        // } else {
        //     Err(Error::ExpectedNull)
        // }
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
        // read tag
        let tag = self.read_tag()?;
        assert_eq!(tag, self.tag, "tag missmatch {} vs {}", tag, self.tag);

        // read len
        let len = self.read_len()?;

        // calculate actual payload len
        let payload_len = len - TLV_HEADER_SIZE;

        let value = visitor.visit_seq(BytesReader::new(&mut self, payload_len))?;
        Ok(value)
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently.
    //
    // As indicated by the length parameter, the `Deserialize` implementation
    // for a tuple in the Serde data model is required to know the length of the
    // tuple before even looking at the input data.
    fn deserialize_tuple<V>(mut self, len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // self.deserialize_seq(visitor)
        // let _len = self.read_len()?;
        // let value = visitor.visit_seq(DumpReader::new(&mut self))?;
        // Ok(value)
        // unimplemented!();
        let value = visitor.visit_seq(BytesReader::new(&mut self, len))?;
        Ok(value)
    }

    // Tuple structs look just like sequences in JSON.
    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // self.deserialize_seq(visitor)
        unimplemented!()
    }

    // Much like `deserialize_seq` but calls the visitors `visit_map` method
    // with a `MapAccess` implementation, rather than the visitor's `visit_seq`
    // method with a `SeqAccess` implementation.
    fn deserialize_map<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // // Parse the opening brace of the map.
        // if self.next_char()? == '{' {
        //     // Give the visitor access to each entry of the map.
        //     let value = visitor.visit_map(CommaSeparated::new(&mut self))?;
        //     // Parse the closing brace of the map.
        //     if self.next_char()? == '}' {
        //         Ok(value)
        //     } else {
        //         Err(Error::ExpectedMapEnd)
        //     }
        // } else {
        //     Err(Error::ExpectedMap)
        // }
        let tag = self.read_tag()?;
        assert_eq!(tag, self.tag);

        // read len
        let len = self.read_len()?;

        // calculate actual payload len
        let payload_len = len - TLV_HEADER_SIZE;

        let value = visitor.visit_seq(BytesReader::new(&mut self, payload_len))?;
        Ok(value)
    }

    // Structs look just like maps in JSON.
    //
    // Notice the `fields` parameter - a "struct" in the Serde data model means
    // that the `Deserialize` implementation is required to know what the fields
    // are before even looking at the input data. Any key-value pairing in which
    // the fields cannot be known ahead of time is probably a map.
    fn deserialize_struct<V>(
        mut self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let _tag = self.read_tag()?;
        // assert_eq!(tag, self.tag, "tag missmatch {} vs {}", tag, self.tag);

        // read len
        let len = self.read_len()?;

        // calculate actual payload len
        let payload_len = len - TLV_HEADER_SIZE;

        let value = visitor.visit_seq(BytesReader::new(&mut self, payload_len))?;

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
        // self.deserialize_any(visitor)
        unimplemented!()
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Reads a fixed number of bytes
pub struct BytesReader<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
    len_start: usize,
    len_to_read: usize,
}

impl<'a, 'de> BytesReader<'a, 'de> {
    pub fn new(de: &'a mut Deserializer<'de>, len_to_read: usize) -> Self {
        let len = de.input.len();
        BytesReader {
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
impl<'de, 'a> SeqAccess<'de> for BytesReader<'a, 'de> {
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

impl<'de, 'a> MapAccess<'de> for BytesReader<'a, 'de> {
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

struct Enum<'a, 'de: 'a> {
    #[allow(dead_code)]
    de: &'a mut Deserializer<'de>,
}

impl<'a, 'de> Enum<'a, 'de> {
    #[allow(dead_code)]
    fn new(de: &'a mut Deserializer<'de>) -> Self {
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
