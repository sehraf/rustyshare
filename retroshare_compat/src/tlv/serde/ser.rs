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
use serde::ser::{self, Serialize};

pub struct Serializer {
    output: Vec<u8>,
    tag: u16,
}

// By convention, the public API of a Serde serializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
pub fn to_tlv<T>(value: &T, tag: u16) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut serializer = Serializer {
        output: Vec::new(),
        tag,
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

impl<'a> ser::Serializer for &'a mut Serializer {
    // The output type produced by this `Serializer` during successful
    // serialization. Most serializers that produce text or binary output should
    // set `Ok = ()` and serialize into an `io::Write` or buffer contained
    // within the `Serializer` instance, as happens here. Serializers that build
    // in-memory data structures may be simplified by using `Ok` to propagate
    // the data structure around.
    type Ok = ();

    // The error type when some error occurs during serialization.
    type Error = Error;

    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // Serializer struct.
    type SerializeSeq = TlvSerializer<'a>;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = TlvSerializer<'a>;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _v: bool) -> Result<()> {
        unimplemented!("bool");
    }

    // signed numbers
    fn serialize_i8(self, _v: i8) -> Result<()> {
        unimplemented!("i8");
    }

    fn serialize_i16(self, _v: i16) -> Result<()> {
        unimplemented!("i16");
    }

    fn serialize_i32(self, _v: i32) -> Result<()> {
        unimplemented!("i32");
    }

    fn serialize_i64(self, _v: i64) -> Result<()> {
        unimplemented!("i64");
    }

    // unsigned numbers
    fn serialize_u8(self, _v: u8) -> Result<()> {
        unimplemented!("u8");
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        const SIZE: usize = 2;
        let mut buf: [u8; SIZE] = [0; SIZE];
        NetworkEndian::write_u16(&mut buf, v);
        self.output.extend_from_slice(&buf);
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        const SIZE: usize = 4;
        let mut buf: [u8; SIZE] = [0; SIZE];
        NetworkEndian::write_u32(&mut buf, v);
        self.output.extend_from_slice(&buf);
        Ok(())
    }

    fn serialize_u64(self, _v: u64) -> Result<()> {
        unimplemented!("u64");
    }

    // floating point numbers
    fn serialize_f32(self, _v: f32) -> Result<()> {
        unimplemented!("f32");
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        unimplemented!("u64");
    }

    // char
    fn serialize_char(self, _v: char) -> Result<()> {
        unimplemented!("char");
    }

    // This only works for strings that don't require escape sequences but you
    // get the idea. For example it would emit invalid JSON if the input string
    // contains a '"' character.
    fn serialize_str(self, v: &str) -> Result<()> {
        self.serialize_u16(self.tag)?;
        self.serialize_u32((v.len() + TLV_HEADER_SIZE) as u32)?;
        self.output.extend_from_slice(v.as_bytes());
        Ok(())
    }

    // Serialize a byte array as an array of bytes. Could also use a base64
    // string here. Binary formats will typically represent byte arrays more
    // compactly.
    fn serialize_bytes(self, _v: &[u8]) -> Result<()> {
        // use serde::ser::SerializeSeq;
        // let mut seq = self.serialize_seq(Some(v.len()))?;
        // for byte in v {
        //     seq.serialize_element(byte)?;
        // }
        // seq.end()
        Err(Error::Message(String::from(
            "byte is not implemented/serializable",
        )))
    }

    // An absent optional is represented as the JSON `null`.
    fn serialize_none(self) -> Result<()> {
        // self.serialize_unit()
        Err(Error::Message(String::from(
            "none is not implemented/serializable",
        )))
    }

    // A present optional is represented as just the contained value. Note that
    // this is a lossy representation. For example the values `Some(())` and
    // `None` both serialize as just `null`. Unfortunately this is typically
    // what people expect when working with JSON. Other formats are encouraged
    // to behave more intelligently if possible.
    fn serialize_some<T>(self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // value.serialize(self)
        Err(Error::Message(String::from(
            "some is not implemented/serializable",
        )))
    }

    // In Serde, unit means an anonymous value containing no data. Map this to
    // JSON as `null`.
    fn serialize_unit(self) -> Result<()> {
        // self.output += "null";
        // Ok(())
        Err(Error::Message(String::from(
            "unit is not implemented/serializable",
        )))
    }

    // Unit struct means a named value containing no data. Again, since there is
    // no data, map this to JSON as `null`. There is no need to serialize the
    // name in most formats.
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        // self.serialize_unit()
        Err(Error::Message(String::from(
            "unit struct is not implemented/serializable",
        )))
    }

    // When serializing a unit variant (or any other kind of variant), formats
    // can choose whether to keep track of it by index or by name. Binary
    // formats typically use the index of the variant and human-readable formats
    // typically use the name.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<()> {
        // self.serialize_str(variant)
        Err(Error::Message(String::from(
            "unit variant is not implemented/serializable",
        )))
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain.
    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // Note that newtype variant (and all of the other variant serialization
    // methods) refer exclusively to the "externally tagged" enum
    // representation.
    //
    // Serialize this to JSON in externally tagged form as `{ NAME: VALUE }`.
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // self.output += "{";
        // variant.serialize(&mut *self)?;
        // self.output += ":";
        // value.serialize(&mut *self)?;
        // self.output += "}";
        // Ok(())
        Err(Error::Message(String::from(
            "newtype vartiant is not implemented/serializable",
        )))
    }

    // Now we get to the serialization of compound types.
    //
    // The start of the sequence, each value, and the end are three separate
    // method calls. This one is responsible only for serializing the start,
    // which in JSON is `[`.
    //
    // The length of the sequence may or may not be known ahead of time. This
    // doesn't make a difference in JSON because the length is not represented
    // explicitly in the serialized form. Some serializers may only be able to
    // support sequences for which the length is known up front.
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        Ok(TlvSerializer {
            items: vec![],
            tag: self.tag,
            output: &mut self.output,
        })
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently by omitting the length, since tuple
    // means that the corresponding `Deserialize implementation will know the
    // length without needing to look at the serialized data.
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        // self.serialize_seq(Some(len))
        // self.serialize_u32(len as u32)?;
        Ok(self)
    }

    // Tuple structs look just like sequences in JSON.
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        // self.serialize_seq(Some(len))
        Err(Error::Message(String::from(
            "tuple struct is not implemented/serializable",
        )))
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }`. Again
    // this method is only responsible for the externally tagged representation.
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        // self.output += "{";
        // variant.serialize(&mut *self)?;
        // self.output += ":[";
        // Ok(self)
        Err(Error::Message(String::from(
            "tuple variant is not implemented/serializable",
        )))
    }

    // Maps are represented in JSON as `{ K: V, K: V, ... }`.
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        // self.output += "{";
        // Ok(self)
        // let len = len.ok_or(Error::UnknownSize)? as u32;
        // self.serialize_u32(len as u32)?;
        // Ok(self)
        unimplemented!();
    }

    // Structs look just like maps in JSON. In particular, JSON requires that we
    // serialize the field names of the struct. Other formats may be able to
    // omit the field names when serializing structs because the corresponding
    // Deserialize implementation is required to know what the keys are without
    // looking at the serialized data.
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Ok(TlvSerializer {
            items: vec![],
            tag: self.tag,
            output: &mut self.output,
        })
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }`.
    // This is the externally tagged representation.
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        // self.output += "{";
        // variant.serialize(&mut *self)?;
        // self.output += ":{";
        // Ok(self)
        Err(Error::Message(String::from(
            "struct variant is not implemented/serializable",
        )))
    }
}

pub struct TlvSerializer<'a> {
    /// Temporary storage for individual serialized array elements.
    items: Vec<Vec<u8>>,
    tag: u16,

    /// Storage for final serialized output of header plus all elements. This is
    /// typically a reference to the full output buffer being serialized into.
    output: &'a mut Vec<u8>,
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl<'a> ser::SerializeSeq for TlvSerializer<'a> {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        let mut serializer = crate::serde::Serializer { output: vec![] };
        value.serialize(&mut serializer)?;
        self.items.push(serializer.output);
        Ok(())
    }

    // Close the sequence.
    fn end(self) -> Result<Self::Ok> {
        if self.items.is_empty() {
            panic!("this should not happen!");
        }

        let mut payload: Vec<u8> = self.items.into_iter().flatten().collect();

        let mut tlv = [0u8; 6];
        NetworkEndian::write_u16(&mut tlv, self.tag); // tag
        NetworkEndian::write_u32(&mut tlv[2..], (payload.len() + TLV_HEADER_SIZE) as u32); // tag
        self.output.extend_from_slice(&tlv);
        self.output.append(&mut payload);
        Ok(())
    }
}

// Same thing but for tuples.
impl<'a> ser::SerializeTuple for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // if !self.output.ends_with('[') {
        //     self.output += ",";
        // }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "]";
        // Ok(())
        unimplemented!();
    }
}

// Same thing but for tuple structs.
impl<'a> ser::SerializeTupleStruct for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // if !self.output.ends_with('[') {
        //     self.output += ",";
        // }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "]";
        // Ok(())
        unimplemented!();
    }
}

// Tuple variants are a little different. Refer back to the
// `serialize_tuple_variant` method above:
//
//    self.output += "{";
//    variant.serialize(&mut *self)?;
//    self.output += ":[";
//
// So the `end` method in this impl is responsible for closing both the `]` and
// the `}`.
impl<'a> ser::SerializeTupleVariant for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // if !self.output.ends_with('[') {
        //     self.output += ",";
        // }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "]}";
        // Ok(())
        unimplemented!();
    }
}

// Some `Serialize` types are not able to hold a key and value in memory at the
// same time so `SerializeMap` implementations are required to support
// `serialize_key` and `serialize_value` individually.
//
// There is a third optional method on the `SerializeMap` trait. The
// `serialize_entry` method allows serializers to optimize for the case where
// key and value are both available simultaneously. In JSON it doesn't make a
// difference so the default behavior for `serialize_entry` is fine.
impl<'a> ser::SerializeMap for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    // The Serde data model allows map keys to be any serializable type. JSON
    // only allows string keys so the implementation below will produce invalid
    // JSON if the key serializes as something other than a string.
    //
    // A real JSON serializer would need to validate that map keys are strings.
    // This can be done by using a different Serializer to serialize the key
    // (instead of `&mut **self`) and having that other serializer only
    // implement `serialize_str` and return an error on any other data type.
    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // if !self.output.ends_with('{') {
        //     self.output += ",";
        // }
        key.serialize(&mut **self)
    }

    // It doesn't make a difference whether the colon is printed at the end of
    // `serialize_key` or at the beginning of `serialize_value`. In this case
    // the code is a bit simpler having it here.
    fn serialize_value<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // self.output += ":";
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "}";
        // Ok(())
        unimplemented!();
    }
}

// Structs are like maps in which the keys are constrained to be compile-time
// constant strings.
impl<'a> ser::SerializeStruct for TlvSerializer<'a> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        let mut serializer = crate::serde::Serializer { output: vec![] };
        value.serialize(&mut serializer)?;
        self.items.push(serializer.output);

        Ok(())
    }

    fn end(self) -> Result<()> {
        // use crate::TLV_HEADER_SIZE;

        if self.items.is_empty() {
            panic!("this should not happen!");
        }

        let mut payload: Vec<u8> = self.items.into_iter().flatten().collect();

        let mut tlv = [0u8; 6];

        NetworkEndian::write_u16(&mut tlv, self.tag); // tag
        NetworkEndian::write_u32(&mut tlv[2..], (payload.len() + TLV_HEADER_SIZE) as u32); // tag
        self.output.extend_from_slice(&tlv);
        self.output.append(&mut payload);
        Ok(())
    }
}

// Similar to `SerializeTupleVariant`, here the `end` method is responsible for
// closing both of the curly braces opened by `serialize_struct_variant`.
impl<'a> ser::SerializeStructVariant for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // if !self.output.ends_with('{') {
        //     self.output += ",";
        // }
        key.serialize(&mut **self)?;
        // self.output += ":";
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "}}";
        // Ok(())
        unimplemented!();
    }
}

// 0000 00220000 00000003 00000007 74 68 69 73 20 69 73 00000001 61 00000004 74 65 73 74
// 1337 00000022 00000003 00000007 74 68 69 73 20 69 73 00000001 61 00000004 74 65 73 74

////////////////////////////////////////////////////////////////////////////////
