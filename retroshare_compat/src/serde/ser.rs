// Copyright 2018 Serde Developers
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::serde::error::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use serde::ser::{self, Serialize};

// use super::RetroShareTLV;

pub struct RetroShareWireSerializer {
    // This string starts empty and JSON is appended as values are serialized.
    pub output: Vec<u8>,
}

// By convention, the public API of a Serde serializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
pub fn to_retroshare_wire<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut serializer = RetroShareWireSerializer { output: Vec::new() };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

impl<'a> ser::Serializer for &'a mut RetroShareWireSerializer {
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
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _v: bool) -> Result<()> {
        // self.output += if v { "true" } else { "false" };
        // Ok(())
        Err(Error::Message(String::from(
            "bool is not implemented/serializable",
        )))
    }

    // signed numbers
    fn serialize_i8(self, v: i8) -> Result<()> {
        self.output.push(v as u8);
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        const SIZE: usize = 2;
        let mut buf: [u8; SIZE] = [0; SIZE];
        NetworkEndian::write_i16(&mut buf, v);
        self.output.extend_from_slice(&buf);
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        const SIZE: usize = 4;
        let mut buf: [u8; SIZE] = [0; SIZE];
        NetworkEndian::write_i32(&mut buf, v);
        self.output.extend_from_slice(&buf);
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> Result<()> {
        const SIZE: usize = 8;
        let mut buf: [u8; SIZE] = [0; SIZE];
        NetworkEndian::write_i64(&mut buf, v);
        self.output.extend_from_slice(&buf);
        Ok(())
    }

    // unsigned numbers
    fn serialize_u8(self, v: u8) -> Result<()> {
        self.output.push(v);
        Ok(())
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

    fn serialize_u64(self, v: u64) -> Result<()> {
        const SIZE: usize = 8;
        let mut buf: [u8; SIZE] = [0; SIZE];
        NetworkEndian::write_u64(&mut buf, v);
        self.output.extend_from_slice(&buf);
        Ok(())
    }

    // floating point numbers
    fn serialize_f32(self, v: f32) -> Result<()> {
        // from RetroShare
        // This serialisation is quite accurate. The max relative error is approx.
        // 0.01% and most of the time less than 1e-05% The error is well distributed
        // over numbers also.
        // uint32_t n = (f < 1e-7)?(~(uint32_t)0): ((uint32_t)( (1.0f/(1.0f+f) * (~(uint32_t)0)))) ;
        let n = if v < 1e-7 {
            !(0 as u32)
        } else {
            (1 as f32 / (1 as f32 + v) * (!(0 as u32)) as f32) as u32
        };

        self.serialize_u32(n)
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        Err(Error::Message(String::from(
            "f64 is not implemented/serializable",
        )))
    }

    // char
    fn serialize_char(self, _v: char) -> Result<()> {
        Err(Error::Message(String::from(
            "char is not implemented/serializable",
        )))
    }

    // This only works for strings that don't require escape sequences but you
    // get the idea. For example it would emit invalid JSON if the input string
    // contains a '"' character.
    fn serialize_str(self, v: &str) -> Result<()> {
        self.serialize_u32(v.len() as u32)?;
        self.output.extend_from_slice(v.as_bytes());
        Ok(())
    }

    // Serialize a byte array as an array of bytes. Could also use a base64
    // string here. Binary formats will typically represent byte arrays more
    // compactly.
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        // use serde::ser::SerializeSeq;
        // let mut seq = self.serialize_seq(Some(v.len()))?;
        // for byte in v {
        //     seq.serialize_element(byte)?;
        // }
        // seq.end()

        // Err(Error::Message(String::from(
        //     "byte is not implemented/serializable",
        // )))

        self.output.extend_from_slice(v);
        Ok(())
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
        // match name {
        //     "VsDisc" | "VsDht" => {
        //         return self.serialize_u16(variant_index as u16);
        //     }
        //     _ => {}
        // }

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
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        let len = len.ok_or(Error::UnknownSize)? as u32;
        self.serialize_u32(len)?;
        Ok(self)
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
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        // self.output += "{";
        // Ok(self)
        let len = len.ok_or(Error::UnknownSize)? as u32;
        self.serialize_u32(len as u32)?;
        Ok(self)
    }

    // Structs look just like maps in JSON. In particular, JSON requires that we
    // serialize the field names of the struct. Other formats may be able to
    // omit the field names when serializing structs because the corresponding
    // Deserialize implementation is required to know what the keys are without
    // looking at the serialized data.
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        // let len = len.ok_or(Error::UnknownSize)? as u32;
        // self.serialize_u32(len as u32)?;
        Ok(self)
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

// struct LengthWriter<'a> {
//     ser: &'a mut Serializer,
//     len: usize,
// }

// impl<'a> LengthWriter<'a> {
//     fn new(ser: &'a mut Serializer) -> Self {
//         let len = ser.output.len();
//         assert!(len >= 4);
//         LengthWriter { ser, len }
//     }
// }

// // This impl is SerializeSeq so these methods are called after `serialize_seq`
// // is called on the Serializer.
// impl<'a> ser::SerializeSeq for &'a mut LengthWriter<'a> {
//     // Must match the `Ok` type of the serializer.
//     type Ok = ();
//     // Must match the `Error` type of the serializer.
//     type Error = Error;

//     // Serialize a single element of the sequence.
//     fn serialize_element<T>(&mut self, value: &T) -> Result<()>
//     where
//         T: ?Sized + Serialize,
//     {
//         value.serialize(&mut *self.ser)
//     }

//     // Close the sequence.
//     fn end(self) -> Result<()> {
//         let wrote = self.ser.output.len() - self.len;
//         // update length
//         // let pos = self.ser.output.iter_mut().nth(self.len - 4).unwrap();
//         NetworkEndian::write_u32(&mut buf, v);

//         Ok(())
//     }
// }

// // Some `Serialize` types are not able to hold a key and value in memory at the
// // same time so `SerializeMap` implementations are required to support
// // `serialize_key` and `serialize_value` individually.
// //
// // There is a third optional method on the `SerializeMap` trait. The
// // `serialize_entry` method allows serializers to optimize for the case where
// // key and value are both available simultaneously. In JSON it doesn't make a
// // difference so the default behavior for `serialize_entry` is fine.
// impl<'a> ser::SerializeMap for &'a mut LengthWriter<'a> {
//     type Ok = ();
//     type Error = Error;

//     // The Serde data model allows map keys to be any serializable type. JSON
//     // only allows string keys so the implementation below will produce invalid
//     // JSON if the key serializes as something other than a string.
//     //
//     // A real JSON serializer would need to validate that map keys are strings.
//     // This can be done by using a different Serializer to serialize the key
//     // (instead of `&mut **self`) and having that other serializer only
//     // implement `serialize_str` and return an error on any other data type.
//     fn serialize_key<T>(&mut self, key: &T) -> Result<()>
//     where
//         T: ?Sized + Serialize,
//     {
//         // if !self.output.ends_with('{') {
//         //     self.output += ",";
//         // }
//         key.serialize(&mut *self.ser)
//     }

//     // It doesn't make a difference whether the colon is printed at the end of
//     // `serialize_key` or at the beginning of `serialize_value`. In this case
//     // the code is a bit simpler having it here.
//     fn serialize_value<T>(&mut self, value: &T) -> Result<()>
//     where
//         T: ?Sized + Serialize,
//     {
//         // self.output += ":";
//         value.serialize(&mut *self.ser)
//     }

//     fn end(self) -> Result<()> {
//         // self.output += "}";
//         Ok(())
//     }
// }

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl<'a> ser::SerializeSeq for &'a mut RetroShareWireSerializer {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // if !self.output.ends_with('[') {
        //     self.output += ",";
        // }
        value.serialize(&mut **self)
    }

    // Close the sequence.
    fn end(self) -> Result<()> {
        // self.output += "]";
        Ok(())
    }
}

// Same thing but for tuples.
impl<'a> ser::SerializeTuple for &'a mut RetroShareWireSerializer {
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
        Ok(())
    }
}

// Same thing but for tuple structs.
impl<'a> ser::SerializeTupleStruct for &'a mut RetroShareWireSerializer {
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
        Ok(())
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
impl<'a> ser::SerializeTupleVariant for &'a mut RetroShareWireSerializer {
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
        Ok(())
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
impl<'a> ser::SerializeMap for &'a mut RetroShareWireSerializer {
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
        Ok(())
    }
}

// Structs are like maps in which the keys are constrained to be compile-time
// constant strings.
impl<'a> ser::SerializeStruct for &'a mut RetroShareWireSerializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // if !self.output.ends_with('{') {
        //     self.output += ",";
        // }
        // key.serialize(&mut **self)?; // NO FIELD IN STRUCTS
        // self.output += ":";
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // self.output += "}";
        Ok(())
    }
}

// Similar to `SerializeTupleVariant`, here the `end` method is responsible for
// closing both of the curly braces opened by `serialize_struct_variant`.
impl<'a> ser::SerializeStructVariant for &'a mut RetroShareWireSerializer {
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
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

// // fn<S>(&T, S) -> Result<S::Ok, S::Error> where S: Serializer
// fn serialize_tlv<S, T>(tlv: &T, serializer: S) -> Result<S::Ok>
// where
//     S: serde::Serializer<Ok = ()>,
//     T: RetroShareTLV + serde::Serialize,
// {
//     let tag = tlv.get_tlv_tag();
//     let data = to_retroshare_wire(tlv).expect("failed to serialized");
//     let len = data.len();

//     // tag.serialize(serializer).expect("failed to serialized");
//     // len.serialize(serializer)?;
//     // data.serialize(serializer).expect("failed to serialized");
//     // serializer.serialize_u16(tag).expect("failed to serialized");
//     // let s = serializer.serialize_seq(len).expect("failed to serialized");
//     // data.iter().for_each(|b| s.serialize_element(b));
//     // s.end();

//     Ok(())
// }
