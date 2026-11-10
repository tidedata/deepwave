//! Structural "tree" rendering of any `Serialize` value, driven by serde in
//! non-human-readable mode (the same mode BCS uses), so every custom
//! `Serialize` impl in sui-types takes its BCS code path.
//!
//! Canonical text rules (the Zig side in src/conformance/tree.zig must match):
//!   bool -> true/false; u8..u64, i8..i64 -> decimal number; u128/i128 -> "decimal string"
//!   bytes (serialize_bytes) and non-empty sequences/tuples made only of u8 -> "0x<hex>"
//!   empty bytes / empty sequence -> []
//!   string -> JSON string (serde_json escaping)
//!   None / unit / unit struct -> null; Some(v) -> v; newtype struct -> v (transparent)
//!   seq / tuple / tuple struct -> [..]
//!   map -> [[k, v], ..] in serialization order
//!   struct -> {"field": v, ..} in declaration order
//!   enum variant -> {"Variant": payload}; unit payload is null, tuple payload is [..]
//! Output is compact (no whitespace).

use serde::ser::{self, Serialize};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug)]
pub struct Error(String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error(msg.to_string())
    }
}

pub enum Node {
    Null,
    Bool(bool),
    Byte(u8),
    UInt(u64),
    Int(i64),
    Big(String),
    Str(String),
    Bytes(Vec<u8>),
    Arr(Vec<Node>),
    Obj(Vec<(&'static str, Node)>),
    Variant(&'static str, Box<Node>),
}

/// Collects `Enum::Variant` names seen while serializing (coverage report).
#[derive(Default)]
pub struct Coverage {
    pub variants: BTreeSet<String>,
}

pub fn to_node<T: Serialize + ?Sized>(v: &T, cov: &mut Coverage) -> Result<Node, Error> {
    v.serialize(Ser { cov })
}

pub fn to_text<T: Serialize + ?Sized>(v: &T, cov: &mut Coverage) -> Result<String, Error> {
    let n = to_node(v, cov)?;
    let mut s = String::new();
    render(&n, &mut s);
    Ok(s)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex(out: &mut String, b: &[u8]) {
    out.push_str("\"0x");
    for x in b {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 15) as usize] as char);
    }
    out.push('"');
}

pub fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let v = c as u32;
                out.push_str("\\u00");
                out.push(HEX[(v >> 4) as usize] as char);
                out.push(HEX[(v & 15) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn render(n: &Node, out: &mut String) {
    match n {
        Node::Null => out.push_str("null"),
        Node::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Node::Byte(b) => out.push_str(&b.to_string()),
        Node::UInt(v) => out.push_str(&v.to_string()),
        Node::Int(v) => out.push_str(&v.to_string()),
        Node::Big(s) => {
            out.push('"');
            out.push_str(s);
            out.push('"');
        }
        Node::Str(s) => push_json_str(out, s),
        Node::Bytes(b) => {
            if b.is_empty() {
                out.push_str("[]")
            } else {
                push_hex(out, b)
            }
        }
        Node::Arr(items) => {
            if !items.is_empty() && items.iter().all(|i| matches!(i, Node::Byte(_))) {
                let bytes: Vec<u8> = items
                    .iter()
                    .map(|i| match i {
                        Node::Byte(b) => *b,
                        _ => unreachable!(),
                    })
                    .collect();
                push_hex(out, &bytes);
            } else {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    render(it, out);
                }
                out.push(']');
            }
        }
        Node::Obj(fields) => {
            out.push('{');
            for (i, (k, v)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_json_str(out, k);
                out.push(':');
                render(v, out);
            }
            out.push('}');
        }
        Node::Variant(name, payload) => {
            out.push('{');
            push_json_str(out, name);
            out.push(':');
            render(payload, out);
            out.push('}');
        }
    }
}

pub struct Ser<'c> {
    cov: &'c mut Coverage,
}

impl<'c> Ser<'c> {
    fn reborrow(&mut self) -> Ser<'_> {
        Ser { cov: self.cov }
    }
}

pub struct SeqSer<'c> {
    cov: &'c mut Coverage,
    items: Vec<Node>,
    variant: Option<&'static str>,
}

pub struct MapSer<'c> {
    cov: &'c mut Coverage,
    items: Vec<Node>,
    key: Option<Node>,
}

pub struct StructSer<'c> {
    cov: &'c mut Coverage,
    fields: Vec<(&'static str, Node)>,
    variant: Option<&'static str>,
}

impl<'c> ser::Serializer for Ser<'c> {
    type Ok = Node;
    type Error = Error;
    type SerializeSeq = SeqSer<'c>;
    type SerializeTuple = SeqSer<'c>;
    type SerializeTupleStruct = SeqSer<'c>;
    type SerializeTupleVariant = SeqSer<'c>;
    type SerializeMap = MapSer<'c>;
    type SerializeStruct = StructSer<'c>;
    type SerializeStructVariant = StructSer<'c>;

    fn is_human_readable(&self) -> bool {
        false
    }
    fn serialize_bool(self, v: bool) -> Result<Node, Error> {
        Ok(Node::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Node, Error> {
        Ok(Node::Int(v as i64))
    }
    fn serialize_i16(self, v: i16) -> Result<Node, Error> {
        Ok(Node::Int(v as i64))
    }
    fn serialize_i32(self, v: i32) -> Result<Node, Error> {
        Ok(Node::Int(v as i64))
    }
    fn serialize_i64(self, v: i64) -> Result<Node, Error> {
        Ok(Node::Int(v))
    }
    fn serialize_i128(self, v: i128) -> Result<Node, Error> {
        Ok(Node::Big(v.to_string()))
    }
    fn serialize_u8(self, v: u8) -> Result<Node, Error> {
        Ok(Node::Byte(v))
    }
    fn serialize_u16(self, v: u16) -> Result<Node, Error> {
        Ok(Node::UInt(v as u64))
    }
    fn serialize_u32(self, v: u32) -> Result<Node, Error> {
        Ok(Node::UInt(v as u64))
    }
    fn serialize_u64(self, v: u64) -> Result<Node, Error> {
        Ok(Node::UInt(v))
    }
    fn serialize_u128(self, v: u128) -> Result<Node, Error> {
        Ok(Node::Big(v.to_string()))
    }
    fn serialize_f32(self, _v: f32) -> Result<Node, Error> {
        Err(Error("f32 not supported".into()))
    }
    fn serialize_f64(self, _v: f64) -> Result<Node, Error> {
        Err(Error("f64 not supported".into()))
    }
    fn serialize_char(self, _v: char) -> Result<Node, Error> {
        Err(Error("char not supported".into()))
    }
    fn serialize_str(self, v: &str) -> Result<Node, Error> {
        Ok(Node::Str(v.to_string()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Node, Error> {
        Ok(Node::Bytes(v.to_vec()))
    }
    fn serialize_none(self) -> Result<Node, Error> {
        Ok(Node::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Node, Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Node, Error> {
        Ok(Node::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Node, Error> {
        Ok(Node::Null)
    }
    fn serialize_unit_variant(
        self,
        name: &'static str,
        _idx: u32,
        variant: &'static str,
    ) -> Result<Node, Error> {
        self.cov.variants.insert(format!("{name}::{variant}"));
        Ok(Node::Variant(variant, Box::new(Node::Null)))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Node, Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        mut self,
        name: &'static str,
        _idx: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Node, Error> {
        self.cov.variants.insert(format!("{name}::{variant}"));
        let inner = value.serialize(self.reborrow())?;
        Ok(Node::Variant(variant, Box::new(inner)))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSer<'c>, Error> {
        Ok(SeqSer { cov: self.cov, items: Vec::with_capacity(len.unwrap_or(0)), variant: None })
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqSer<'c>, Error> {
        Ok(SeqSer { cov: self.cov, items: Vec::with_capacity(len), variant: None })
    }
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<SeqSer<'c>, Error> {
        Ok(SeqSer { cov: self.cov, items: Vec::with_capacity(len), variant: None })
    }
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        _idx: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<SeqSer<'c>, Error> {
        self.cov.variants.insert(format!("{name}::{variant}"));
        Ok(SeqSer { cov: self.cov, items: Vec::with_capacity(len), variant: Some(variant) })
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<MapSer<'c>, Error> {
        Ok(MapSer { cov: self.cov, items: Vec::new(), key: None })
    }
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<StructSer<'c>, Error> {
        Ok(StructSer { cov: self.cov, fields: Vec::with_capacity(len), variant: None })
    }
    fn serialize_struct_variant(
        self,
        name: &'static str,
        _idx: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<StructSer<'c>, Error> {
        self.cov.variants.insert(format!("{name}::{variant}"));
        Ok(StructSer { cov: self.cov, fields: Vec::with_capacity(len), variant: Some(variant) })
    }
}

impl<'c> SeqSer<'c> {
    fn push<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
        let n = v.serialize(Ser { cov: self.cov })?;
        self.items.push(n);
        Ok(())
    }
    fn finish(self) -> Node {
        match self.variant {
            Some(v) => Node::Variant(v, Box::new(Node::Arr(self.items))),
            None => Node::Arr(self.items),
        }
    }
}

impl<'c> ser::SerializeSeq for SeqSer<'c> {
    type Ok = Node;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
        self.push(v)
    }
    fn end(self) -> Result<Node, Error> {
        Ok(self.finish())
    }
}
impl<'c> ser::SerializeTuple for SeqSer<'c> {
    type Ok = Node;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
        self.push(v)
    }
    fn end(self) -> Result<Node, Error> {
        Ok(self.finish())
    }
}
impl<'c> ser::SerializeTupleStruct for SeqSer<'c> {
    type Ok = Node;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
        self.push(v)
    }
    fn end(self) -> Result<Node, Error> {
        Ok(self.finish())
    }
}
impl<'c> ser::SerializeTupleVariant for SeqSer<'c> {
    type Ok = Node;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
        self.push(v)
    }
    fn end(self) -> Result<Node, Error> {
        Ok(self.finish())
    }
}
impl<'c> ser::SerializeMap for MapSer<'c> {
    type Ok = Node;
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, k: &T) -> Result<(), Error> {
        self.key = Some(k.serialize(Ser { cov: self.cov })?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
        let k = self.key.take().ok_or_else(|| Error("value before key".into()))?;
        let v = v.serialize(Ser { cov: self.cov })?;
        self.items.push(Node::Arr(vec![k, v]));
        Ok(())
    }
    fn end(self) -> Result<Node, Error> {
        Ok(Node::Arr(self.items))
    }
}
impl<'c> StructSer<'c> {
    fn push<T: Serialize + ?Sized>(&mut self, k: &'static str, v: &T) -> Result<(), Error> {
        let n = v.serialize(Ser { cov: self.cov })?;
        self.fields.push((k, n));
        Ok(())
    }
    fn finish(self) -> Node {
        match self.variant {
            Some(v) => Node::Variant(v, Box::new(Node::Obj(self.fields))),
            None => Node::Obj(self.fields),
        }
    }
}
impl<'c> ser::SerializeStruct for StructSer<'c> {
    type Ok = Node;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, k: &'static str, v: &T) -> Result<(), Error> {
        self.push(k, v)
    }
    fn end(self) -> Result<Node, Error> {
        Ok(self.finish())
    }
}
impl<'c> ser::SerializeStructVariant for StructSer<'c> {
    type Ok = Node;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, k: &'static str, v: &T) -> Result<(), Error> {
        self.push(k, v)
    }
    fn end(self) -> Result<Node, Error> {
        Ok(self.finish())
    }
}
