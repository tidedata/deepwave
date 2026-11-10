//! Writes the `bcs-codec` suite vectors: edge cases for the BCS codec, with the result of
//! crates.io `bcs` 0.1.6 (the codec Mysten's sui-types links) for each input.
//!
//!   zui-truth-bcs-types vectors <out.jsonl>
//!
//! One JSON object per line (format in README.md):
//!   {"id":"u32/trunc-3","type":"u32","in":"010203","ok":"01020300"}      decoded, re-encoded bytes
//!   {"id":"u32/trunc-3","type":"u32","in":"010203","err":"EndOfInput"}   decode error kind
//! Error kinds are deepwave's `bcs.Error` names; see `kind()`.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
enum E {
    A,
    B(u32),
    C { x: u8, y: bool },
    D(Vec<u8>),
    F(u8, u16),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct S {
    a: u16,
    b: Option<String>,
    c: [u8; 4],
    d: (u8, u16),
    e: Vec<E>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
enum Nest {
    Nil,
    Cons(Box<Nest>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct NT(Option<Box<NT>>);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Unit;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Wrapper {
    v: Vec<Wrapper>,
}

fn kind(e: &bcs::Error) -> &'static str {
    use bcs::Error::*;
    match e {
        Eof => "EndOfInput",
        RemainingInput => "TrailingBytes",
        NonCanonicalUleb128Encoding | IntegerOverflowDuringUleb128Decoding => "InvalidUleb",
        ExpectedBoolean => "InvalidBool",
        ExpectedOption => "InvalidEnumTag",
        Utf8 => "InvalidUtf8",
        ExceededMaxLen(_) => "LengthTooLarge",
        ExceededContainerDepthLimit(_) => "DepthExceeded",
        NonCanonicalMap => "NonCanonical",
        Custom(m) if m.contains("variant index") => "InvalidEnumTag",
        _ => "Other",
    }
}

struct Out {
    w: std::io::BufWriter<std::fs::File>,
    n: usize,
}

impl Out {
    fn probe<T: for<'a> Deserialize<'a> + Serialize>(&mut self, ty: &str, id: &str, input: &[u8]) {
        let res = match bcs::from_bytes::<T>(input) {
            Ok(v) => match bcs::to_bytes(&v) {
                Ok(b) => format!("\"ok\":\"{}\"", hex::encode(b)),
                Err(e) => format!("\"err\":\"EncodeFailed:{}\"", e.to_string().replace('"', "'")),
            },
            Err(e) => {
                let k = kind(&e);
                if k == "Other" {
                    eprintln!("unclassified error for {ty}/{id}: {e:?}");
                }
                format!("\"err\":\"{k}\"")
            }
        };
        writeln!(self.w, "{{\"id\":\"{ty}/{id}\",\"type\":\"{ty}\",\"in\":\"{}\",{}}}", hex::encode(input), res).unwrap();
        self.n += 1;
    }

    /// Valid encodings, every truncation, trailing byte, and single-byte corruptions.
    fn family<T: for<'a> Deserialize<'a> + Serialize>(&mut self, ty: &str, samples: &[Vec<u8>]) {
        for (si, s) in samples.iter().enumerate() {
            self.probe::<T>(ty, &format!("valid-{si}"), s);
            for cut in 0..s.len() {
                self.probe::<T>(ty, &format!("s{si}-trunc-{cut}"), &s[..cut]);
            }
            let mut t = s.clone();
            t.push(0);
            self.probe::<T>(ty, &format!("s{si}-trailing"), &t);
            for pos in 0..s.len().min(24) {
                for v in [0x00u8, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff] {
                    if s[pos] == v {
                        continue;
                    }
                    let mut m = s.clone();
                    m[pos] = v;
                    self.probe::<T>(ty, &format!("s{si}-set-{pos}-{v:02x}"), &m);
                }
            }
        }
    }
}

fn ser<T: Serialize>(v: &T) -> Vec<u8> {
    bcs::to_bytes(v).unwrap()
}

fn uleb_edges() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        vec![0x00],
        vec![0x01],
        vec![0x7f],
        vec![0x80, 0x01],
        vec![0xff, 0x7f],
        vec![0x80, 0x80, 0x01],
        vec![0xff, 0xff, 0x7f],
        vec![0x80, 0x80, 0x80, 0x01],
        vec![0xff, 0xff, 0xff, 0x7f],
        vec![0x80, 0x80, 0x80, 0x80, 0x01],
        vec![0xff, 0xff, 0xff, 0xff, 0x07],
        vec![0x80, 0x80, 0x80, 0x80, 0x08],
        vec![0xff, 0xff, 0xff, 0xff, 0x0f],
        vec![0xff, 0xff, 0xff, 0xff, 0x10],
        vec![0xff, 0xff, 0xff, 0xff, 0x1f],
        vec![0xff, 0xff, 0xff, 0xff, 0x7f],
        vec![0x80, 0x00],
        vec![0x80, 0x80, 0x00],
        vec![0xff, 0x00],
        vec![0x80, 0x80, 0x80, 0x80, 0x00],
        vec![0x80, 0x80, 0x80, 0x80, 0x80],
        vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
        vec![0x80],
        vec![0xff, 0xff],
        vec![],
    ];
    // lengths that fit the following bytes
    for n in [1usize, 2, 127, 128, 129, 300] {
        let mut b = ser(&vec![7u8; n]);
        b.truncate(b.len());
        v.push(b);
    }
    v
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1] != "vectors" {
        eprintln!("usage: zui-truth-bcs-types vectors <out.jsonl>");
        std::process::exit(2);
    }
    let mut o = Out { w: std::io::BufWriter::new(std::fs::File::create(&args[2]).unwrap()), n: 0 };

    // Scalars: exhaustive where cheap.
    for b in 0..=255u8 {
        o.probe::<bool>("bool", &format!("{b:02x}"), &[b]);
        o.probe::<u8>("u8", &format!("{b:02x}"), &[b]);
    }
    o.family::<u16>("u16", &[ser(&0u16), ser(&0xabcdu16), ser(&u16::MAX)]);
    o.family::<u32>("u32", &[ser(&0u32), ser(&0x01020304u32), ser(&u32::MAX)]);
    o.family::<u64>("u64", &[ser(&0u64), ser(&0x0102030405060708u64), ser(&u64::MAX)]);
    o.family::<u128>("u128", &[ser(&0u128), ser(&(u128::MAX - 12345)), ser(&u128::MAX)]);
    o.family::<Option<u32>>("opt_u32", &[ser(&None::<u32>), ser(&Some(0u32)), ser(&Some(u32::MAX))]);
    o.family::<()>("unit", &[vec![]]);
    o.family::<Unit>("unit_struct", &[vec![]]);
    o.family::<[u8; 4]>("array4", &[ser(&[1u8, 2, 3, 4])]);
    o.family::<(u8, bool)>("tuple_u8_bool", &[ser(&(9u8, true)), ser(&(0u8, false))]);

    // Byte strings and sequences: length prefixes.
    for (i, e) in uleb_edges().iter().enumerate() {
        for tail in [0usize, 1, 3] {
            let mut inp = e.clone();
            inp.extend(std::iter::repeat(0x41).take(tail));
            o.probe::<Vec<u8>>("bytes", &format!("uleb{i}-tail{tail}"), &inp);
            o.probe::<String>("string", &format!("uleb{i}-tail{tail}"), &inp);
            o.probe::<Vec<u32>>("vec_u32", &format!("uleb{i}-tail{tail}"), &inp);
            o.probe::<Vec<Option<u8>>>("vec_opt_u8", &format!("uleb{i}-tail{tail}"), &inp);
            o.probe::<BTreeMap<u8, u8>>("map_u8_u8", &format!("uleb{i}-tail{tail}"), &inp);
            o.probe::<E>("enum", &format!("uleb{i}-tail{tail}"), &inp);
        }
    }
    o.family::<Vec<u8>>("bytes", &[ser(&Vec::<u8>::new()), ser(&vec![1u8, 2, 3]), ser(&vec![9u8; 200])]);
    o.family::<Vec<u32>>("vec_u32", &[ser(&Vec::<u32>::new()), ser(&vec![1u32, 2, 3])]);
    o.family::<Vec<Vec<u8>>>("vec_vec_u8", &[ser(&vec![vec![1u8], vec![], vec![2, 3]])]);
    o.family::<Vec<Option<u8>>>("vec_opt_u8", &[ser(&vec![Some(1u8), None, Some(3)])]);
    o.family::<String>("string", &[ser(&String::new()), ser(&"hello".to_string()), ser(&"h\u{e9}llo \u{1f600}".to_string())]);
    // UTF-8 edge cases
    for (i, bytes) in [
        vec![0x01, 0x80],
        vec![0x01, 0xc0],
        vec![0x02, 0xc0, 0x80],
        vec![0x02, 0xc2, 0xa9],
        vec![0x03, 0xe0, 0x80, 0x80],
        vec![0x03, 0xed, 0xa0, 0x80],
        vec![0x03, 0xe2, 0x82, 0xac],
        vec![0x04, 0xf0, 0x80, 0x80, 0x80],
        vec![0x04, 0xf4, 0x90, 0x80, 0x80],
        vec![0x04, 0xf0, 0x9f, 0x98, 0x80],
        vec![0x04, 0xf8, 0x88, 0x80, 0x80],
        vec![0x03, 0xe2, 0x82],
        vec![0x01, 0x00],
        vec![0x01, 0x7f],
    ]
    .iter()
    .enumerate()
    {
        o.probe::<String>("string", &format!("utf8-{i}"), bytes);
    }

    // Enums: every variant index around the valid range.
    let es = vec![
        ser(&E::A),
        ser(&E::B(0xdeadbeef)),
        ser(&E::C { x: 7, y: true }),
        ser(&E::D(vec![1, 2, 3])),
        ser(&E::F(1, 2)),
    ];
    o.family::<E>("enum", &es);
    for tag in [4u8, 5, 6, 0x7f, 0x80, 0xff] {
        o.probe::<E>("enum", &format!("tag-{tag:02x}"), &[tag, 0, 0, 0, 0, 0]);
    }
    o.probe::<E>("enum", "tag-noncanon", &[0x80, 0x00]);
    o.probe::<E>("enum", "tag-0-long", &[0x80, 0x00, 0x00]);

    let s = S {
        a: 513,
        b: Some("zui".into()),
        c: [1, 2, 3, 4],
        d: (5, 6),
        e: vec![E::A, E::B(1), E::D(vec![9])],
    };
    o.family::<S>("struct", &[ser(&s), ser(&S { b: None, e: vec![], ..s.clone() })]);

    // Maps: canonical order is by serialized key bytes.
    let mut m = BTreeMap::new();
    m.insert(1u8, 10u8);
    m.insert(2, 20);
    m.insert(200, 30);
    o.family::<BTreeMap<u8, u8>>("map_u8_u8", &[ser(&BTreeMap::<u8, u8>::new()), ser(&m)]);
    for (i, inp) in [
        vec![2u8, 1, 1, 1, 2],
        vec![2, 2, 1, 1, 2],
        vec![2, 1, 1, 1, 1],
        vec![2, 1, 1, 2, 2, 3, 3],
        vec![3, 1, 1, 0, 2, 3, 3],
    ]
    .iter()
    .enumerate()
    {
        o.probe::<BTreeMap<u8, u8>>("map_u8_u8", &format!("order-{i}"), inp);
    }
    let mut ms = BTreeMap::new();
    ms.insert("b".to_string(), 1u8);
    ms.insert("aa".to_string(), 2);
    ms.insert("address".to_string(), 3);
    o.family::<BTreeMap<String, u8>>("map_str_u8", &[ser(&ms)]);
    // Wire order of string keys is length first, not lexicographic.
    o.probe::<BTreeMap<String, u8>>("map_str_u8", "lex-order", &[2, 2, b'a', b'a', 1, 1, b'b', 2]);
    o.probe::<BTreeMap<String, u8>>("map_str_u8", "len-order", &[2, 1, b'b', 2, 2, b'a', b'a', 1]);

    // Container depth: enum nesting (each level is one container).
    fn nest(n: usize) -> Vec<u8> {
        let mut v = vec![1u8; n];
        v.push(0);
        v
    }
    for n in [0usize, 1, 2, 10, 100, 498, 499, 500, 501, 502, 1000, 5000] {
        o.probe::<Nest>("nest", &format!("depth-{n}"), &nest(n));
    }
    // Newtype structs count; Option and Vec do not.
    fn nt(n: usize) -> Vec<u8> {
        let mut v = vec![1u8; n];
        v.push(0);
        v
    }
    for n in [0usize, 1, 100, 498, 499, 500, 501, 502, 1000] {
        o.probe::<NT>("newtype_nest", &format!("depth-{n}"), &nt(n));
    }
    // Wrapper { v: Vec<Wrapper> }: struct counts, Vec does not: each level is `01` (len 1) then
    // the inner struct; the innermost is `00`.
    fn wr(n: usize) -> Vec<u8> {
        let mut v = vec![1u8; n];
        v.push(0);
        v
    }
    for n in [0usize, 1, 100, 498, 499, 500, 501, 502, 1000] {
        o.probe::<Wrapper>("wrapper_nest", &format!("depth-{n}"), &wr(n));
    }
    o.w.flush().unwrap();
    eprintln!("wrote {} vectors", o.n);
}
