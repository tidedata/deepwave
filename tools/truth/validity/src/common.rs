//! Shared pieces: the vector file writer and the result encoding every suite uses.
//!
//! A vector file is zstd of text lines, one case per line, fields separated by a tab. The last
//! field is the verdict: `ok` (optionally followed by a space and a value) or `err <message>`,
//! where the message is Rust's `Display` of the error (`SuiError`/`UserInputError`), with `\`,
//! tab and newline escaped as `\\`, `\t` and `\n`. Lines starting with `#` are comments.

use std::fmt::Display;
use std::io::Write;

pub struct Out {
    lines: Vec<String>,
}

impl Out {
    pub fn new(header: &str) -> Self {
        Self {
            lines: header.lines().map(|l| format!("# {l}")).collect(),
        }
    }

    pub fn push(&mut self, fields: &[String]) {
        for f in fields {
            assert!(!f.contains('\t') && !f.contains('\n'), "unescaped field {f:?}");
        }
        self.lines.push(fields.join("\t"));
    }

    pub fn write(&self, path: &str) -> anyhow::Result<()> {
        let mut text = self.lines.join("\n");
        text.push('\n');
        let z = zstd::encode_all(text.as_bytes(), 19)?;
        let mut f = std::fs::File::create(path)?;
        f.write_all(&z)?;
        eprintln!(
            "{path}: {} cases, {} bytes ({} compressed)",
            self.lines.iter().filter(|l| !l.starts_with('#')).count(),
            text.len(),
            z.len()
        );
        Ok(())
    }
}

pub fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

/// `ok` / `ok <v>` / `err <Display>`.
pub fn verdict<T, E: Display>(r: &Result<T, E>, ok_value: impl Fn(&T) -> Option<String>) -> String {
    match r {
        Ok(v) => match ok_value(v) {
            Some(s) => format!("ok {}", esc(&s)),
            None => "ok".to_string(),
        },
        Err(e) => format!("err {}", esc(&e.to_string())),
    }
}
