use std::collections::BTreeMap;
use std::fmt::Write as _;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Num {
    Int(i128),
    Float(f64),
}

impl Num {
    fn float(self) -> f64 {
        match self {
            Num::Int(n) => n as f64,
            Num::Float(f) => f,
        }
    }

    fn same(self, other: Num) -> bool {
        match (self, other) {
            (Num::Int(a), Num::Int(b)) => a == b,
            (a, b) => (a.float() - b.float()).abs() <= 1e-9 * a.float().abs().max(1.0),
        }
    }
}

/// An evaluated constant: a plain number, or a duration in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Quantity {
    Plain(Num),
    Duration(Num),
}

impl Quantity {
    fn same(self, other: Quantity) -> bool {
        match (self, other) {
            (Quantity::Plain(a), Quantity::Plain(b))
            | (Quantity::Duration(a), Quantity::Duration(b)) => a.same(b),
            _ => false,
        }
    }

    fn render(self) -> String {
        match self {
            Quantity::Plain(Num::Int(n)) => n.to_string(),
            Quantity::Plain(Num::Float(f)) => format!("{f}"),
            Quantity::Duration(Num::Float(ns)) => format!("{} s", ns / 1e9),
            Quantity::Duration(Num::Int(ns)) => {
                for (unit, scale) in [("s", 1_000_000_000), ("ms", 1_000_000), ("µs", 1_000)] {
                    if ns != 0 && ns % scale == 0 {
                        return format!("{} {unit}", ns / scale);
                    }
                }
                if ns == 0 {
                    "0 s".to_string()
                } else {
                    format!("{ns} ns")
                }
            }
        }
    }
}

/// A value as the code states it: evaluated when the initializer is literal arithmetic, else
/// the initializer's source text.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Value {
    Known(Quantity),
    Text(String),
}

impl Value {
    pub(super) fn render(&self) -> String {
        match self {
            Value::Known(quantity) => quantity.render(),
            Value::Text(text) => format!("`{text}`"),
        }
    }

    pub(super) fn matches(&self, written: &Written) -> bool {
        match (self, written) {
            (Value::Known(code), Written::Quantity(cell)) => code.same(*cell),
            (Value::Text(code), Written::Text(cell)) => squash(code) == squash(cell),
            (Value::Known(_), Written::Text(_)) | (Value::Text(_), Written::Quantity(_)) => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Written {
    Quantity(Quantity),
    Text(String),
}

pub(super) fn squash(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Parses `64`, `16_384`, `65,536`, `1.5`, `64 KiB`, `30 s`, `100 ms`, or `` `expr` ``.
pub(super) fn parse_written(cell: &str) -> Option<Written> {
    let cell = cell.trim();
    if let Some(text) = cell.strip_prefix('`').and_then(|c| c.strip_suffix('`')) {
        return (!text.is_empty() && !text.contains('`')).then(|| Written::Text(text.to_string()));
    }
    let (number, unit) = match cell.split_once(' ') {
        Some((number, unit)) => (number, unit.trim()),
        None => (cell, ""),
    };
    let digits: String = number.chars().filter(|c| *c != '_' && *c != ',').collect();
    let num = if let Ok(n) = digits.parse::<i128>() {
        Num::Int(n)
    } else {
        Num::Float(digits.parse::<f64>().ok().filter(|f| f.is_finite())?)
    };
    let scaled = |scale: i128| match num {
        Num::Int(n) => Num::Int(n * scale),
        Num::Float(f) => Num::Float(f * scale as f64),
    };
    Some(Written::Quantity(match unit {
        "" => Quantity::Plain(num),
        "B" => Quantity::Plain(num),
        "KiB" => Quantity::Plain(scaled(1 << 10)),
        "MiB" => Quantity::Plain(scaled(1 << 20)),
        "GiB" => Quantity::Plain(scaled(1 << 30)),
        "ns" => Quantity::Duration(num),
        "µs" | "us" => Quantity::Duration(scaled(1_000)),
        "ms" => Quantity::Duration(scaled(1_000_000)),
        "s" => Quantity::Duration(scaled(1_000_000_000)),
        "min" => Quantity::Duration(scaled(60_000_000_000)),
        "h" => Quantity::Duration(scaled(3_600_000_000_000)),
        _ => return None,
    }))
}

/// A cell holding the values of every definition of an item, `cfg` variants in source order
/// separated by ` / `.
pub(super) fn parse_values(cell: &str) -> Option<Vec<Written>> {
    cell.split(" / ").map(parse_written).collect()
}

pub(super) fn values_match(code: &[Value], written: &[Written]) -> bool {
    code.len() == written.len() && code.iter().zip(written).all(|(c, w)| c.matches(w))
}

pub(super) fn render_values(values: &[Value]) -> String {
    values
        .iter()
        .map(Value::render)
        .collect::<Vec<_>>()
        .join(" / ")
}

/// Source text with the spaces `to_string` puts inside paths and calls removed.
pub(super) fn source_text(tokens: TokenStream) -> String {
    let mut out = String::new();
    write_tokens(&mut out, tokens);
    out.trim().to_string()
}

pub(super) fn write_tokens(out: &mut String, tokens: TokenStream) {
    let mut joint = true;
    for token in tokens {
        match token {
            TokenTree::Group(group) => {
                let (open, close) = match group.delimiter() {
                    Delimiter::Parenthesis => ("(", ")"),
                    Delimiter::Bracket => ("[", "]"),
                    Delimiter::Brace => (" { ", " }"),
                    Delimiter::None => ("", ""),
                };
                out.push_str(open);
                write_tokens(out, group.stream());
                out.push_str(close);
                joint = false;
            }
            TokenTree::Punct(punct) => {
                let c = punct.as_char();
                let tight = matches!(c, ':' | '.' | '!' | '&');
                if !tight && c != ',' && !out.ends_with([' ', '(', '[']) {
                    out.push(' ');
                }
                out.push(c);
                if !tight && punct.spacing() == proc_macro2::Spacing::Alone {
                    out.push(' ');
                }
                joint = true;
            }
            TokenTree::Ident(ident) => {
                if !joint && !out.ends_with([' ', '(', '[']) {
                    out.push(' ');
                }
                let _ = write!(out, "{ident}");
                joint = false;
            }
            TokenTree::Literal(literal) => {
                if !joint && !out.ends_with([' ', '(', '[']) {
                    out.push(' ');
                }
                let _ = write!(out, "{literal}");
                joint = false;
            }
        }
    }
}

pub(super) struct Eval<'a> {
    pub(super) locals: &'a BTreeMap<String, Value>,
}

impl Eval<'_> {
    pub(super) fn quantity(&self, expr: &syn::Expr) -> Option<Quantity> {
        match expr {
            syn::Expr::Paren(inner) => self.quantity(&inner.expr),
            syn::Expr::Group(inner) => self.quantity(&inner.expr),
            syn::Expr::Lit(lit) => literal(&lit.lit).map(Quantity::Plain),
            syn::Expr::Unary(unary) => match (&unary.op, self.quantity(&unary.expr)?) {
                (syn::UnOp::Neg(_), Quantity::Plain(Num::Int(n))) => {
                    Some(Quantity::Plain(Num::Int(-n)))
                }
                (syn::UnOp::Neg(_), Quantity::Plain(Num::Float(f))) => {
                    Some(Quantity::Plain(Num::Float(-f)))
                }
                _ => None,
            },
            syn::Expr::Cast(cast) => {
                let value = self.quantity(&cast.expr)?;
                let target = leaf(&cast.ty)?;
                match value {
                    Quantity::Plain(Num::Float(f)) if is_int(&target) => {
                        Some(Quantity::Plain(Num::Int(f.trunc() as i128)))
                    }
                    Quantity::Plain(Num::Int(n)) if is_float(&target) => {
                        Some(Quantity::Plain(Num::Float(Num::Int(n).float())))
                    }
                    Quantity::Plain(_) if is_number(&target) => Some(value),
                    _ => None,
                }
            }
            syn::Expr::Binary(binary) => {
                let left = self.quantity(&binary.left)?;
                let right = self.quantity(&binary.right)?;
                binary_op(&binary.op, left, right)
            }
            syn::Expr::Path(path) => self.path(&path.path),
            syn::Expr::Call(call) => self.call(call),
            syn::Expr::MethodCall(method)
                if matches!(method.method.to_string().as_str(), "unwrap" | "expect") =>
            {
                let syn::Expr::Call(call) = &*method.receiver else {
                    return None;
                };
                let name = call_path(call)?;
                (name.len() == 2 && name[0].starts_with("NonZero") && name[1] == "new")
                    .then(|| self.single_arg(call))
                    .flatten()
            }
            _ => None,
        }
    }

    fn path(&self, path: &syn::Path) -> Option<Quantity> {
        let names: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        match names.as_slice() {
            [name] | [_, name] if names.len() == 1 || names[0] == "Self" => {
                match self.locals.get(name) {
                    Some(Value::Known(quantity)) => Some(*quantity),
                    _ => None,
                }
            }
            [ty, bound] if is_int(ty) && (bound == "MAX" || bound == "MIN") => {
                int_bound(ty, bound == "MAX").map(|n| Quantity::Plain(Num::Int(n)))
            }
            [ty, zero] if ty == "Duration" && zero == "ZERO" => {
                Some(Quantity::Duration(Num::Int(0)))
            }
            _ => None,
        }
    }

    fn single_arg(&self, call: &syn::ExprCall) -> Option<Quantity> {
        match call.args.iter().collect::<Vec<_>>().as_slice() {
            [arg] => self.quantity(arg),
            _ => None,
        }
    }

    fn call(&self, call: &syn::ExprCall) -> Option<Quantity> {
        let name = call_path(call)?;
        let [ty, function] = name.as_slice() else {
            return None;
        };
        if ty != "Duration" {
            return None;
        }
        let scale: i128 = match function.as_str() {
            "from_secs" => 1_000_000_000,
            "from_millis" => 1_000_000,
            "from_micros" => 1_000,
            "from_nanos" => 1,
            "from_secs_f64" | "from_secs_f32" => {
                let Quantity::Plain(seconds) = self.single_arg(call)? else {
                    return None;
                };
                return Some(Quantity::Duration(Num::Float(seconds.float() * 1e9)));
            }
            "new" => {
                let args: Vec<&syn::Expr> = call.args.iter().collect();
                let [secs, nanos] = args.as_slice() else {
                    return None;
                };
                let (Quantity::Plain(Num::Int(secs)), Quantity::Plain(Num::Int(nanos))) =
                    (self.quantity(secs)?, self.quantity(nanos)?)
                else {
                    return None;
                };
                return Some(Quantity::Duration(Num::Int(secs * 1_000_000_000 + nanos)));
            }
            _ => return None,
        };
        match self.single_arg(call)? {
            Quantity::Plain(Num::Int(n)) => Some(Quantity::Duration(Num::Int(n * scale))),
            _ => None,
        }
    }
}

pub(super) fn call_path(call: &syn::ExprCall) -> Option<Vec<String>> {
    let syn::Expr::Path(path) = &*call.func else {
        return None;
    };
    let names: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    let start = names.len().saturating_sub(2);
    Some(names[start..].to_vec())
}

pub(super) fn literal(lit: &syn::Lit) -> Option<Num> {
    match lit {
        syn::Lit::Int(int) => int.base10_parse::<i128>().ok().map(Num::Int),
        syn::Lit::Float(float) => float.base10_parse::<f64>().ok().map(Num::Float),
        syn::Lit::Byte(byte) => Some(Num::Int(i128::from(byte.value()))),
        _ => None,
    }
}

pub(super) fn binary_op(op: &syn::BinOp, left: Quantity, right: Quantity) -> Option<Quantity> {
    use syn::BinOp;
    let int = |f: fn(i128, i128) -> Option<i128>, a: Num, b: Num| match (a, b) {
        (Num::Int(a), Num::Int(b)) => f(a, b).map(Num::Int),
        _ => None,
    };
    let num = |a: Num, b: Num| -> Option<Num> {
        match op {
            BinOp::Add(_) => {
                int(i128::checked_add, a, b).or(Some(Num::Float(a.float() + b.float())))
            }
            BinOp::Sub(_) => {
                int(i128::checked_sub, a, b).or(Some(Num::Float(a.float() - b.float())))
            }
            BinOp::Mul(_) => {
                int(i128::checked_mul, a, b).or(Some(Num::Float(a.float() * b.float())))
            }
            BinOp::Div(_) => match (a, b) {
                (Num::Int(_), Num::Int(_)) => int(i128::checked_div, a, b),
                _ => Some(Num::Float(a.float() / b.float())),
            },
            BinOp::Rem(_) => int(i128::checked_rem, a, b),
            BinOp::Shl(_) => int(
                |a, b| u32::try_from(b).ok().and_then(|b| a.checked_shl(b)),
                a,
                b,
            ),
            BinOp::Shr(_) => int(
                |a, b| u32::try_from(b).ok().and_then(|b| a.checked_shr(b)),
                a,
                b,
            ),
            BinOp::BitOr(_) => int(|a, b| Some(a | b), a, b),
            BinOp::BitAnd(_) => int(|a, b| Some(a & b), a, b),
            _ => None,
        }
    };
    match (left, right) {
        (Quantity::Plain(a), Quantity::Plain(b)) => num(a, b).map(Quantity::Plain),
        (Quantity::Duration(a), Quantity::Duration(b))
            if matches!(op, BinOp::Add(_) | BinOp::Sub(_)) =>
        {
            num(a, b).map(Quantity::Duration)
        }
        (Quantity::Duration(a), Quantity::Plain(b))
            if matches!(op, BinOp::Mul(_) | BinOp::Div(_)) =>
        {
            num(a, b).map(Quantity::Duration)
        }
        _ => None,
    }
}

pub(super) const INTS: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
];

pub(super) fn is_int(name: &str) -> bool {
    INTS.contains(&name)
}

pub(super) fn is_float(name: &str) -> bool {
    name == "f32" || name == "f64"
}

pub(super) fn is_number(name: &str) -> bool {
    is_int(name) || is_float(name)
}

pub(super) fn int_bound(ty: &str, max: bool) -> Option<i128> {
    let bits = match ty {
        "u8" | "i8" => 8,
        "u16" | "i16" => 16,
        "u32" | "i32" => 32,
        "u64" | "i64" | "usize" | "isize" => 64,
        _ => return None,
    };
    Some(match (ty.starts_with('u'), max) {
        (true, true) => (1i128 << bits) - 1,
        (true, false) => 0,
        (false, true) => (1i128 << (bits - 1)) - 1,
        (false, false) => -(1i128 << (bits - 1)),
    })
}

pub(super) fn leaf(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) if path.qself.is_none() => {
            path.path.segments.last().map(|s| s.ident.to_string())
        }
        syn::Type::Paren(inner) => leaf(&inner.elem),
        syn::Type::Group(inner) => leaf(&inner.elem),
        _ => None,
    }
}

/// Whether a `const` or `static` of this type is gated: a number, a `Duration`, a `NonZero*`,
/// or an array of them.
pub(super) fn is_gated_type(ty: &syn::Type) -> bool {
    if let syn::Type::Array(array) = ty {
        return is_gated_type(&array.elem);
    }
    leaf(ty)
        .is_some_and(|name| is_number(&name) || name == "Duration" || name.starts_with("NonZero"))
}
