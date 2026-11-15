use std::collections::BTreeMap;
use std::path::Path;

use quote::ToTokens;
use syn::visit::{self, Visit};

use super::value::{Eval, Value, is_gated_type, leaf, source_text};
use crate::ratchets::is_test_file;
use crate::stream_policy::rust_files;

const ROOTS: &[&str] = &["crates", "bins"];
const SKIPPED: &[&str] = &["crates/test-support"];

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Item {
    pub(super) path: String,
    pub(super) file: String,
    pub(super) line: usize,
    pub(super) values: Vec<Value>,
}

/// `crates/net/src/relay.rs` is `net::relay`; `bins/android/src/core.rs` is `android::core`.
pub(super) fn module_of(file: &str) -> String {
    let parts: Vec<&str> = file.split('/').collect();
    let mut module = vec![parts.get(1).copied().unwrap_or_default().to_string()];
    let rest = match parts.get(2) {
        Some(&"src") => &parts[3..],
        _ => &parts[2..],
    };
    for (index, part) in rest.iter().enumerate() {
        let part = part.strip_suffix(".rs").unwrap_or(part);
        let last = index + 1 == rest.len();
        if last && matches!(part, "lib" | "main" | "mod") {
            continue;
        }
        module.push(part.to_string());
    }
    module.join("::")
}

pub(super) fn scan(root: &Path) -> Result<Vec<Item>, String> {
    let mut files = Vec::new();
    for dir in ROOTS {
        rust_files(&root.join(dir), &mut files)?;
    }
    files.sort();
    let mut parsed = Vec::new();
    let mut test_modules = Vec::new();
    for file in files {
        let name = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_file(&name)
            || SKIPPED
                .iter()
                .any(|skip| name.starts_with(&format!("{skip}/")))
        {
            continue;
        }
        let source =
            std::fs::read_to_string(&file).map_err(|err| format!("{}: {err}", file.display()))?;
        let syntax = syn::parse_file(&source).map_err(|err| format!("{name}: {err}"))?;
        test_modules.extend(test_module_files(&name, &syntax));
        parsed.push((name, syntax));
    }
    let mut items: BTreeMap<String, Item> = BTreeMap::new();
    for (name, syntax) in parsed {
        if test_modules
            .iter()
            .any(|prefix| name == format!("{prefix}.rs") || name.starts_with(&format!("{prefix}/")))
        {
            continue;
        }
        for item in items_of(&name, &syntax) {
            match items.get_mut(&item.path) {
                Some(seen) => seen.values.extend(item.values),
                None => {
                    items.insert(item.path.clone(), item);
                }
            }
        }
    }
    Ok(items.into_values().collect())
}

/// The files of the out-of-line modules a file declares under `cfg(test)`, without `.rs`:
/// `crates/tun/src/lib.rs` declaring `mod testing;` gives `crates/tun/src/testing`.
fn test_module_files(file: &str, syntax: &syn::File) -> Vec<String> {
    let (dir, stem) = file.rsplit_once('/').unwrap_or(("", file));
    let stem = stem.strip_suffix(".rs").unwrap_or(stem);
    let dir = if matches!(stem, "lib" | "main" | "mod") {
        dir.to_string()
    } else {
        format!("{dir}/{stem}")
    };
    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.content.is_none() && test_only(&module.attrs) => {
                Some(format!("{dir}/{}", module.ident))
            }
            _ => None,
        })
        .collect()
}

pub(super) fn scan_source(file: &str, source: &str) -> Result<Vec<Item>, String> {
    let parsed = syn::parse_file(source).map_err(|err| format!("{file}: {err}"))?;
    Ok(items_of(file, &parsed))
}

fn items_of(file: &str, parsed: &syn::File) -> Vec<Item> {
    let mut finder = Finder {
        owner: vec![module_of(file)],
        locals: BTreeMap::new(),
        items: Vec::new(),
        file,
    };
    finder.visit_file(parsed);
    finder.items
}

struct Finder<'a> {
    owner: Vec<String>,
    locals: BTreeMap<String, Value>,
    items: Vec<Item>,
    file: &'a str,
}

impl Finder<'_> {
    fn record(&mut self, ident: &syn::Ident, ty: &syn::Type, expr: &syn::Expr) {
        if !is_gated_type(ty) {
            return;
        }
        let value = match (Eval {
            locals: &self.locals,
        })
        .quantity(expr)
        {
            Some(quantity) => Value::Known(quantity),
            None => Value::Text(source_text(expr.to_token_stream())),
        };
        self.locals
            .entry(ident.to_string())
            .or_insert_with(|| value.clone());
        let mut path = self.owner.clone();
        path.push(ident.to_string());
        let path = path.join("::");
        match self.items.iter_mut().find(|item| item.path == path) {
            Some(item) => item.values.push(value),
            None => self.items.push(Item {
                path,
                file: self.file.to_string(),
                line: ident.span().start().line,
                values: vec![value],
            }),
        }
    }

    fn nested<F: FnOnce(&mut Self)>(&mut self, name: String, inner: F) {
        self.owner.push(name);
        inner(self);
        self.owner.pop();
    }
}

impl<'ast> Visit<'ast> for Finder<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if test_only(&item.attrs) {
            return;
        }
        self.nested(item.ident.to_string(), |this| {
            visit::visit_item_mod(this, item)
        });
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if test_only(&item.attrs) {
            return;
        }
        self.nested(item.sig.ident.to_string(), |this| {
            visit::visit_item_fn(this, item)
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if test_only(&item.attrs) {
            return;
        }
        self.nested(item.sig.ident.to_string(), |this| {
            visit::visit_impl_item_fn(this, item);
        });
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if test_only(&item.attrs) {
            return;
        }
        let owner = leaf(&item.self_ty).unwrap_or_else(|| "impl".to_string());
        self.nested(owner, |this| visit::visit_item_impl(this, item));
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.nested(item.ident.to_string(), |this| {
            visit::visit_item_trait(this, item)
        });
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if test_only(&item.attrs) {
            return;
        }
        self.record(&item.ident, &item.ty, &item.expr);
        visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if test_only(&item.attrs) {
            return;
        }
        self.record(&item.ident, &item.ty, &item.expr);
        visit::visit_item_static(self, item);
    }

    fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
        if test_only(&item.attrs) {
            return;
        }
        self.record(&item.ident, &item.ty, &item.expr);
        visit::visit_impl_item_const(self, item);
    }

    fn visit_trait_item_const(&mut self, item: &'ast syn::TraitItemConst) {
        if let Some((_, expr)) = &item.default {
            self.record(&item.ident, &item.ty, expr);
        }
        visit::visit_trait_item_const(self, item);
    }
}

/// Whether the attributes compile the item only for tests: `#[test]`, or a `cfg` that needs
/// `test` or the `testing` feature. `any(test, windows)` does not.
fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let path = attr.path();
        if path.is_ident("cfg") {
            attr.parse_args::<syn::Meta>()
                .is_ok_and(|meta| needs_test(&meta))
        } else {
            path.segments
                .last()
                .is_some_and(|last| last.ident == "test")
        }
    })
}

fn needs_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::NameValue(pair) => {
            pair.path.is_ident("feature")
                && matches!(&pair.value, syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) if s.value() == "testing")
        }
        syn::Meta::List(list) => {
            let Ok(inner) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return false;
            };
            if list.path.is_ident("all") {
                inner.iter().any(needs_test)
            } else if list.path.is_ident("any") {
                !inner.is_empty() && inner.iter().all(needs_test)
            } else {
                false
            }
        }
    }
}
