#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

pub mod cidr_set;
mod compile;
pub mod domain_set;
pub mod error;
mod eval;
pub mod geo;
mod index;
mod kind;
pub mod mrs;
mod observed;
mod payload;
mod prog;
mod program;
mod ruleset;
mod run;
mod runs;
mod table;
mod text;

pub use kind::RuleKind;
pub use observed::Observed;
pub use program::{
    CompileEnv, CompileError, Cond, Demands, MatchCtx, RouteProgram, RuleDef, RuleInfo, RuleRef,
    Step,
};
pub use ruleset::{
    Behavior, CompileSetError, CompiledRuleSet, Format, GeoFault, ParsedRuleSet, RuleSet,
    RuleSetError, RuleSetHandle, RuleSetStore, SetInfo, compile_rule_set, dump_mrs,
};
pub use run::Run;

#[cfg(test)]
mod bench;
#[cfg(test)]
mod differential;
#[cfg(test)]
mod program_tests;
#[cfg(test)]
mod testkit;
