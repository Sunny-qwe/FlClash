# Commands

Run everything from the workspace root. `cargo xtask` is an alias for `cargo run -p xtask --` (`.cargo/config.toml`).

## Build

```sh
cargo build --release -p concord-desktop   # target/release/concord
```

Release uses fat LTO over BoringSSL and aws-lc and takes minutes; build it only when the release binary is what you
need (size, speed, a bench). Android's `libconcord.so` is built by FlClash's `cargoCore` Gradle task with the NDK
environment it sets up; the variables a host sets are in `embedding.md`.

Windows compiles BoringSSL from source with CMake, the MSVC build tools and LLVM (`libclang` for bindgen), plus NASM
for `x86_64-pc-windows-msvc`, or `clang-cl` and Ninja for `aarch64-pc-windows-msvc` (its assembly is `.S`, which the
Visual Studio generator cannot build). `.cargo/config.toml` points `boring-sys` at `cmake/boring-*-windows.cmake`,
so run cargo from the workspace root. Do not set `OPENSSL_NO_ASM` or your own `CMAKE_TOOLCHAIN_FILE`: without
assembly AES-GCM is about 150 times slower, and BoringSSL sees no AES hardware and offers ChaCha20 first, unlike a
browser. `BUILD_TESTING` is off because BoringSSL's benchmark feature check fails under `/W4 /WX` once `cmake-rs`
drops `/EHsc`.

## The Full Gate

A change is done when all of these pass. `.github/workflows/ci.yaml` runs them on Linux with `--locked` and then
fails if they changed a tracked file; it also runs clippy and the tests on macOS, and clippy for Android and Windows
(the Windows job does not fail the run yet). Run the clippy of every platform whose code the change touches.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xtask check-layers
cargo xtask schema --check
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml
cargo build --release -p concord-desktop
cargo xtask check-size target/release/concord <bytes>   # CI's CORE_MAX_BYTES
```

- `cargo test --workspace` also runs xtask's source checks: `stream_policy` holds every `Stream` wrapper to its
  declared capability policy (`rules.md`, Layering And Ownership); `vendor_patches` holds `vendor/` to the files
  `vendor/PATCHES.md` lists, by the hashes in `vendor/UPSTREAM.sha256`; `reference_choices` holds each choice in
  `reference-choices.md` to its Entry Shape; `unsafe_policy` holds `allow(unsafe_code)` to the crates and files
  `rules.md` names and every member to `[lints] workspace = true`; `ratchets` holds file and function sizes and `Result<_, String>` counts to `xtask/ratchets.txt`.
  `tunables` holds every numeric or `Duration` `const` and `static` to a row with its basis in `reference-choices.md`
  "Tunables", a wire or format line there, or `xtask/tunables.txt` (`rules.md`, Tunables); after adding or changing
  one, `cargo test -p xtask tunables::tests::list_unregistered -- --ignored --nocapture` prints what is missing.
  After a change that moves one, `cargo test -p xtask ratchets::tests::regenerate -- --ignored` rewrites the file,
  keeping raise notes and marking a new growth `raised from <old>: ?` for you to replace with the reason.
- `cargo xtask schema` rewrites `schema/config-schema.json` and `schema/api.json`; commit them with the change.
- A change to config parsing that changes output: `CONCORD_BLESS=1 cargo test -p concord-config --test golden`
  rewrites the golden files, and the diff is reviewed like code.
- Clippy for Android (`--target aarch64-linux-android`) runs with `-A clippy::missing_const_for_thread_local`. On
  that target the lint fires on two `thread_local!` statics whose initializer is already `const { … }`
  (`crates/common/src/packet.rs:13`, `crates/common/src/stream_buffer.rs:15`); other targets do not report them.
- `#[ignore]`d tests need an external peer named by an environment variable. An interop test run without its peer
  fails rather than passing silently. mihomo's Snell listener can lose a frame when its peek deadline falls between
  the two reads of that frame, so the Snell interop cases retry TCP once. Run the ones a change touches, for example
  `CONCORD_MIHOMO=<mihomo> cargo test -p concord-proxy --test interop -- --ignored`.

  | Variable | Peer |
  |---|---|
  | `CONCORD_MIHOMO` | An upstream mihomo binary, for protocol interop |
  | `CONCORD_WGSERVER` | A WireGuard test server |
  | `CONCORD_SSHD`, `CONCORD_SSH_KEYGEN` | OpenSSH |
  | `CONCORD_SSRCLIENT` | A ShadowsocksR test client |
  | `CONCORD_HY1_SERVER` | A Hysteria v1 server |
  | `CONCORD_LARGE_PROFILE` | A large YAML profile; reports heap per stage |

- `fuzz/` is a separate workspace of libFuzzer targets for config parsing, profile loading, share links, rule
  parsing and, as `tls_record_read`, the read side of the TLS record engine (`concord_tls::fuzzing`, behind the
  crate's `fuzzing` feature). With nightly and `cargo-fuzz` they build as usual; point `CARGO_TARGET_DIR` at the
  main `target`. It depends on `libfuzzer-sys`, which is partly `NCSA`-licensed, so `cargo deny` does not check it.
  Only `tls_record_read` has been run, 31 minutes on the Linux VM; the others are compiled only. It was built on
  the pinned stable toolchain, with coverage instrumentation and no sanitizer:

  ```sh
  RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
    -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
    -Cllvm-args=-sanitizer-coverage-trace-compares -Cdebug-assertions -Coverflow-checks -Ccodegen-units=1" \
    cargo build --manifest-path fuzz/Cargo.toml --release --target aarch64-unknown-linux-gnu --bin tls_record_read
  ```

  The explicit `--target` keeps the flags off build scripts. `--cfg fuzzing` is left out: it compiles the vendored
  h2's `fuzz_bridge`, which fails that crate's `missing_docs` lint.
- `deny.toml`'s advisory exceptions each carry the reason the advisory does not reach Concord; keep that true when
  adding one.
- When a check cannot run (no `cargo-deny`, no peer binary, no Windows), say which and why instead of dropping it.

## Benchmarks

```sh
cargo xtask bench --quick --base <ref before the change> --mihomo <mihomo>   # while changing code
cargo xtask bench --full  --base <ref before the change> --mihomo <mihomo>   # only when the user asks
```

The quick tier is the SOCKS part of the representative set (`direct`, `ss-aes128`, `trojan-tls`, `vmess-grpc-tls`,
`hysteria2`; `performance.md` has the rest); the full tier covers every case and workload. The tier lists live in
`tools/bench/src/plan.rs` so a tier always measures the same thing. `--only`, `--workloads`, `--rounds` and `--secs`
narrow or tighten a run; `concord-bench list` prints cases, workloads and tiers;
`concord-bench compare <base.json> <new.json>` compares two runs. Use an upstream mihomo build; a fork that leaves listeners to its host app cannot serve.
Running it, Windows and Android: `.agents/benchmarking.md`. What a result must show and the pitfalls:
`.agents/performance.md`.

Run nothing else on the machine while a bench measures, and a full run only on a quiet host.

## Target Directory And Disk

- One target directory per checkout: the workspace's own `target/`. Never share one `CARGO_TARGET_DIR` between two
  Concord checkouts, worktrees or extracted trees: cargo can reuse the other tree's artifacts, and the binary you
  measure is then not the code you think. `xtask bench --base` builds the base into `target/bench/rev-target` for
  this reason. A baseline in another worktree gets its own target, deleted when the comparison is done.
- Do not give each crate or each agent its own target inside one checkout either; that multiplies a tree that already
  passes 10 GB.
- Keep debug builds small: `CARGO_INCREMENTAL=0` and `CARGO_PROFILE_DEV_DEBUG=line-tables-only`.
- Check `du -sh target` before and after a round. After a round of tests, `target/debug/deps` keeps many hashed copies
  of the same crate; keep the two most recent per crate and delete the rest, and clear `target/debug/incremental`.
  First check that no one else is building in this checkout (`pgrep -f "cargo (test|build|clippy|check)"`).
- Keep that target warm between builds, also on a measurement VM: prune hashes no recent build used rather than
  deleting the tree. Delete the whole target when the toolchain changes or the disk is short.
- Delete scratch worktrees, extracted trees and probe binaries when they are no longer needed, and stop any process you
  started by its pid.
- Errors that name a symbol the source plainly has (stale metadata after parallel edits in one target): confirm the
  tree is clean, `find crates -name '*.rs' -exec touch {} +`, and rebuild. `cargo clean -p` on one crate is not enough.
  Any test or bench result taken in that state is rerun.
