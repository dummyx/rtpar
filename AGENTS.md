# Repository Guidelines

## Project Structure & Module Organization
- `src/lib.rs`: Library entry; re-exports public APIs.
- `src/rtp.rs`: RTP header/packet parsing.
- `src/codecs/`: RTP payload parsers
  - `avc.rs` (H.264), `hevc.rs` (H.265), `vp9.rs`, `av1.rs`.
- `src/analyze.rs`: Frame boundary analyzer.
- `src/reassemble.rs`: Frame reassembler with reordering/gap handling.
- `src/guess.rs`: Codec guessing heuristics.
- Tests live alongside code in `#[cfg(test)]` modules.

## Build, Test, and Development Commands
- Build: `cargo build` — compiles the library.
- Test: `cargo test` — runs all unit tests.
  - Run a single test: `cargo test rtp::tests::parse_basic_packet`.
- Format: `cargo fmt --all` — applies rustfmt.
- Lint: `cargo clippy --no-deps` — lints without external deps noise.

## Coding Style & Naming Conventions
- Rust 2021 edition; rustfmt default style (4-space indents).
- Naming: `lower_snake_case` (functions/modules), `UpperCamelCase` (types), `SCREAMING_SNAKE_CASE` (consts).
- Prefer explicit, descriptive names; avoid one-letter identifiers.
- Public APIs should have `///` doc comments.

## Testing Guidelines
- Write tests first (TDD) when adding features or fixing bugs.
- Co-locate unit tests within the module under `#[cfg(test)]`.
- Keep tests deterministic and focused; cover edge cases (padding, header extensions, FU start/end, aggregation packets, descriptor fields).
- Always run: `cargo fmt`, `cargo clippy`, then `cargo test` before opening PRs.

## Commit & Pull Request Guidelines
- Commits: imperative mood, concise scope. Conventional Commits encouraged (e.g., `feat: add HEVC AP parsing`, `fix: handle RTP padding bounds`).
- PRs should include:
  - Summary of change and rationale
  - Linked issue (if any)
  - Tests demonstrating the behavior
  - Note that `cargo fmt`, `clippy`, and tests were run

## Agent-Specific Instructions
- Keep changes minimal and targeted; do not fix unrelated issues.
- Respect module layout and naming; prefer extending existing modules over creating new ones.
- Use `apply_patch` to edit files; reference paths precisely.
- Validate locally with `cargo fmt`, `cargo clippy`, and `cargo test` before yielding.
