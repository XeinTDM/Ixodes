# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Rust entry point in `main.rs` plus the `recovery` module tree handling contexts, managers, and task definitions for browsers, services, wallets, VPN, etc.
- `src/recovery/`: split by domain (e.g., `gecko.rs`, `messenger.rs`, `services.rs`) with `mod.rs` re-exporting helpers, keeping each task self-contained.
- `Cargo.toml`: single binary crate named `ixodes`; update dependencies here and run `cargo update` with care.
- `target/`: generated Rust artifacts; treat as build output only and never edit files inside.

## Build, Test, and Development Commands
- `cargo build`: compiles the binary for fast iteration.
- `cargo build --release`: produce an optimized executable intended for release.
- `cargo run`: execute the CLI with the current workspace configuration (adds instrumentation you can log).
- `cargo fmt`: format Rust code to the standard; run before committing.
- `cargo clippy`: static analysis to catch common mistakes.
- `cargo test`: run unit/integration tests covering `RecoveryManager` and helpers.
- `cargo check`: fast type check without building, useful for CI or quick validation.

## Coding Style & Naming Conventions
- Follow Rust edition 2024 idioms: snake_case for functions and modules, PascalCase for structs/enums, and SCREAMING_SNAKE for constants.
- Keep module files focused (one task or helper) and prefer small helper functions inside `helpers/` submodules.
- Document public structures using `///` comments describing intent (especially for recovery contexts/tasks).
- Avoid `unwrap` in favor of `?`/`Result` with context; `thiserror`-based errors live in `recovery::task`.

## Testing Guidelines
- Tests should live next to the code they validate (e.g., `mod tests` inside `recovery/services.rs`) and target behaviors through `RecoveryManager` runs.
- Cover error paths by mocking with `RecoveryContext::discover` when possible (use `#[cfg(test)]` helpers in `helpers`).
- Always run `cargo test` after touching logic that alters task registration or I/O paths.

## Commit & Pull Request Guidelines
- Use imperative commit messages (e.g., `Add FTP recovery task`). Conventional commits are preferred but not enforced on this new repo.
- PRs require a concise summary, testing steps (`cargo test`, `cargo clippy`), and any relevant logs or generated artifacts.
- Include before/after behavior notes when changing recovery coverage or logging levels.

## Security & Configuration Tips
- Secrets (passwords, tokens, certificates) must never be committed; store them externally and load via environment variables when needed.
- Windows-specific APIs reside under `recovery::helpers`; keep low-level bindings confined there to simplify future audit.
