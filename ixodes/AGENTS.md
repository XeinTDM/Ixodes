# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Rust entry point in `main.rs` plus the `recovery` module tree handling contexts, managers, and task definitions for browsers, services, wallets, VPN, etc.
- `src/recovery/`: split by domain (e.g., `gecko.rs`, `messenger.rs`, `services.rs`) with `mod.rs` re-exporting helpers, keeping each task self-contained.
- `Cargo.toml`: single binary crate named `ixodes`; update dependencies here and run `cargo update` with care.
- `target/`: generated Rust artifacts; treat as build output only and never edit files inside.

## Architecture: Stub + Config
Ixodes uses a "Stub + Config" architecture to avoid recompiling the agent for every build.
1.  **Stub:** The `ixodes` binary is compiled once (usually via CI or manual release build). It contains the core logic (recovery modules, evasion, sender).
2.  **Config:** The `ixodes-gui` builder generates a JSON configuration (`LoaderConfig`), encrypts it (XOR with static key), and appends it to the end of the `ixodes` stub binary.
3.  **Runtime:** At startup, the agent reads its own binary file, locates the appended config (delimited by `::IXODES_CONFIG::`), decrypts it, and initializes `RecoveryControl`.
4.  If no config is found (e.g., during development `cargo run`), it falls back to environment variables or compile-time defaults.

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