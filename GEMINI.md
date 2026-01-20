# Ixodes Project Context

## Overview
Ixodes is a dual-component project consisting of a Rust-based data recovery agent (`ixodes`) and a Tauri-based GUI builder (`ixodes-gui`). The agent is designed to extract sensitive information (browsers, wallets, messengers, system data) from Windows environments, while the GUI provides a user-friendly interface to configure and compile the agent.

## Directory Structure

### `ixodes/` (The Agent)
A Rust application acting as the core data extraction engine.
*   **Type:** Rust Binary (Windows target)
*   **Key Files:**
    *   `src/main.rs`: Entry point; initializes logging, context, and the recovery manager.
    *   `src/recovery/manager.rs`: Orchestrates various recovery tasks.
    *   `src/recovery/`: Contains modules for specific data targets (e.g., `browser`, `wallet`, `gaming`, `communication`).
    *   `Cargo.toml`: Manages dependencies (`tokio`, `rusqlite`, `reqwest`, `nokhwa`, etc.) and build profiles.

### `ixodes-gui/` (The Builder)
A SvelteKit + Tauri v2 application for configuring and building the agent.
*   **Type:** Desktop Application (Tauri)
*   **Stack:** Svelte 5, Tailwind CSS v4, TypeScript.
*   **Key Files:**
    *   `src-tauri/tauri.conf.json`: Tauri configuration (app name, windows, permissions).
    *   `src-tauri/src/lib.rs`: Rust backend for the GUI, likely handling the compilation of the `ixodes` agent.
    *   `package.json`: Frontend dependencies and scripts.

## Development & Usage

### Building the Agent (`ixodes`)
The agent is a standard Rust project but relies on specific environment variables or generated configuration (handled by the GUI builder).

*   **Build (Release):** `cargo build --release`
    *   *Note:* The release profile is optimized for size (`opt-level = "z"`, `strip = true`, `lto = true`).
*   **Test:** `cargo test`

### Developing the Builder (`ixodes-gui`)
Uses `bun` (recommended) or `npm`/`pnpm` for package management.

*   **Install Dependencies:** `bun install`
*   **Run Development Server:** `bun run tauri dev`
    *   This launches the GUI and the backend simultaneously.
*   **Build Application:** `bun run tauri build`

## Key Conventions
*   **Agent Configuration:** The `ixodes` agent appears to be configurable at compile-time (via `build.rs` or generated `settings.rs`) to enable/disable specific recovery modules (e.g., "Browsers", "Wallets").
*   **Output:** The agent produces structured logs and artifacts, typically saved to a local `target/` directory or exfiltrated via configured senders (Discord/Telegram).
*   **Windows-Centric:** The agent has explicit Windows dependencies (`winreg`, `ntapi`, `windows` crate features).

## Common Tasks
*   **Adding a Recovery Module:** Create a new module in `ixodes/src/recovery/`, implement the task logic, and register it in `manager.rs`.
*   **Updating the GUI:** Modify Svelte components in `ixodes-gui/src/routes/` and update the Rust backend in `ixodes-gui/src-tauri/src/lib.rs` if new configuration options are needed.
