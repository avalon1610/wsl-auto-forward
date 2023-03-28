# wsl-auto-forward

## wsl-auto-forward - A tool that can automatically forward local TCP requests to WSL2

### Why another tool
- Accessing WSL2 via localhost occasionally fails
- Windows portproxy: need manually setup forwarding port

### Installation

use cargo (need **nightly**)
```rust
cargo +nightly install wsl-auto-forward
```

or download from Release

### Features
- Auto detect WSL2 listening port changes, and apply forwarding
    - only detect ports bound to 0.0.0.0
    - detecting interval can be set
- Fixed port forwarding

