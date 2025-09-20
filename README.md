# RustWarden
An IDS/IPS system implemented in Rust. Real time packet sniffing and anomaly detection.

## Usage
`RustWarden <COMMAND>`
Current commands: List, Dump

### List Command
`RustWarden {list|-l}`
List out network interfaces to bind to

### Dump
`RustWarden {dump|-d} [Network Interface]`
Dump packet info to console for selected network interface