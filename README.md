## Intrusion Detection System

##### How to run (Ubuntu Linux)
- Clone repo into your local machine
- Must have libpcap-dev in your machine for packet capture
- Navigate into 'ids' folder
- Set log level to 'debug' using this command: 'export RUST_LOG=debug'
- Run ids with this command: sudo -E RUSTUP_HOME=$HOME/.rustup CARGO_HOME=$HOME/.cargo /path/to/.cargo/bin/cargo run
- Watch the ids go!

##### Rust Crates IDS uses:
- etherparse v0.13
- serde v1.0
- serde_json v1.0
- log v0.4
- env_logger v0.10
- pcap v1.1
- chrono v0.4.40
- lazy_static v1.4
- ctrlc v3.2.0
