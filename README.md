# IdaraSYN - High-Speed TCP SYN Port Scanner

Production-grade TCP SYN port scanner with stealth features and banner grabbing capabilities.

## Features

- **TCP SYN Scanning**: Half-open scanning using raw sockets for stealth
- **Asynchronous Architecture**: Built with Tokio for high-performance async packet transmission
- **Stealth Capabilities**:
  - Random port order to evade pattern detection
  - Configurable jitter between packet bursts
  - Rate limiting to avoid network congestion
- **Banner Grabbing**: Full TCP handshake for service identification
- **Modular Design**: Separate modules for packet construction, scanning, listening, and probing
- **JSON Output**: Integration-ready output format
- **Cross-Platform**: Supports both Unix/Linux and Windows

## Architecture

```
src/
├── cli.rs            - Command-line interface
├── packet_factory.rs - IPv4/TCP packet construction
├── scanner.rs        - SYN packet transmission
├── listener.rs       - Response capture and filtering
├── prober.rs         - Banner grabbing
├── utils.rs          - Network interface detection, privilege checking
└── main.rs           - Application orchestration
```

## Dependencies

- `pnet` - Low-level packet construction
- `tokio` - Async runtime
- `clap` - CLI argument parsing
- `socket2` - Raw socket handling
- `anyhow` - Error handling
- `serde/serde_json` - JSON serialization

## Prerequisites

**Linux/Unix**:
- Root privileges or `CAP_NET_RAW` capability
- Run with `sudo`

**Windows**:
- Administrator privileges
- WinPcap or Npcap installed for packet capture

## Build

```bash
cargo build --release
```

The optimized binary will be located at `target/release/idarasyn` (or `idarasyn.exe` on Windows).

## Usage

### Basic Scan
```bash
sudo ./idarasyn 192.168.1.1 --ports 1-1000
```

### Custom Port Range
```bash
sudo ./idarasyn 10.0.0.5 --ports 80,443,8080,8443
```

### With Banner Grabbing
```bash
sudo ./idarasyn 192.168.1.100 --ports 1-1000 --banner-grab
```

### JSON Output
```bash
sudo ./idarasyn 192.168.1.1 --ports 1-65535 --json > scan_results.json
```

### Full Options
```bash
sudo ./idarasyn <TARGET_IP> \
  --ports <RANGE>           # Port range (default: 1-1000)
  --interface <NAME>        # Network interface (auto-detected if omitted)
  --source-port <PORT>      # Source port for scanning (default: 50000)
  --rate-limit <NUM>        # Packets per burst (default: 100)
  --jitter <MS>             # Max jitter between bursts (default: 50)
  --timeout <SECS>          # Response timeout (default: 10)
  --banner-grab             # Enable banner grabbing
  --banner-timeout <SECS>   # Banner grab timeout (default: 3)
  --json                    # Output in JSON format
```

## How It Works

1. **Setup**: Detects network interface and checks privileges
2. **Listener Thread**: Spawns background thread to capture TCP responses
3. **Packet Transmission**: Sends randomized SYN packets with rate limiting
4. **Response Processing**: Filters SYN-ACK (open) and RST (closed) packets
5. **Banner Grabbing** (optional): Performs full TCP handshake to identify services
6. **Output**: Displays results in human-readable or JSON format

## Security Considerations

- **Authorization**: Only scan networks and systems you have permission to test
- **Legal Compliance**: Unauthorized port scanning may violate laws and regulations
- **Network Impact**: High scan rates may trigger IDS/IPS systems or cause network issues
- **Ethical Use**: This tool is for security professionals, penetration testers, and network administrators

## Limitations

- Requires raw socket privileges
- May be detected by modern IDS/IPS systems
- Banner grabbing increases scan time and visibility
- Some firewalls may filter SYN packets

## License

For authorized security testing and network administration only.
