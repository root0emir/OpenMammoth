# OpenMammoth Network Protection Toolkit

A powerful and comprehensive network protection tool designed to safeguard your systems against various types of cyber attacks.

## Features

- **Advanced Attack Detection**
  - Port scanning detection
  - SYN flood protection
  - UDP flood protection
  - ICMP flood protection
  - Fragment attack detection
  - Malformed packet detection
  - Rate limiting
  - Geo-location based blocking
  - VPN/TOR detection
  - Botnet activity detection
  - Malware signature detection
  - Exploit attempt detection
  - Zero-day attack detection

- **Multiple Protection Levels**
  - Level 1: Basic protection
  - Level 2: Standard protection
  - Level 3: Enhanced protection
  - Level 4: Extreme protection

- **Performance Optimizations**
  - Multi-threading support
  - Batch processing
  - Connection pooling
  - Memory optimization
  - Thread-safe operations

- **Customization**
  - Custom rule support
  - Configurable thresholds
  - Flexible blocking policies
  - Customizable logging

## Requirements

- Linux operating system
- Root privileges
- libpcap development library
- pthread library
- C compiler (gcc recommended)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/root0emir/OpenMammoth.git
cd openmammoth
```

2. Compile the source code:
```bash
make
```

3. Install the binary:
```bash
sudo make install
```

## Usage

Basic usage:
```bash
sudo openmammoth -i eth0 -l 3 -a 1
```

Command line options:
```
-h, --help           Display help menu
-i, --interface      Specify network interface (default: eth0)
-l, --level         Protection level (1-4)
-a, --advanced      Advanced protection (0/1)
-d, --debug         Debug mode
-c, --config        Configuration file
-r, --rules         Custom rules file
-s, --stats         Show statistics
-b, --blocked       Show blocked IPs
-v, --version       Show version information
```

## Configuration

The tool can be configured using a JSON configuration file. Example configuration:
```json
{
    "protection_level": 3,
    "advanced_protection": true,
    "debug_mode": false,
    "block_duration": 3600,
    "max_connections": 100000,
    "thresholds": {
        "port_scan": 100,
        "syn_flood": 1000,
        "udp_flood": 1000,
        "icmp_flood": 1000
    }
}
```

## Custom Rules

Custom rules can be defined in a rules file. Example rules:
```
# Block IPs from specific countries
RULE geo_block
PATTERN country_code=RU,CN,KP
ACTION block

# Block suspicious traffic patterns
RULE suspicious_traffic
PATTERN packet_size>1500 AND rate>1000
ACTION block
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GPL v3 License - see the LICENSE file for details.

## Author

- Emir(root0emir)
- GitHub: [https://github.com/root0emir](https://github.com/root0emir)

## Acknowledgments

- libpcap team for packet capture library
- Open source community for inspiration and support 
