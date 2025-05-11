# smbsh-rs

A fast, concurrent SMB share scanner written in Rust.

## Features

- **Fast scanning**: Uses asynchronous Rust for high-performance network scanning
- **Concurrent operation**: Configurable number of workers for parallel scanning
- **Flexible targeting**: Scan individual hosts, CIDR ranges, or lists from files
- **Authentication support**: Optional username, password, and domain parameters
- **Detailed output**: Shows share name, permissions, and comments

## Installation

### Prerequisites

- Rust and Cargo (https://www.rust-lang.org/tools/install)

### Building from source

```bash
git clone https://github.com/yourusername/smbsh-rs.git
cd smbsh-rs
cargo build --release
```

The compiled binary will be available at `target/release/smbsh-rs`

## Usage

```
smbsh-rs [OPTIONS] <TARGET>
```

### Arguments

- `<TARGET>`: Target specification: a single IP, CIDR range (e.g., 192.168.1.0/24), or a file containing a list of targets

### Options

- `-u, --username <USERNAME>`: Username for SMB authentication
- `-p, --password <PASSWORD>`: Password for SMB authentication
- `-d, --domain <DOMAIN>`: Domain for SMB authentication
- `-w, --workers <WORKERS>`: Number of concurrent workers (default: 10)
- `-t, --timeout <TIMEOUT>`: Connection timeout in seconds (default: 3)
- `-h, --help`: Print help information

## Examples

### Scan a single host

```bash
smbsh-rs 192.168.1.10
```

### Scan a network range with authentication

```bash
smbsh-rs 192.168.1.0/24 -u administrator -p Password123
```

### Scan hosts from a file with increased timeout and workers

```bash
smbsh-rs targets.txt -t 5 -w 100
```

## Example Output

```
SMB Share Scanner
Workers: 128
Target(s): 192.168.99.0/24 (256 hosts)
["192.168.99.21", "192.168.99.20"]

PROTO  IP/HOST         PORT  HOSTNAME        SHARE                PERMISSIONS  COMMENTS
------------------------------------------------------------------------------------------
SMB    192.168.99.21   445   UBUNTU          ADMIN$               RW           Remote Admin
SMB    192.168.99.21   445   UBUNTU          C$                   RW           Default share
SMB    192.168.99.21   445   UBUNTU          IPC$                 RW           Remote IPC
SMB    192.168.99.21   445   UBUNTU          SHARE                RW           Howdy!
SMB    192.168.99.20   445   UBUNTU          ADMIN$               RW           Remote Admin
SMB    192.168.99.20   445   UBUNTU          C$                   RW           Default share
SMB    192.168.99.20   445   UBUNTU          IPC$                 RW           Remote IPC
SMB    192.168.99.20   445   UBUNTU          NETLOGON             RW           Logon server share 
SMB    192.168.99.20   445   UBUNTU          SYSVOL               RW           Logon server share 

Scan complete!
```

## How It Works

The scanner works by:
1. Parsing the target input (IP, CIDR, or file)
2. Checking which hosts are alive on port 445 (SMB)
3. Attempting to connect to each alive host using provided credentials
4. Enumerating available shares and their permissions
5. Displaying results in a formatted table

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is provided for legitimate security testing and network administration only. Always ensure you have proper authorization before scanning any systems or networks.
