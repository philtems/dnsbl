# DNSBL Server v2.5.0

A complete multi-zone DNSBL (DNS Blackhole List) server with NS/SOA record support, real-time DNSBL forwarding, and advanced logging.

## Features

- **Multi-zone support**: Handle multiple DNSBL domains simultaneously
- **Self-referential queries**: Responds to A/NS/SOA queries on the domain itself
- **DNSBL forwarding**: Query remote DNSBLs in real-time (`dnsbl://`)
- **Automatic NS discovery**: Find authoritative servers of remote DNSBLs
- **Intelligent caching**: Cache DNSBL query results (5 minutes)
- **Round-robin rotation**: Distribute queries among NS servers
- **Rate limiting**: Limit queries per IP address
- **Dual logging**: Application logs and dedicated query logs
- **Auto-reload**: Periodically reload source files
- **HTTP/HTTPS support**: Download blocklists from URLs
- **Daemon mode**: Run as a background service

## Installation

### Prerequisites

- Rust (2021 edition)
- Cargo

### Build

git clone "https://github.com/philtems/dnsbl.git"
cd dnsbl
cargo build --release

The binary will be at `target/release/dnsbl-server`

## Usage

### Basic Syntax

dnsbl-server [OPTIONS]

### Options

| Option | Description |
|--------|-------------|
| `-D, --domain <DOMAIN>` | DNSBL domain (can be multiple) |
| `-r, --response <IP>` | Response IP for blocked IPs |
| `-s, --self-ip <IP>` | IP for queries on the domain itself |
| `-f, --file <SOURCE>` | Blocklist source (file, URL, or dnsbl://) |
| `-F, --file-list <FILE>` | File containing one source per line |
| `-R, --reload <MINUTES>` | Reload interval (0 = disabled) |
| `--max-requests <COUNT>` | Max requests per minute per IP (0 = unlimited) |
| `--no-request-limit <IP,RANGE>` | IPs/ranges exempt from rate limiting |
| `--stats-interval <SECONDS>` | Statistics logging interval (0 = disabled) |
| `--query-log <FILE>` | Query log file |
| `-d, --daemon` | Daemon mode |
| `-i, --interface <INTERFACE>` | Listening interface (default: 0.0.0.0:53) |
| `-v, --verbose` | Verbose mode |
| `-l, --log <LOG_FILE>` | Application log file |

### Source Types

#### Local Files

-f /path/to/blocklist.txt

#### HTTP/HTTPS URLs

-f http://example.com/blocklist.txt
-f https://example.com/blocklist.txt

#### Remote DNSBLs (real-time forwarding)

-f dnsbl://zen.spamhaus.org
-f dnsbl://b.barracudacentral.org

#### Multi-source File

-F sources.txt

Example sources.txt:
# Local list
/var/lib/dnsbl/local.list
# URLs
http://www.example.com/blocklist.txt
https://another.org/blacklist.txt
# Remote DNSBLs
dnsbl://zen.spamhaus.org
dnsbl://b.barracudacentral.org

## Examples

### Basic Single-Zone Server

dnsbl-server -D bl.example.com -r 127.0.0.2 -s 192.168.1.100 -f /etc/dnsbl/blocklist.txt

### Multi-Zone with Different Sources

dnsbl-server \
  -D bl1.example.com -r 127.0.0.2 -s 192.168.1.100 -f /etc/dnsbl/list1.txt \
  -D bl2.example.com -r 127.0.0.3 -s 192.168.1.100 -f /etc/dnsbl/list2.txt

### With DNSBL Forwarding and Logging

dnsbl-server \
  -D bl.example.com \
  -r 127.0.0.2 \
  -s 192.168.1.100 \
  -f dnsbl://zen.spamhaus.org \
  -f /etc/dnsbl/local.list \
  --query-log /var/log/dnsbl-queries.log \
  -l /var/log/dnsbl.log \
  -v

### Daemon Mode with Rate Limiting

dnsbl-server \
  -D bl.example.com \
  -r 127.0.0.2 \
  -s 192.168.1.100 \
  -f dnsbl://zen.spamhaus.org \
  --max-requests 100 \
  --no-request-limit 192.168.1.0/24,10.0.0.1 \
  -d \
  -l /var/log/dnsbl.log

## Architecture

### How It Works

1. **DNS query reception** on port 53 (or custom port)
2. **Parsing** to extract domain and query type
3. **Detection** of self-domain queries (A/NS/SOA)
4. **IP extraction** from subdomain (reverse format)
5. **Checking**:
   - Local lists (IPs and CIDR ranges)
   - Remote DNSBLs (via forwarding)
6. **Response**:
   - Configured IP if blocked
   - NXDOMAIN if not blocked
   - Self-IP for domain queries

### DNSBL Forwarding

For remote DNSBLs like zen.spamhaus.org:

1. **NS discovery**: Query public resolvers for NS records of the remote DNSBL
2. **Resolution**: Resolve NS names to IP addresses
3. **Caching**: Cache NS servers for 1 hour
4. **Query**: For each IP to check, query an NS server directly (round-robin)
5. **Result caching**: Cache results for 5 minutes

## Testing

### With dig

Test A record (blocked IP):
dig @127.0.0.1 -p 5453 2.0.0.127.bl.example.com A

Test A record (unblocked IP):
dig @127.0.0.1 -p 5453 1.2.3.4.bl.example.com A

Test NS record on domain:
dig @127.0.0.1 -p 5453 bl.example.com NS

Test A record on domain:
dig @127.0.0.1 -p 5453 bl.example.com A

Test SOA record:
dig @127.0.0.1 -p 5453 bl.example.com SOA

### Test Script

#!/bin/bash

SERVER="127.0.0.1"
PORT="5453"
DOMAIN="bl.example.com"

echo "=== DNSBL Server Test ==="
echo

echo "1. Self-domain A query:"
dig @$SERVER -p $PORT $DOMAIN A +short

echo "2. Self-domain NS query:"
dig @$SERVER -p $PORT $DOMAIN NS +noall +answer

echo "3. Blocked IP (127.0.0.2):"
dig @$SERVER -p $PORT 2.0.0.127.$DOMAIN A +short

echo "4. Unblocked IP:"
dig @$SERVER -p $PORT 1.2.3.4.$DOMAIN A +short

## Logging

### Application Log

Format: `[timestamp][LEVEL] message`

Example:
[2026-02-20 14:50:20][INFO] DNSBL server v2.5.0 started on 127.0.0.1:5453
[2026-02-20 14:50:20][INFO] Zone: bl.example.com -> 127.0.0.2 (self: 192.168.1.100, 2 sources, 1 DNSBL forwarders)
[2026-02-20 14:50:33][INFO] [bl.example.com] Blocked IP: 127.0.0.2 (domain: 2.0.0.127.bl.example.com from 127.0.0.1)

### Query Log (--query-log)

Format: `[timestamp] source_ip domain type status`

Example:
[2026-02-20 14:50:33] 127.0.0.1 2.0.0.127.bl.example.com A BLOCKED 127.0.0.2
[2026-02-20 14:50:34] 127.0.0.1 1.2.3.4.bl.example.com A NOT_BLOCKED
[2026-02-20 14:50:35] 127.0.0.1 bl.example.com A NOT_BLOCKED
[2026-02-20 14:50:36] 127.0.0.1 bl.example.com NS NOT_BLOCKED

## Troubleshooting

### Server Not Responding

Check if port 53 is already in use:
sudo netstat -tulpn | grep :53

### Remote DNSBLs Not Working

Enable verbose mode to see NS discovery logs:
dnsbl-server -v -D bl.example.com -f dnsbl://zen.spamhaus.org ...

Look for in logs:
- Found NS servers - discovery successful
- Failed to discover NS servers - discovery failed

### NOTIMP Responses

Check if query type is supported (A for subdomains, A/NS/SOA for domain).

### Permission Issues

To listen on privileged port 53:
sudo ./dnsbl-server ...

Or use a non-privileged port for testing:
./dnsbl-server -i 127.0.0.1:5453 ...

## File Formats

### Blocklist File

One IP or CIDR per line. Lines starting with # are ignored.

# Individual IPs
192.168.1.1
10.0.0.1

# CIDR ranges
192.168.1.0/24
10.0.0.0/8

### Source List File

One source per line. Supports # for comments.

# Local sources
/etc/dnsbl/blacklist.txt
/var/lib/dnsbl/custom.list

# URLs
http://www.example.com/blocklist.txt
https://example.org/blacklist.txt

# Remote DNSBLs
dnsbl://zen.spamhaus.org
dnsbl://b.barracudacentral.org

## Performance

- **DNSBL cache**: 5 minutes
- **NS cache**: 1 hour
- **DNS timeout**: 2 seconds
- **Buffer size**: 512 bytes (RFC compliant)
- **Threading**: One thread per query

## License

GPL

## Author

Philippe TEMESI

## Version

2.5.0 - 2026

## Changelog

### v2.5.0
- Added trust-dns for reliable NS discovery
- Improved DNSBL forwarding with authoritative server queries
- Added round-robin load balancing
- Enhanced caching system

### v2.4.0
- Added NS record discovery for remote DNSBLs
- Added SOA record support
- Improved error handling

### v2.3.0
- Added NS record support for self-domain
- Added file-list option (-F)
- Added dnsbl:// protocol for remote DNSBLs

### v2.2.0
- Added rate limiting
- Added query logging
- Improved multi-zone support

### v2.1.0
- Added self-domain A record support
- Added auto-reload functionality

### v2.0.0
- Complete rewrite with multi-zone support
- HTTP/HTTPS source support
- CIDR range support

## Acknowledgments

- The Rust community for excellent libraries
- DNSBL operators for their services
- Contributors and testers

Note: For more information, visit https://www.tems.be
