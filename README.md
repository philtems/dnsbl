# DNSBL Server v2.9.0

A complete multi-zone DNSBL (DNS Blackhole List) server with NS/SOA/MX/TXT record support, real-time DNSBL forwarding, and advanced logging.

## Features

- **Multi-zone support**: Handle multiple DNSBL domains simultaneously
- **Full DNS record support**: A, NS, SOA, MX, and TXT records for self-domain queries
- **TXT record substitution**: Dynamic insertion of IP in TXT responses (`@`, `@dotted`, `@reversed`)
- **DNSBL forwarding**: Query remote DNSBLs in real-time (`dnsbl://`)
- **Automatic NS discovery**: Find authoritative servers of remote DNSBLs recursively
- **Intelligent caching**: Cache DNSBL query results (5 minutes) and NS servers (1 hour)
- **Round-robin rotation**: Distribute queries among NS servers for load balancing
- **Rate limiting**: Limit queries per IP address with exempt lists
- **Dual logging**: Application logs and dedicated query logs
- **Auto-reload**: Periodically reload source files
- **HTTP/HTTPS support**: Download blocklists from URLs
- **Daemon mode**: Run as a background service
- **Configuration file**: INI-format configuration with multiple zones

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

### Two Configuration Modes

1. **Command-line mode** (legacy, simple setups)
2. **Configuration file mode** (recommended for complex setups)

### Configuration File (Recommended)

Create an INI file (e.g., `/etc/dnsbl/server.conf`):

; ======================================
; DNSBL Server v2.9.0 Configuration File
; ======================================

; ----------------------------------------
; [global] section - Global server options
; ----------------------------------------
[global]

; Listening interface (address:port)
; Default: 0.0.0.0:53
interface = 0.0.0.0:53

; Maximum requests per minute per IP (0 = unlimited)
; Default: 0
max-requests = 100

; File containing IPs/networks exempt from rate limiting (one per line)
no-request-limit-file = /etc/dnsbl/exempt.conf

; Alternative: direct list of IPs/networks (comma-separated)
; no-request-limit = 127.0.0.1,192.168.1.0/24,10.0.0.0/8

; File containing denied IPs/networks (one per line)
deny-file = /etc/dnsbl/deny.conf

; Rate limiting stats logging interval (seconds, 0 = disabled)
; Default: 0
stats-interval = 60

; DNS query log file (text format)
query-log = /var/log/dnsbl/queries.log

; File to save IPs found in remote DNSBLs
dbl-save = /var/log/dnsbl/dbl_ips.log

; Auto-reload interval for sources (minutes, 0 = disabled)
; Default: 0
reload = 60

; Daemon mode (true/false)
; Default: false
daemon = true

; Verbose mode (debug) (true/false)
; Default: false
verbose = false

; Main server log file
log = /var/log/dnsbl/server.log


; -------------------------------------------------
; [domain "..."] section - DNSBL zone configuration
; Repeat for each domain
; -------------------------------------------------

; ==============================
; First zone: dnsbl1.example.com
; ==============================
[domain "dnsbl1.example.com"]

; Response IP for blocked IPs (usually 127.0.0.2)
; Default: 127.0.0.2
response = 127.0.0.2

; IP to return for queries on the domain itself (A, NS, SOA)
; Default: 127.0.0.2
self = 192.168.1.10

; TXT record for the domain (supports @, @dotted, @reversed substitutions)
; Can be repeated multiple times
txt = "This IP @dotted is listed in our database"
txt = "Listed since 2026 - Contact abuse@example.com"

; MX record (format: server,priority)
; Can be repeated multiple times
mx = mail.example.com,10
mx = backup-mail.example.com,20

; Blocklist sources (local file, HTTP/HTTPS URL, remote DNSBL)
; Can be repeated multiple times

; Source: local file
source = /etc/dnsbl/lists/blocklist.txt

; Source: local file with IPs and CIDR ranges
source = /etc/dnsbl/lists/ranges.txt

; Source: HTTP URL
source = http://www.example.com/blocklist.txt

; Source: HTTPS URL
source = https://lists.example.com/blocklist.txt

; Source: remote DNSBL (real-time forwarding)
source = dnsbl://dnsbl.example.org

; Source: remote DNSBL with different providers
source = dnsbl://zen.spamhaus.org
source = dnsbl://b.barracudacentral.org

; File containing a list of sources (one per line)
source-file = /etc/dnsbl/sources/dnsbl1.list


; ==================================
; Second zone: blacklist.example.net
; ==================================
[domain "blacklist.example.net"]

response = 127.0.0.3
self = 192.168.1.11

; TXT record with substitutions
txt = "IP @reversed (dotted: @dotted) is blocked"

; MX record
mx = mx1.example.net,5

; Mixed sources
source = /etc/dnsbl/lists/custom_blacklist.txt
source = https://lists.example.net/blocklist.txt
source = dnsbl://dnsbl.example.net
source-file = /etc/dnsbl/sources/blacklist.sources


; ============================
; Third zone: spam.example.org
; ============================
[domain "spam.example.org"]

response = 127.0.0.4
self = 192.168.1.12

; No TXT or MX for this zone

; Multiple sources
source = /etc/dnsbl/lists/spam_ips.txt
source = https://spam.example.org/blocklist.txt
source = dnsbl://dnsbl1.spamhaus.org
source = dnsbl://dnsbl2.spamhaus.org
source = dnsbl://dnsbl3.spamhaus.org
source-file = /etc/dnsbl/sources/spam.sources


; ==========================================
; Fourth zone: dnsbl.local (local test zone)
; ==========================================
[domain "dnsbl.local"]

response = 127.0.0.5
self = 127.0.0.1

; Simple TXT record
txt = "Local test zone"

; Local source only
source = /etc/dnsbl/lists/local_blacklist.txt

### Command-line Options

| Option | Description |
|--------|-------------|
| `--config <FILE>` | Configuration file (INI format) |
| `-D, --domain <DOMAIN>` | DNSBL domain (can be multiple) |
| `-r, --response <IP>` | Response IP for blocked IPs |
| `-s, --self-ip <IP>` | IP for queries on the domain itself |
| `--txt <TEXT>` | TXT record for the domain |
| `--mx <SERVER,PRIORITY>` | MX record (format: server,priority) |
| `-f, --file <SOURCE>` | Blocklist source (file, URL, or dnsbl://) |
| `-F, --file-list <FILE>` | File containing one source per line |
| `-R, --reload <MINUTES>` | Reload interval (0 = disabled) |
| `--max-requests <COUNT>` | Max requests per minute per IP (0 = unlimited) |
| `--no-request-limit <IP,RANGE>` | IPs/ranges exempt from rate limiting |
| `--no-request-limit-file <FILE>` | File with exempt IPs/ranges |
| `--deny-file <FILE>` | File with denied IPs/ranges |
| `--stats-interval <SECONDS>` | Statistics logging interval (0 = disabled) |
| `--query-log <FILE>` | Query log file |
| `--dbl-save <FILE>` | File to save IPs found in remote DNSBLs |
| `-d, --daemon` | Daemon mode |
| `--no-daemon` | Do not run in daemon mode (override config) |
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

### Using Configuration File

dnsbl-server --config /etc/dnsbl/server.conf

## Architecture

### How It Works

1. **DNS query reception** on port 53 (or custom port)
2. **Parsing** to extract domain and query type
3. **Detection** of self-domain queries (A/NS/SOA/MX/TXT)
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

1. **NS discovery**: Query public resolvers for NS records of the remote DNSBL (recursive)
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

Test TXT record (blocked IP):
dig @127.0.0.1 -p 5453 2.0.0.127.bl.example.com TXT

Test NS record on domain:
dig @127.0.0.1 -p 5453 bl.example.com NS

Test MX record:
dig @127.0.0.1 -p 5453 bl.example.com MX

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

echo "3. Self-domain MX query:"
dig @$SERVER -p $PORT $DOMAIN MX +short

echo "4. Self-domain TXT query:"
dig @$SERVER -p $PORT $DOMAIN TXT +short

echo "5. Blocked IP (127.0.0.2) A record:"
dig @$SERVER -p $PORT 2.0.0.127.$DOMAIN A +short

echo "6. Blocked IP TXT record:"
dig @$SERVER -p $PORT 2.0.0.127.$DOMAIN TXT +short

echo "7. Unblocked IP:"
dig @$SERVER -p $PORT 1.2.3.4.$DOMAIN A +short

## Logging

### Application Log

Format: `[timestamp][LEVEL] message`

Example:
[2026-02-20 14:50:20][INFO] DNSBL server v2.9.0 started on 127.0.0.1:5453
[2026-02-20 14:50:20][INFO] Zone: bl.example.com -> 127.0.0.2 (self: 192.168.1.100, TXT: 2, MX: 1, 3 sources, 2 DNSBL forwarders)
[2026-02-20 14:50:33][INFO] [bl.example.com] Blocked IP: 127.0.0.2 (domain: 2.0.0.127.bl.example.com from 127.0.0.1)
[2026-02-20 14:50:35][INFO] [bl.example.com] TXT query for IP: 127.0.0.2 (domain: 2.0.0.127.bl.example.com from 127.0.0.1)

### Query Log (--query-log)

Format: `[timestamp] source_ip domain qtype status [source:name]`

Example:
[2026-02-20 14:50:33] 127.0.0.1 2.0.0.127.bl.example.com A A_RESPONSE 127.0.0.2 [source:local]
[2026-02-20 14:50:34] 127.0.0.1 1.2.3.4.bl.example.com A NXDOMAIN
[2026-02-20 14:50:35] 127.0.0.1 2.0.0.127.bl.example.com TXT TXT_RESPONSE "This IP 127.0.0.2 is listed"
[2026-02-20 14:50:36] 127.0.0.1 bl.example.com A A_RESPONSE 192.168.1.100

### DBL Save File (--dbl-save)

Format: One IP per line

Example:
192.168.1.1
10.0.0.1
172.16.0.1

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

### Exempt/Deny Files

One IP or CIDR per line. Lines starting with # are ignored.

127.0.0.1
192.168.1.0/24
10.0.0.0/8
::1

## Performance

- **DNSBL cache**: 5 minutes
- **NS cache**: 1 hour
- **DNS timeout**: 2 seconds
- **Buffer size**: 512 bytes (RFC compliant)
- **Threading**: Single-threaded with non-blocking I/O

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

Check if query type is supported (A for subdomains, A/NS/SOA/MX/TXT for domain).

### Permission Issues

To listen on privileged port 53:
sudo ./dnsbl-server ...

Or use a non-privileged port for testing:
./dnsbl-server -i 127.0.0.1:5453 ...

## License

GPL

## Author

Philippe TEMESI

## Version

2.9.0 - 2026

## Changelog

### v2.9.0
- Added configuration file support (INI format)
- Added MX record support
- Enhanced TXT record substitution (@dotted, @reversed)
- Improved recursive NS discovery
- Better error handling and logging

### v2.8.0
- Added TXT record support with IP substitution
- Enhanced DNSBL forwarding with fallback resolvers
- Improved cache management

### v2.7.0
- Added SOA record support
- Improved NS discovery algorithm
- Added round-robin load balancing

### v2.6.0
- Added trust-dns for reliable NS discovery
- Enhanced DNSBL forwarding with authoritative server queries
- Added comprehensive logging

### v2.5.0
- Initial release with multi-zone support
- NS record support for self-domain
- Rate limiting and query logging

## Acknowledgments

- The Rust community for excellent libraries
- DNSBL operators for their services
- Contributors and testers

Note: For more information, visit https://www.tems.be
