# DNSBL Server User Manual

**Version 2.9.0** \| **Philippe TEMESI** \| [**https://www.tems.be**](https://www.tems.be/)

## Table of Contents

1.  Introduction

2.  Quick Start

3.  DNSBL Query Tool (*dnsbl-query*)

4.  DNSBL Server (*dnsbl-server*)

    -   Configuration File (INI Format)
    -   Command-Line Options
    -   Zone Configuration

5.  Source Types

6.  DNS Record Support

7.  Access Control

8.  Logging

9.  Auto-Reload

10. Real-Time DNSBL Forwarding

11. Test Queries

12. Examples

## Introduction

The DNSBL Server is a complete toolkit for running DNS-based Blocklists (DNSBL). It provides:

-   **DNSBL Server** (*dnsbl-server*): A full-featured DNS server that responds to blocklist queries
-   **DNSBL Query Tool** (*dnsbl-query*): A client tool to test if an IP address is listed

Key features:

-   Multi-zone support (run multiple DNSBL domains on a single server)
-   HTTP/HTTPS and local file blocklist sources
-   Real-time DNSBL forwarding with recursive NS discovery
-   NS, SOA, MX, and TXT record support for your DNSBL domains
-   Rate limiting and IP-based access control
-   Query logging and DBL saving
-   Auto-reload of blocklists

## Quick Start

### Basic Server with One Zone


dnsbl-server -D dnsbl.example.com -r 127.0.0.2 -s 192.168.1.100 -f /path/to/blocklist.txt

### Query an IP Address


dnsbl-query -d dnsbl.example.com 192.168.1.100

### Using a Configuration File


dnsbl-server \--config /etc/dnsbl/server.ini

## DNSBL Query Tool (*dnsbl-query*)

The query tool checks whether an IP address is listed in a DNSBL.

### Usage


dnsbl-query \[OPTIONS\] -d DOMAIN IP_ADDRESS

### Options

  -------------------------- -----------------------------------------------
  *-d, \--domain DOMAIN*     DNSBL domain to query (e.g., *dnsbl.tems.be*)
  *-s, \--server SERVER*     DNS server to use (default: *127.0.0.1:53*)
  *-t, \--timeout SECONDS*   DNS query timeout (default: 5 seconds)
  *-v, \--verbose*           Enable verbose output
  *-q, \--quiet*             Quiet mode - output only the result
  *-h, \--help*              Show help information
  -------------------------- -----------------------------------------------

### Output Formats

**Normal mode** (default):

-   *✅ IP x.x.x.x is CLEAN* - IP not listed
-   *✅ IP x.x.x.x is BLOCKED* - IP is listed, with response IP and reason

**Quiet mode** (*-q*):

-   *CLEAN* - IP not listed
-   *BLOCKED:x.x.x.x* - IP is blocked (x.x.x.x is the response IP)
-   *ERROR:message* - An error occurred

### Examples


\# Query using system DNS

dnsbl-query -d dnsbl.tems.be 192.168.1.100

\# Query using Google DNS

dnsbl-query -d dnsbl.tems.be -s 8.8.8.8 192.168.1.100

\# Query with custom port and verbose output

dnsbl-query -d dnsbl.tems.be -s 127.0.0.1:5453 -v 192.168.1.100

\# Quiet mode for scripting

dnsbl-query -d dnsbl.tems.be -q 192.168.1.100

### Response Code Interpretation

When verbose mode is enabled, the tool interprets common DNSBL response codes:

  ----------- ----------------------
  127.0.0.2   General spam source
  127.0.0.3   High confidence spam
  127.0.0.4   Open proxy
  127.0.0.5   Open relay
  127.0.0.6   Hacked/Compromised
  127.0.0.7   Dynamic IP
  127.0.0.8   Dialup IP
  127.0.0.9   Blacklisted
  ----------- ----------------------

## DNSBL Server (*dnsbl-server*)

The server listens for DNS queries and responds based on configured blocklists.

### Configuration Methods

The server can be configured in two ways:

1.  **Configuration file (INI format)** - Recommended for complex setups
2.  **Command-line arguments** - Simple setups or legacy compatibility

### Configuration File (INI Format)

The configuration file uses INI format with a *\[global\]* section and one or more *\[domain \"\...\"\]* sections.

#### Global Section


\[global\]

interface = 0.0.0.0:53

max-requests = 60

no-request-limit = 192.168.1.0/24,10.0.0.5

no-request-limit-file = /etc/dnsbl/exempt.txt

deny-file = /etc/dnsbl/deny.txt

stats-interval = 60

query-log = /var/log/dnsbl/queries.log

dbl-save = /var/lib/dnsbl/blocked_ips.txt

reload = 30

daemon = true

verbose = false

log = /var/log/dnsbl/server.log

#### Global Options

  ------------------------- -----------------------------------------------------
  *interface*               Network interface to bind (IP:port)
  *max-requests*            Max requests per minute per IP (0 = unlimited)
  *no-request-limit*        Comma-separated IPs/CIDRs exempt from rate limiting
  *no-request-limit-file*   File with exempt IPs/CIDRs (one per line)
  *deny-file*               File with IPs/CIDRs denied access (one per line)
  *stats-interval*          Interval for rate limiting stats logging (seconds)
  *query-log*               File path for DNS query logs
  *dbl-save*                File path to save IPs found in remote DNSBLs
  *reload*                  Auto-reload interval (minutes, 0 = disabled)
  *daemon*                  Run as daemon (true/false)
  *verbose*                 Enable verbose logging (true/false)
  *log*                     Server log file path
  ------------------------- -----------------------------------------------------

#### Zone Section

Each zone is defined with *\[domain \"your.domain.com\"\]*:


\[domain \"dnsbl.example.com\"\]

response = 127.0.0.2

self = 192.168.1.100

txt = \"Spam source - see https://example.com/remove\"

mx = mail.example.com,10

source = /var/lib/dnsbl/blocklist.txt

source = https://example.com/blocklist.txt

source = dnsbl://other-dnsbl.example.com

source-file = /etc/dnsbl/sources.txt

#### Zone Options

  --------------- ------------------------------------------------------------------
  *response*      IP address returned for blocked queries
  *self*          IP address returned for queries to the domain itself
  *txt*           TXT record (supports *@*, *\@dotted*, *\@replaced* placeholders)
  *mx*            MX record (format: *server,priority*)
  *source*        Blocklist source (file, http://, https://, or dnsbl://domain)
  *source-file*   File containing one source per line
  --------------- ------------------------------------------------------------------

### Command-Line Options

When not using a config file, command-line options are available:

#### Server Options

  ------------------------------ ---------------------------------------------
  *-i, \--interface INTERFACE*   Listening interface (default: *0.0.0.0:53*)
  *-v, \--verbose*               Enable verbose mode
  *-d, \--daemon*                Run as daemon
  *\--no-daemon*                 Do not run as daemon (override config)
  *-l, \--log LOG_FILE*          Server log file
  *-R, \--reload MINUTES*        Auto-reload interval (minutes)
  *\--config FILE*               Use configuration file
  ------------------------------ ---------------------------------------------

#### Access Control Options

  ------------------------------------- -------------------------------------
  *\--max-requests COUNT*               Max requests per minute per IP
  *\--no-request-limit IP,RANGE,\...*   IPs/CIDRs exempt from rate limiting
  *\--no-request-limit-file FILE*       File with exempt IPs/CIDRs
  *\--deny-file FILE*                   File with denied IPs/CIDRs
  *\--stats-interval SECONDS*           Stats logging interval
  ------------------------------------- -------------------------------------

#### Logging Options

  --------------------- --------------------------
  *\--query-log FILE*   Log DNS queries to file
  *\--dbl-save FILE*    Save blocked IPs to file
  --------------------- --------------------------

#### Zone Options (per zone, repeatable)

  ------------------------- --------------------------------------
  *-D, \--domain DOMAIN*    DNSBL domain name
  *-r, \--response IP*      Response IP for blocked queries
  *-s, \--self-ip IP*       IP for self-domain queries
  *-f, \--file SOURCE*      Blocklist source (file/URL/dnsbl://)
  *-F, \--file-list FILE*   File containing sources
  *\--txt TEXT*             TXT record for the domain
  *\--mx SERVER,PRIORITY*   MX record for the domain
  ------------------------- --------------------------------------

> **Note**: When using multiple zones with command-line options, the number of *-D*, *-r*, and *-s* options must match. Sources are distributed evenly across zones.

## Source Types

The server supports three types of blocklist sources:

### 1. Local File


source = /path/to/blocklist.txt

File format: one IP address or CIDR range per line. Lines starting with *\#* are ignored.

Example blocklist file:


\# My blocklist

192.168.1.100

10.0.0.0/24

203.0.113.50

### 2. HTTP/HTTPS URL


source = https://example.com/blocklist.txt

The server downloads the file from the URL. The same format as local files is expected.

### 3. DNSBL Forwarder


source = dnsbl://other-dnsbl.example.com

The server forwards queries to another DNSBL in real-time. The queried IP is checked against the remote DNSBL before returning a result.

## DNS Record Support

The server provides full DNS record support for your DNSBL domains.

### A Records (Type 1)

-   **Queries for ***x.x.x.x.zone.domain*****: Returns *response* IP if the IP is blocked
-   **Queries for ***zone.domain*****: Returns *self* IP

### NS Records (Type 2)

Returns NS records for the domain, pointing to the *self* IP address.

### SOA Records (Type 6)

Returns Start of Authority record for the domain.

### MX Records (Type 15)

Returns configured MX record for the domain.

### TXT Records (Type 16)

Returns TXT information. Supports IP substitution placeholders:

  ------------------- -------------------------------------
  *@* or *\@dotted*   Dotted IP format: *192.168.1.100*
  *\@reversed*        Reversed IP format: *100.1.168.192*
  ------------------- -------------------------------------

Example TXT with substitution:


txt = \"IP @ is listed in our blocklist. See https://example.com/remove?ip=@dotted\"

For an IP *192.168.1.100*, this becomes:


\"IP 192.168.1.100 is listed in our blocklist. See https://example.com/remove?ip=192.168.1.100\"

## Access Control

The server implements three layers of access control:

### 1. Deny List

IPs or CIDR ranges in the deny list are completely blocked from querying the server. No response is sent.


deny-file = /etc/dnsbl/deny.txt

### 2. Exempt List (No Rate Limit)

IPs or CIDR ranges in the exempt list bypass rate limiting.


no-request-limit = 192.168.1.0/24,10.0.0.5

no-request-limit-file = /etc/dnsbl/exempt.txt

### 3. Rate Limiting

Limits the number of queries per minute from a single IP address.


max-requests = 60

When the limit is exceeded, the server returns a REFUSED response for the duration of the current minute.

### Order of Evaluation

1.  **Deny list** - If matched, query is rejected immediately
2.  **Exempt list** - If matched, rate limiting is bypassed
3.  **Rate limit check** - Applied only if not exempt

## Logging

### Server Log

Logs server events including startup, errors, and reload operations.


dnsbl-server \--log /var/log/dnsbl/server.log \--verbose

### Query Log

Logs all DNS queries received by the server.


dnsbl-server \--query-log /var/log/dnsbl/queries.log

Query log format:


\[2026-01-15 10:30:45\] 192.168.1.100 dnsbl.example.com A NXDOMAIN

\[2026-01-15 10:30:46\] 10.0.0.50 dnsbl.example.com A A_RESPONSE 127.0.0.2 \[source:local\]

\[2026-01-15 10:30:47\] 192.168.1.101 dnsbl.example.com TXT TXT_RESPONSE \"IP 192.168.1.100 is blocked\"

Fields:

-   Timestamp
-   Client IP address
-   Query domain
-   Query type (A, TXT, NS, MX, etc.)
-   Status/Response (NXDOMAIN, A_RESPONSE IP, TXT_RESPONSE, etc.)
-   Source (local, test, dnsbl:domain, ACTION:EXEMPT, etc.)

### DBL Save File

Saves IP addresses that were found to be blocked by remote DNSBL forwarders.


dnsbl-server \--dbl-save /var/lib/dnsbl/blocked_ips.txt

Each blocked IP appears on a separate line, deduplicated automatically.

## Auto-Reload

The server can automatically reload blocklists at regular intervals.


dnsbl-server -R 30 \... \# Reload every 30 minutes

During reload:

1.  The server re-downloads HTTP/HTTPS sources
2.  Re-reads local file sources
3.  Updates the in-memory blocklist without restarting
4.  Existing queries continue to be served using the old data until reload completes

> **Note**: DNSBL forwarder sources are not reloaded via this mechanism as they operate in real-time.

## Real-Time DNSBL Forwarding

When using *dnsbl://* sources, the server performs real-time DNSBL forwarding:

### How It Works

1.  A query for *x.x.x.x.your-zone.com* is received

2.  The server extracts the IP address from the query

3.  For each DNSBL forwarder source (*dnsbl://other-dnsbl.com*):

    -   The server queries *x.x.x.x.other-dnsbl.com* (note: IP octets are reversed for DNSBL format)
    -   If the remote DNSBL returns an A record, the IP is considered blocked
    -   Results are cached for 5 minutes to reduce network traffic

### NS Discovery

The server automatically discovers NS servers for remote DNSBL domains:

1.  Performs recursive NS record lookup
2.  Resolves NS names to IP addresses
3.  Caches NS servers for 1 hour
4.  Uses round-robin selection among discovered servers

### Fallback

If NS discovery fails, fallback DNS servers (8.8.8.8, 1.1.1.1, 9.9.9.9) are used.

### Example


\[domain \"my-dnsbl.com\"\]

response = 127.0.0.2

self = 192.168.1.100

source = dnsbl://spamhaus.example.com

source = dnsbl://other-blocklist.net

Now queries to *my-dnsbl.com* will also check *spamhaus.example.com* and *other-blocklist.net* in real-time.

## Test Queries

The server supports test queries using the IP *127.0.0.2* in reversed format.

### Test Format

Query domain: *2.0.0.127.\** - the *2.0.0.127* part matches the test pattern.

### Example


\# This query will always return a positive (blocked) response

dig 2.0.0.127.dnsbl.example.com

This is useful for:

-   Testing server functionality
-   Verifying DNS configuration
-   Monitoring server health

## Examples

### Example 1: Simple Single-Zone Server


\# Create a blocklist file

echo \"192.168.1.100\" \> /tmp/blocklist.txt

echo \"10.0.0.0/24\" \>\> /tmp/blocklist.txt

\# Start the server

dnsbl-server \\

-D my-dnsbl.com \\

-r 127.0.0.2 \\

-s 192.168.1.100 \\

-f /tmp/blocklist.txt \\

-v

### Example 2: Multi-Zone with Configuration File

**/etc/dnsbl/server.ini:**


\[global\]

interface = 0.0.0.0:53

max-requests = 120

no-request-limit = 127.0.0.1

query-log = /var/log/dnsbl/queries.log

reload = 60

daemon = true

log = /var/log/dnsbl/server.log

\[domain \"spam.example.com\"\]

response = 127.0.0.2

self = 10.0.0.1

txt = \"This IP is a spam source\"

source = https://example.com/spam-list.txt

source = dnsbl://other-spam-list.net

\[domain \"malware.example.com\"\]

response = 127.0.0.3

self = 10.0.0.1

txt = \"Malware detected on IP @\"

source = /var/lib/dnsbl/malware.txt

source = https://malware-domains.com/dnsbl.txt

mx = mail.example.com,10

**Start the server:**


dnsbl-server \--config /etc/dnsbl/server.ini

### Example 3: DNSBL Forwarding Only


\# Forward all queries to another DNSBL without local blocklist

dnsbl-server \\

-D forwarder.com \\

-r 127.0.0.2 \\

-s 192.168.1.100 \\

-f dnsbl://upstream-dnsbl.org

### Example 4: Testing with Query Tool


\# Setup: Start server in one terminal

dnsbl-server -D test.com -r 127.0.0.2 -s 127.0.0.1 -f /tmp/blocklist.txt

\# In another terminal, test queries

dnsbl-query -d test.com 192.168.1.100 -v

dnsbl-query -d test.com 192.168.1.200 -v -q

dnsbl-query -d test.com 2.0.0.127 -s 127.0.0.1:53

### Example 5: Production Setup with systemd

**/etc/systemd/system/dnsbl.service:**


\[Unit\]

Description=DNSBL Server

After=network.target

\[Service\]

Type=simple

ExecStart=/usr/local/bin/dnsbl-server \--config /etc/dnsbl/server.ini

Restart=always

User=dnsbl

Group=dnsbl

AmbientCapabilities=CAP_NET_BIND_SERVICE

\[Install\]

WantedBy=multi-user.target

## Troubleshooting

### Server Won\'t Start

**Problem**: *Permission denied* on port 53

**Solution**: Run as root or use *CAP_NET_BIND_SERVICE*:


sudo setcap \'cap_net_bind_service=+ep\' /usr/local/bin/dnsbl-server

### 

### 

### 

### DNSBL Forwarding Not Working

**Problem**: Remote DNSBL queries consistently fail

**Solutions**:

1.  Check network connectivity to remote DNS servers
2.  Verify the remote DNSBL domain is correct
3.  Increase query timeout in configuration
4.  Check DNS resolution of remote NS records

### High Memory Usage

**Solution**: Reduce blocklist size or increase reload interval:


reload = 120 \# Reload less frequently

### Rate Limiting Too Aggressive

**Solutions**:

1.  Increase *max-requests* value
2.  Add trusted IPs to *no-request-limit*
3.  Use *no-request-limit-file* for larger exempt lists

## License

This software is released under the GNU General Public License.

Copyright (c) 2026, Philippe TEMESI - [https://www.tems.be](https://www.tems.be/)
