DNSBL Server

A lightweight, high-performance DNSBL (DNS Blacklist) server written in Rust. It manages blocked IP addresses and responds to DNS queries according to the DNSBL standard.

Features

    Load multiple blocklist files simultaneously

    Support for single IP addresses and CIDR ranges

    Standard DNSBL responses (127.0.0.2 for blocked IPs, NXDOMAIN for non-blocked)

    Daemon mode with PID file

    Verbose logging and log file support

    Low memory footprint

    High performance (implicit multi-threading via Async IO)

Prerequisites

    Rust (1.70 or newer) - https://www.rust-lang.org/tools/install

    Optional: musl-tools for fully static compilation

Compilation

Standard build:

git clone https://github.com/philtems/dnsbl.git
cd dnsbl
cargo build --release

Binary will be located at target/release/dnsbl-server

Static build with musl (recommended for deployment):

rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools
cargo build --release --target x86_64-unknown-linux-musl
ls -lh target/x86_64-unknown-linux-musl/release/dnsbl-server

The statically compiled binary has no dependencies and runs on any Linux system.

Quick install:

sudo cp target/release/dnsbl-server /usr/local/bin/
sudo mkdir -p /etc/dnsbl
sudo cp your-blocklists.txt /etc/dnsbl/

Usage

Blocklist format:

Plain text files, one entry per line:
Comments are supported

192.168.1.1
10.0.0.0/24
172.16.0.0/12

Basic commands:

Single blocklist file:
./dnsbl-server -f blocklist.txt

Multiple blocklists:
./dnsbl-server -f spam-ips.txt -f malwares.txt -f scanners.txt

Custom port and interface:
./dnsbl-server -f blocklist.txt -i 127.0.0.1:5353

Verbose mode (debug):
./dnsbl-server -f blocklist.txt -v

Daemon mode with log file:
./dnsbl-server -f blocklist.txt -d -l /var/log/dnsbl.log

Custom domain:
./dnsbl-server -f blocklist.txt -D dnsbl.your-domain.com

Options:

-f, --file : Blocklist file(s) (can be used multiple times) - Required
-D, --domain : DNSBL domain - Default: dnsbl.tems.be
-i, --interface : Listening interface - Default: 0.0.0.0:53
-d, --daemon : Daemon mode - Default: Disabled
-v, --verbose : Verbose output - Default: Disabled
-l, --log : Log file path - Default: stdout

Examples:

    Local testing:

Terminal 1 - Start server:
./dnsbl-server -f test-blocklist.txt -i 127.0.0.1:5353 -v

Terminal 2 - Test with dig:
dig @127.0.0.1 -p 5353 2.0.0.127.dnsbl.tems.be A

Expected response: 127.0.0.2

    Production daemon:

Start as daemon:
sudo ./dnsbl-server -f /etc/dnsbl/blacklist.txt -d -l /var/log/dnsbl.log

Verify:
ps aux | grep dnsbl
tail -f /var/log/dnsbl.log

    Static deployment:

Build on development machine:
cargo build --release --target x86_64-unknown-linux-musl

Copy to production server:
scp target/x86_64-unknown-linux-musl/release/dnsbl-server root@server:/usr/local/bin/

Binary works immediately on the server:
dnsbl-server --version

Architecture:

[ Blocklists (files) ] -> [ Loader ] -> [ HashSet + CIDR ] -> [ DNS Query reverse IP ] -> [ Response DNSBL ] -> [ DNS Client ]

Performance:

Tested with:

    1 million IPs in memory: ~50 MB RAM

    10,000 queries/second: <5% CPU on standard VPS

    Response time: <1ms for non-blocked IPs, <2ms for blocked IPs

Security:

    Root privileges required for port 53 (standard DNS)

    Recommended: -i 127.0.0.1:5353 with NAT redirection

    Daemon mode creates PID file: /tmp/dnsbl.pid

Troubleshooting:

Permission denied on port 53:

sudo setcap cap_net_bind_service=+ep ./dnsbl-server
Or simply use a port >1024

Musl compilation errors:

rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools musl-dev

License:

GNU General Public License v3.0 - See LICENSE file for details

Author:

Philippe TEMESI - https://www.tems.be

Contributions, bug reports and feature requests are welcome!
