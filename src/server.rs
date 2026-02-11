use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use clap::{App, Arg};
use daemonize::Daemonize;
use ipnetwork::Ipv4Network;
use log::{info, warn, error, debug};

// Structure for storing blocked IPs
#[derive(Debug, Clone)]
struct DNSBLServer {
    blocked_ips: Arc<RwLock<HashSet<Ipv4Addr>>>,
    blocked_ranges: Arc<RwLock<Vec<Ipv4Network>>>,
    domain: String,
}

impl DNSBLServer {
    fn new(domain: &str) -> Self {
        DNSBLServer {
            blocked_ips: Arc::new(RwLock::new(HashSet::new())),
            blocked_ranges: Arc::new(RwLock::new(Vec::new())),
            domain: domain.to_string(),
        }
    }

    // Load IPs from multiple files
    fn load_blocklists(&self, filenames: &[String]) -> io::Result<()> {
        let mut ips = self.blocked_ips.write().unwrap();
        let mut ranges = self.blocked_ranges.write().unwrap();
        
        ips.clear();
        ranges.clear();
        
        let mut total_ips = 0;
        let mut total_ranges = 0;
        
        for filename in filenames {
            match self.load_single_blocklist(filename) {
                Ok((file_ips, file_ranges)) => {
                    total_ips += file_ips;
                    total_ranges += file_ranges;
                    info!("Loaded {} IPs and {} CIDR ranges from {}", 
                          file_ips, file_ranges, filename);
                }
                Err(e) => {
                    error!("Error loading blocklist file {}: {}", filename, e);
                    return Err(e);
                }
            }
        }
        
        info!("Total blocklist loaded: {} IPs, {} CIDR ranges", total_ips, total_ranges);
        Ok(())
    }
    
    // Load IPs from a single file
    fn load_single_blocklist(&self, filename: &str) -> io::Result<(usize, usize)> {
        let path = Path::new(filename);
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", filename)
            ));
        }
        
        let file = File::open(filename)?;
        let reader = io::BufReader::new(file);
        
        let mut ips = self.blocked_ips.write().unwrap();
        let mut ranges = self.blocked_ranges.write().unwrap();
        
        let mut file_ips = 0;
        let mut file_ranges = 0;
        
        for (line_num, line) in reader.lines().enumerate() {
            let line = line?.trim().to_string();
            
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Try to parse as CIDR
            if let Ok(network) = Ipv4Network::from_str(&line) {
                ranges.push(network);
                file_ranges += 1;
                debug!("Added CIDR range from {}: {}", filename, network);
            } 
            // Try as simple IP
            else if let Ok(ip) = Ipv4Addr::from_str(&line) {
                if ips.insert(ip) {
                    file_ips += 1;
                    debug!("Added IP from {}: {}", filename, ip);
                } else {
                    debug!("Duplicate IP from {}: {} (skipped)", filename, ip);
                }
            } else {
                warn!("Invalid line {} in {}: {}", line_num + 1, filename, line);
            }
        }
        
        Ok((file_ips, file_ranges))
    }

    // Check if an IP is blocked
    fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        // Check simple IPs
        let ips = self.blocked_ips.read().unwrap();
        if ips.contains(&ip) {
            return true;
        }
        
        // Check CIDR ranges
        let ranges = self.blocked_ranges.read().unwrap();
        for range in ranges.iter() {
            if range.contains(ip) {
                return true;
            }
        }
        
        false
    }

    // Process DNS query
    fn handle_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }

        // Transaction ID
        let id = &query[0..2];
        
        // Copy the entire query header
        let mut response = Vec::new();
        response.extend_from_slice(id);
        
        // Set response flags (QR=1, AA=1, RCODE=0 for success, 3 for NXDOMAIN)
        let is_blocked = self.parse_and_check_query(query);
        
        if is_blocked {
            // Flags: QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=0, Z=0, RCODE=0
            response.extend_from_slice(&[0x81, 0x80]);
            // QDCOUNT = 1, ANCOUNT = 1
            response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            // NSCOUNT = 0, ARCOUNT = 0
            response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            
            // Copy question section from query
            let mut pos = 12;
            while pos < query.len() && query[pos] != 0 {
                let len = query[pos] as usize;
                if pos + len + 1 >= query.len() {
                    return None;
                }
                response.extend_from_slice(&query[pos..=pos + len]);
                pos += len + 1;
            }
            if pos >= query.len() || query[pos] != 0 {
                return None;
            }
            response.push(0); // Terminator
            
            // Copy QTYPE and QCLASS
            if pos + 4 <= query.len() {
                response.extend_from_slice(&query[pos + 1..pos + 5]);
            } else {
                return None;
            }
            
            // Answer section
            // Name pointer to question (0xC0 0x0C)
            response.extend_from_slice(&[0xC0, 0x0C]);
            // TYPE A, CLASS IN
            response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            // TTL 300 seconds
            response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
            // RDLENGTH 4
            response.extend_from_slice(&[0x00, 0x04]);
            // RDATA 127.0.0.2 (standard DNSBL response)
            response.extend_from_slice(&[127, 0, 0, 2]);
            
            Some(response)
        } else {
            // NXDOMAIN response
            // Flags: QR=1, AA=1, TC=0, RD=1, RCODE=3 (NXDOMAIN)
            response.extend_from_slice(&[0x81, 0x83]);
            // QDCOUNT = 1, ANCOUNT = 0
            response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
            // NSCOUNT = 0, ARCOUNT = 0
            response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            
            // Copy question section from query
            let mut pos = 12;
            while pos < query.len() && query[pos] != 0 {
                let len = query[pos] as usize;
                if pos + len + 1 >= query.len() {
                    return None;
                }
                response.extend_from_slice(&query[pos..=pos + len]);
                pos += len + 1;
            }
            if pos >= query.len() || query[pos] != 0 {
                return None;
            }
            response.push(0); // Terminator
            
            // Copy QTYPE and QCLASS
            if pos + 4 <= query.len() {
                response.extend_from_slice(&query[pos + 1..pos + 5]);
            } else {
                return None;
            }
            
            Some(response)
        }
    }
    
    // Parse query and check if IP is blocked
    fn parse_and_check_query(&self, query: &[u8]) -> bool {
        if query.len() < 12 {
            return false;
        }
        
        // Find question section
        let mut pos = 12;
        let mut domain_parts = Vec::new();
        
        while pos < query.len() && query[pos] != 0 {
            let len = query[pos] as usize;
            if pos + len + 1 >= query.len() {
                return false;
            }
            
            let part = &query[pos + 1..pos + 1 + len];
            domain_parts.push(String::from_utf8_lossy(part).to_string());
            pos += len + 1;
            
            if pos >= query.len() {
                return false;
            }
        }
        
        if domain_parts.is_empty() {
            return false;
        }
        
        let domain = domain_parts.join(".");
        debug!("Query received for domain: {}", domain);
        
        // Check if it's our DNSBL domain
        if domain.ends_with(&self.domain) {
            // Extract IP from domain name (reverse format)
            let ip_part = domain.trim_end_matches(&format!(".{}", self.domain));
            
            // Parse reverse format: d.c.b.a -> a.b.c.d
            let parts: Vec<&str> = ip_part.split('.').collect();
            if parts.len() >= 4 {
                // Take last 4 octets
                let last_four = if parts.len() > 4 {
                    &parts[parts.len() - 4..]
                } else {
                    &parts
                };
                
                // Reverse to get correct order
                let octets: Result<Vec<u8>, _> = last_four
                    .iter()
                    .rev()
                    .map(|s| s.parse::<u8>())
                    .collect();
                
                if let Ok(octets) = octets {
                    if octets.len() == 4 {
                        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                        
                        if self.is_blocked(ip) {
                            info!("Blocked IP: {} (domain: {})", ip, domain);
                            return true;
                        } else {
                            debug!("IP not blocked: {} (domain: {})", ip, domain);
                        }
                    }
                }
            }
        }
        
        false
    }

    // Start server
    fn start(&self, interface: &str, verbose: bool) -> io::Result<()> {
        let socket_addr = if interface.contains(':') {
            SocketAddr::from_str(interface).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?
        } else {
            // Default to port 53 on all interfaces
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53)
        };
        
        let socket = UdpSocket::bind(socket_addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        
        info!("DNSBL server started on {} (domain: {})", socket_addr, self.domain);
        info!("Press Ctrl+C to stop the server");
        
        let mut buf = [0u8; 512];
        
        loop {
            match socket.recv_from(&mut buf) {
                Ok((size, src_addr)) => {
                    if verbose {
                        debug!("Request received from {}", src_addr);
                    }
                    
                    if let Some(response) = self.handle_query(&buf[..size]) {
                        if let Err(e) = socket.send_to(&response, src_addr) {
                            warn!("Send error to {}: {}", src_addr, e);
                        } else if verbose {
                            debug!("Response sent to {}", src_addr);
                            if response.len() > 2 {
                                let rcode = response[3] & 0x0F;
                                if rcode == 0 {
                                    debug!("Response: SUCCESS (IP blocked)");
                                } else if rcode == 3 {
                                    debug!("Response: NXDOMAIN (IP not blocked)");
                                }
                            }
                        }
                    } else {
                        warn!("Failed to generate response for query from {}", src_addr);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data, continue
                }
                Err(e) => {
                    warn!("Receive error: {}", e);
                }
            }
        }
    }
}

// Logging setup
fn setup_logging(log_file: Option<&str>, verbose: bool) -> Result<(), fern::InitError> {
    let mut dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(if verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        });
    
    if let Some(log_file) = log_file {
        dispatch = dispatch.chain(fern::log_file(log_file)?);
    }
    
    dispatch = dispatch.chain(std::io::stdout());
    
    dispatch.apply()?;
    Ok(())
}

fn main() {
    let matches = App::new("DNSBL Server")
        .version("1.0")
        .author("Philippe TEMESI")
        .about("A simple DNSBL server in Rust")
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("Text file(s) containing the blocklist (can be specified multiple times)")
                .takes_value(true)
                .multiple(true)
                .required(true)
        )
        .arg(
            Arg::with_name("daemon")
                .short("d")
                .long("daemon")
                .help("Run in daemon mode")
        )
        .arg(
            Arg::with_name("domain")
                .short("D")
                .long("domain")
                .value_name("DOMAIN")
                .help("DNSBL domain (e.g., dnsbl.example.com)")
                .takes_value(true)
                .default_value("dnsbl.tems.be")
        )
        .arg(
            Arg::with_name("interface")
                .short("i")
                .long("interface")
                .value_name("INTERFACE")
                .help("Listening interface (e.g., 0.0.0.0:53 or 127.0.0.1:5353)")
                .takes_value(true)
                .default_value("0.0.0.0:53")
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Verbose mode")
        )
        .arg(
            Arg::with_name("log")
                .short("l")
                .long("log")
                .value_name("LOG_FILE")
                .help("Log file")
                .takes_value(true)
        )
        .after_help("2026, Philippe TEMESI - https://www.tems.be\n\nExamples:\n  dnsbl-server -f blocklist1.txt -f blocklist2.txt\n  dnsbl-server -f blocklist1.txt -f blocklist2.txt -f blocklist3.txt -i 127.0.0.1:5453")
        .get_matches();

    // Daemon mode
    if matches.is_present("daemon") {
        let daemonize = Daemonize::new()
            .pid_file("/tmp/dnsbl.pid")
            .chown_pid_file(true)
            .working_directory(".")
            .privileged_action(|| info!("Starting in daemon mode"));
        
        match daemonize.start() {
            Ok(_) => info!("Daemon started successfully"),
            Err(e) => {
                eprintln!("Error starting daemon: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Setup logging
    let log_file = matches.value_of("log");
    let verbose = matches.is_present("verbose");
    
    if let Err(e) = setup_logging(log_file, verbose) {
        eprintln!("Logging initialization error: {}", e);
        std::process::exit(1);
    }

    info!("DNSBL Server v1.0 - 2026, Philippe TEMESI");
    info!("Website: https://www.tems.be");
    
    // Get all file arguments
    let blocklist_files: Vec<String> = matches.values_of_lossy("file").unwrap();
    
    info!("Loading {} blocklist file(s):", blocklist_files.len());
    for (i, file) in blocklist_files.iter().enumerate() {
        info!("  {}. {}", i + 1, file);
    }
    
    // Create server
    let domain = matches.value_of("domain").unwrap();
    let dnsbl_server = DNSBLServer::new(domain);
    
    // Load blocklists
    if let Err(e) = dnsbl_server.load_blocklists(&blocklist_files) {
        error!("Error loading blocklist file(s): {}", e);
        std::process::exit(1);
    }
    
    // Start server
    let interface = matches.value_of("interface").unwrap();
    if let Err(e) = dnsbl_server.start(interface, verbose) {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}
