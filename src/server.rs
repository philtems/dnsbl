use std::collections::{HashSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use clap::{App, Arg, ArgMatches};
use daemonize::Daemonize;
use ipnetwork::Ipv4Network;
use log::{info, warn, error, debug};
use reqwest::blocking::Client;
use url::Url;

// Structure pour une zone DNSBL
#[derive(Debug, Clone)]
struct Zone {
    domain: String,
    response_ip: Ipv4Addr,
    blocked_ips: Arc<RwLock<HashSet<Ipv4Addr>>>,
    blocked_ranges: Arc<RwLock<Vec<Ipv4Network>>>,
}

impl Zone {
    fn new(domain: &str, response_ip: Ipv4Addr) -> Self {
        Zone {
            domain: domain.to_string(),
            response_ip,
            blocked_ips: Arc::new(RwLock::new(HashSet::new())),
            blocked_ranges: Arc::new(RwLock::new(Vec::new())),
        }
    }

    // Check if an IP is blocked in this zone
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

    // Load IPs from a local file into this zone
    fn load_from_file(&self, filename: &str) -> io::Result<(usize, usize)> {
        let path = Path::new(filename);
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", filename)
            ));
        }
        
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        
        let mut file_ips = 0;
        let mut file_ranges = 0;
        let mut new_ips = HashSet::new();
        let mut new_ranges = Vec::new();
        
        for (line_num, line) in reader.lines().enumerate() {
            let line = line?.trim().to_string();
            
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            if let Ok(network) = Ipv4Network::from_str(&line) {
                new_ranges.push(network);
                file_ranges += 1;
                debug!("[{}] Added CIDR range from {}: {}", self.domain, filename, network);
            } else if let Ok(ip) = Ipv4Addr::from_str(&line) {
                if new_ips.insert(ip) {
                    file_ips += 1;
                    debug!("[{}] Added IP from {}: {}", self.domain, filename, ip);
                } else {
                    debug!("[{}] Duplicate IP from {}: {} (skipped)", self.domain, filename, ip);
                }
            } else {
                warn!("[{}] Invalid line {} in {}: {}", self.domain, line_num + 1, filename, line);
            }
        }
        
        // Update shared structures
        {
            let mut ips = self.blocked_ips.write().unwrap();
            let mut ranges = self.blocked_ranges.write().unwrap();
            
            for ip in new_ips {
                ips.insert(ip);
            }
            for range in new_ranges {
                ranges.push(range);
            }
        }
        
        Ok((file_ips, file_ranges))
    }
    
    // Load IPs from a URL into this zone
    fn load_from_url(&self, url: &str) -> Result<(usize, usize), String> {
        let parsed_url = Url::parse(url)
            .map_err(|e| format!("Invalid URL {}: {}", url, e))?;
        
        if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
            return Err(format!("Unsupported URL scheme: {}. Use http:// or https://", parsed_url.scheme()));
        }
        
        info!("[{}] Downloading blocklist from {}", self.domain, url);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("DNSBL-Server/2.0 (https://www.tems.be)")
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
        
        let response = client.get(url)
            .send()
            .map_err(|e| format!("Failed to download {}: {}", url, e))?;
        
        if !response.status().is_success() {
            return Err(format!("HTTP error {} when downloading {}", response.status(), url));
        }
        
        let content = response.text()
            .map_err(|e| format!("Failed to read response body from {}: {}", url, e))?;
        
        debug!("[{}] Downloaded {} bytes from {}", self.domain, content.len(), url);
        
        let mut url_ips = 0;
        let mut url_ranges = 0;
        let mut new_ips = HashSet::new();
        let mut new_ranges = Vec::new();
        
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            if let Ok(network) = Ipv4Network::from_str(line) {
                new_ranges.push(network);
                url_ranges += 1;
                debug!("[{}] Added CIDR range from {}: {}", self.domain, url, network);
            } else if let Ok(ip) = Ipv4Addr::from_str(line) {
                if new_ips.insert(ip) {
                    url_ips += 1;
                    debug!("[{}] Added IP from {}: {}", self.domain, url, ip);
                } else {
                    debug!("[{}] Duplicate IP from {}: {} (skipped)", self.domain, url, ip);
                }
            } else {
                warn!("[{}] Invalid line {} in {}: {}", self.domain, line_num + 1, url, line);
            }
        }
        
        // Update shared structures
        {
            let mut ips = self.blocked_ips.write().unwrap();
            let mut ranges = self.blocked_ranges.write().unwrap();
            
            for ip in new_ips {
                ips.insert(ip);
            }
            for range in new_ranges {
                ranges.push(range);
            }
        }
        
        Ok((url_ips, url_ranges))
    }
}

// Structure principale du serveur
#[derive(Debug, Clone)]
struct DNSBLServer {
    zones: Arc<RwLock<HashMap<String, Zone>>>,
    default_response: Ipv4Addr,
}

impl DNSBLServer {
    fn new(default_response: Ipv4Addr) -> Self {
        DNSBLServer {
            zones: Arc::new(RwLock::new(HashMap::new())),
            default_response,
        }
    }

    // Check if a string is a URL
    fn is_url(s: &str) -> bool {
        s.starts_with("http://") || s.starts_with("https://")
    }

    // Add a new zone
    fn add_zone(&self, domain: &str, response_ip: Ipv4Addr) {
        let mut zones = self.zones.write().unwrap();
        let zone = Zone::new(domain, response_ip);
        zones.insert(domain.to_string(), zone);
        info!("Added zone: {} (response: {})", domain, response_ip);
    }

    // Load sources for the current/last zone
    fn load_sources_for_last_zone(&self, sources: &[String]) -> io::Result<()> {
        let zones = self.zones.read().unwrap();
        
        // Get the last zone added
        let last_zone = match zones.values().last() {
            Some(zone) => zone,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "No zone defined. Use -D to define a zone first."
                ));
            }
        };
        
        let mut total_ips = 0;
        let mut total_ranges = 0;
        
        for source in sources {
            if Self::is_url(source) {
                match last_zone.load_from_url(source) {
                    Ok((url_ips, url_ranges)) => {
                        total_ips += url_ips;
                        total_ranges += url_ranges;
                        info!("[{}] Loaded {} IPs and {} CIDR ranges from URL: {}", 
                              last_zone.domain, url_ips, url_ranges, source);
                    }
                    Err(e) => {
                        error!("[{}] Error loading blocklist from URL {}: {}", 
                               last_zone.domain, source, e);
                        return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
                    }
                }
            } else {
                match last_zone.load_from_file(source) {
                    Ok((file_ips, file_ranges)) => {
                        total_ips += file_ips;
                        total_ranges += file_ranges;
                        info!("[{}] Loaded {} IPs and {} CIDR ranges from file: {}", 
                              last_zone.domain, file_ips, file_ranges, source);
                    }
                    Err(e) => {
                        error!("[{}] Error loading blocklist file {}: {}", 
                               last_zone.domain, source, e);
                        return Err(e);
                    }
                }
            }
        }
        
        info!("[{}] Total for this zone: {} IPs, {} CIDR ranges from {} source(s)", 
              last_zone.domain, total_ips, total_ranges, sources.len());
        
        Ok(())
    }

    // Find zone by domain
    fn find_zone(&self, domain: &str) -> Option<Zone> {
        let zones = self.zones.read().unwrap();
        
        // Try exact match first
        if let Some(zone) = zones.get(domain) {
            return Some(zone.clone());
        }
        
        // Try suffix match (for subdomains)
        for (zone_domain, zone) in zones.iter() {
            if domain.ends_with(zone_domain) {
                return Some(zone.clone());
            }
        }
        
        None
    }

    // Process DNS query
    fn handle_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }

        // Transaction ID
        let id = &query[0..2];
        
        // Parse query to get domain
        let (domain, parse_success) = self.parse_query_domain(query);
        
        if !parse_success {
            return None;
        }
        
        let domain = match domain {
            Some(d) => d,
            None => return None,
        };
        
        debug!("Query received for domain: {}", domain);
        
        // Find matching zone
        let result = self.find_zone_and_check(&domain);
        
        // Build response
        let mut response = Vec::new();
        response.extend_from_slice(id);
        
        match result {
            Some((zone, ip)) => {
                // Blocked - return the zone's response IP
                info!("[{}] Blocked IP: {} (domain: {})", zone.domain, ip, domain);
                
                // Flags: QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=0, Z=0, RCODE=0
                response.extend_from_slice(&[0x81, 0x80]);
                // QDCOUNT = 1, ANCOUNT = 1
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                // NSCOUNT = 0, ARCOUNT = 0
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                
                // Copy question section from query
                self.copy_question_section(query, &mut response)?;
                
                // Answer section
                // Name pointer to question (0xC0 0x0C)
                response.extend_from_slice(&[0xC0, 0x0C]);
                // TYPE A, CLASS IN
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                // TTL 300 seconds
                response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
                // RDLENGTH 4
                response.extend_from_slice(&[0x00, 0x04]);
                // RDATA - zone's response IP
                response.extend_from_slice(&zone.response_ip.octets());
                
                Some(response)
            }
            None => {
                // Not blocked - NXDOMAIN
                debug!("IP not blocked (domain: {})", domain);
                
                // Flags: QR=1, AA=1, TC=0, RD=1, RCODE=3 (NXDOMAIN)
                response.extend_from_slice(&[0x81, 0x83]);
                // QDCOUNT = 1, ANCOUNT = 0
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
                // NSCOUNT = 0, ARCOUNT = 0
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                
                // Copy question section from query
                self.copy_question_section(query, &mut response)?;
                
                Some(response)
            }
        }
    }
    
    // Parse domain from query
    fn parse_query_domain(&self, query: &[u8]) -> (Option<String>, bool) {
        if query.len() < 12 {
            return (None, false);
        }
        
        let mut pos = 12;
        let mut domain_parts = Vec::new();
        
        while pos < query.len() && query[pos] != 0 {
            let len = query[pos] as usize;
            if pos + len + 1 >= query.len() {
                return (None, false);
            }
            
            let part = &query[pos + 1..pos + 1 + len];
            match String::from_utf8(part.to_vec()) {
                Ok(part_str) => domain_parts.push(part_str),
                Err(_) => return (None, false),
            }
            pos += len + 1;
            
            if pos >= query.len() {
                return (None, false);
            }
        }
        
        if domain_parts.is_empty() {
            return (None, true);
        }
        
        (Some(domain_parts.join(".")), true)
    }
    
    // Copy question section from query to response
    fn copy_question_section(&self, query: &[u8], response: &mut Vec<u8>) -> Option<()> {
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
            Some(())
        } else {
            None
        }
    }
    
    // Find zone and check if IP is blocked
    fn find_zone_and_check(&self, domain: &str) -> Option<(Zone, Ipv4Addr)> {
        // Try to find matching zone
        let zone = self.find_zone(domain)?;
        
        // Extract IP from domain (reverse format)
        let ip_part = domain.trim_end_matches(&format!(".{}", zone.domain));
        
        // Parse reverse format: d.c.b.a -> a.b.c.d
        let parts: Vec<&str> = ip_part.split('.').collect();
        if parts.len() < 4 {
            return None;
        }
        
        // Take last 4 octets and reverse
        let last_four = &parts[parts.len() - 4..];
        let octets: Result<Vec<u8>, _> = last_four
            .iter()
            .rev()
            .map(|s| s.parse::<u8>())
            .collect();
        
        let octets = match octets {
            Ok(o) if o.len() == 4 => o,
            _ => return None,
        };
        
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        
        // Check if IP is blocked in this zone
        if zone.is_blocked(ip) {
            Some((zone, ip))
        } else {
            None
        }
    }

    // Start server
    fn start(&self, interface: &str, verbose: bool) -> io::Result<()> {
        let socket_addr = if interface.contains(':') {
            SocketAddr::from_str(interface).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53)
        };
        
        let socket = match UdpSocket::bind(socket_addr) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to bind to {}: {}", socket_addr, e);
                error!("Make sure the port is not already in use and you have the required permissions (root for port 53)");
                return Err(e);
            }
        };
        
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        
        // Display zone information
        {
            let zones = self.zones.read().unwrap();
            info!("DNSBL server started on {} with {} zone(s):", socket_addr, zones.len());
            for (domain, zone) in zones.iter() {
                let ips = zone.blocked_ips.read().unwrap();
                let ranges = zone.blocked_ranges.read().unwrap();
                info!("  Zone: {} -> {} ({} IPs, {} CIDR ranges)", 
                      domain, zone.response_ip, ips.len(), ranges.len());
            }
        }
        
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
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
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
    
    if verbose {
        dispatch = dispatch.level_for("dnsbl_server", log::LevelFilter::Debug);
    }
    
    if let Some(log_file) = log_file {
        if let Some(parent) = Path::new(log_file).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        dispatch = dispatch.chain(fern::log_file(log_file)?);
    }
    
    dispatch = dispatch.chain(std::io::stdout());
    dispatch.apply()?;
    Ok(())
}

// Parse command line arguments
fn parse_args() -> Result<(Vec<ZoneConfig>, String, bool, bool, Option<String>), String> {
    let matches = App::new("DNSBL Server")
        .version("2.0.0")
        .author("Philippe TEMESI")
        .about("A multi-zone DNSBL server with support for local files and HTTP/HTTPS blocklists")
        .arg(
            Arg::with_name("domain")
                .short("D")
                .long("domain")
                .value_name("DOMAIN")
                .help("DNSBL domain (e.g., bl.tems.be). Can be specified multiple times for multiple zones")
                .takes_value(true)
                .multiple(true)
        )
        .arg(
            Arg::with_name("response")
                .short("r")
                .long("response")
                .value_name("IP")
                .help("Response IP for the current zone (e.g., 127.0.0.2). Must follow a -D option")
                .takes_value(true)
                .multiple(true)
        )
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("SOURCE")
                .help("Blocklist source: local file path or HTTP/HTTPS URL. Belongs to the last defined zone")
                .takes_value(true)
                .multiple(true)
        )
        .arg(
            Arg::with_name("daemon")
                .short("d")
                .long("daemon")
                .help("Run in daemon mode")
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
        .after_help("2026, Philippe TEMESI - https://www.tems.be\n\nEXAMPLES:\n  # Single zone with multiple sources\n  dnsbl-server -D bl.tems.be -r 127.0.0.2 -f blocklist.txt -f https://example.com/list.txt\n\n  # Multiple zones with different responses\n  dnsbl-server -D spam.tems.be -r 127.0.0.2 -f spam.txt -D malware.tems.be -r 127.0.0.3 -f malware.txt -f https://example.com/malware.list\n\n  # With custom port\n  dnsbl-server -D bl.tems.be -r 127.0.0.2 -f blocklist.txt -i 127.0.0.1:5453 -v")
        .get_matches();
    
    // Get domains and responses
    let domains = match matches.values_of_lossy("domain") {
        Some(d) => d,
        None => vec!["dnsbl.tems.be".to_string()], // Default domain
    };
    
    let responses = match matches.values_of_lossy("response") {
        Some(r) => r,
        None => vec!["127.0.0.2".to_string()], // Default response
    };
    
    if domains.len() != responses.len() {
        return Err(format!(
            "Number of domains ({}) must match number of responses ({})",
            domains.len(), responses.len()
        ));
    }
    
    // Get all file sources
    let all_sources = match matches.values_of_lossy("file") {
        Some(f) => f,
        None => Vec::new(),
    };
    
    // Group sources by zone based on order
    let mut zone_configs = Vec::new();
    let mut source_index = 0;
    
    for i in 0..domains.len() {
        let domain = &domains[i];
        let response_str = &responses[i];
        
        // Parse response IP
        let response_ip = Ipv4Addr::from_str(response_str)
            .map_err(|_| format!("Invalid response IP: {}", response_str))?;
        
        // Determine how many sources belong to this zone
        // Each zone gets sources until the next domain definition
        let mut zone_sources = Vec::new();
        
        while source_index < all_sources.len() {
            // Check if this source is actually a domain definition in disguise?
            // No, we just continue until we run out of sources
            zone_sources.push(all_sources[source_index].clone());
            source_index += 1;
        }
        
        zone_configs.push(ZoneConfig {
            domain: domain.clone(),
            response_ip,
            sources: zone_sources,
        });
    }
    
    let interface = matches.value_of("interface").unwrap().to_string();
    let verbose = matches.is_present("verbose");
    let daemon = matches.is_present("daemon");
    let log_file = matches.value_of("log").map(|s| s.to_string());
    
    Ok((zone_configs, interface, verbose, daemon, log_file))
}

struct ZoneConfig {
    domain: String,
    response_ip: Ipv4Addr,
    sources: Vec<String>,
}

fn main() {
    // Parse arguments
    let (zone_configs, interface, verbose, daemon_mode, log_file) = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    
    // Setup logging
    if let Err(e) = setup_logging(log_file.as_deref(), verbose) {
        eprintln!("Logging initialization error: {}", e);
        std::process::exit(1);
    }

    info!("DNSBL Server v2.0.0 - 2026, Philippe TEMESI");
    info!("Website: https://www.tems.be");

    // Daemon mode
    if daemon_mode {
        info!("Starting in daemon mode...");
        let daemonize = Daemonize::new()
            .pid_file("/tmp/dnsbl.pid")
            .chown_pid_file(true)
            .working_directory(".")
            .privileged_action(|| info!("Daemonized"));
        
        match daemonize.start() {
            Ok(_) => info!("Daemon started successfully"),
            Err(e) => {
                error!("Error starting daemon: {}", e);
                std::process::exit(1);
            }
        }
    }
    
    // Create server
    let default_response = if !zone_configs.is_empty() {
        zone_configs[0].response_ip
    } else {
        Ipv4Addr::new(127, 0, 0, 2)
    };
    
    let server = DNSBLServer::new(default_response);
    
    // Configure zones
    info!("Configuring {} zone(s):", zone_configs.len());
    
    for (i, config) in zone_configs.iter().enumerate() {
        info!("Zone {}: {} -> {}", i + 1, config.domain, config.response_ip);
        server.add_zone(&config.domain, config.response_ip);
        
        if !config.sources.is_empty() {
            info!("  Loading {} source(s) for zone {}...", config.sources.len(), config.domain);
            if let Err(e) = server.load_sources_for_last_zone(&config.sources) {
                error!("Error loading sources for zone {}: {}", config.domain, e);
                std::process::exit(1);
            }
        } else {
            warn!("  No sources defined for zone {}", config.domain);
        }
    }
    
    // Start server
    if let Err(e) = server.start(&interface, verbose) {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

