use std::collections::{HashSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::thread;

use clap::{App, Arg};
use daemonize::Daemonize;
use ipnetwork::Ipv4Network;
use log::{info, warn, error, debug};
use reqwest::blocking::Client;
use url::Url;

// Structure pour les données d'une zone
#[derive(Debug, Clone, Default)]
struct ZoneData {
    blocked_ips: HashSet<Ipv4Addr>,
    blocked_ranges: Vec<Ipv4Network>,
}

impl ZoneData {
    fn new() -> Self {
        ZoneData {
            blocked_ips: HashSet::new(),
            blocked_ranges: Vec::new(),
        }
    }

    fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        if self.blocked_ips.contains(&ip) {
            return true;
        }
        
        for range in &self.blocked_ranges {
            if range.contains(ip) {
                return true;
            }
        }
        
        false
    }
}

// Structure pour une zone DNSBL
#[derive(Debug, Clone)]
struct Zone {
    domain: String,
    response_ip: Ipv4Addr,
    sources: Vec<String>,
    data: Arc<RwLock<ZoneData>>,
}

impl Zone {
    fn new(domain: &str, response_ip: Ipv4Addr, sources: Vec<String>) -> Self {
        Zone {
            domain: domain.to_string(),
            response_ip,
            sources,
            data: Arc::new(RwLock::new(ZoneData::new())),
        }
    }

    fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        let data = self.data.read().unwrap();
        data.is_blocked(ip)
    }

    fn load_from_sources(&self) -> Result<ZoneData, String> {
        let mut new_data = ZoneData::new();
        let mut total_ips = 0;
        let mut total_ranges = 0;
        
        for source in &self.sources {
            if source.starts_with("http://") || source.starts_with("https://") {
                match self.load_from_url(source, &mut new_data) {
                    Ok((url_ips, url_ranges)) => {
                        total_ips += url_ips;
                        total_ranges += url_ranges;
                        info!("[{}] Loaded {} IPs and {} CIDR ranges from URL: {}", 
                              self.domain, url_ips, url_ranges, source);
                    }
                    Err(e) => {
                        error!("[{}] Error loading from URL {}: {}", self.domain, source, e);
                        return Err(format!("Failed to load {}: {}", source, e));
                    }
                }
            } else {
                match self.load_from_file(source, &mut new_data) {
                    Ok((file_ips, file_ranges)) => {
                        total_ips += file_ips;
                        total_ranges += file_ranges;
                        info!("[{}] Loaded {} IPs and {} CIDR ranges from file: {}", 
                              self.domain, file_ips, file_ranges, source);
                    }
                    Err(e) => {
                        error!("[{}] Error loading from file {}: {}", self.domain, source, e);
                        return Err(format!("Failed to load {}: {}", source, e));
                    }
                }
            }
        }
        
        info!("[{}] Total loaded: {} IPs, {} CIDR ranges", 
              self.domain, total_ips, total_ranges);
        
        Ok(new_data)
    }

    fn load_from_file(&self, filename: &str, data: &mut ZoneData) -> io::Result<(usize, usize)> {
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
        
        for (line_num, line) in reader.lines().enumerate() {
            let line = line?.trim().to_string();
            
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            if let Ok(network) = Ipv4Network::from_str(&line) {
                data.blocked_ranges.push(network);
                file_ranges += 1;
                debug!("[{}] Added CIDR range from {}: {}", self.domain, filename, network);
            } else if let Ok(ip) = Ipv4Addr::from_str(&line) {
                if data.blocked_ips.insert(ip) {
                    file_ips += 1;
                    debug!("[{}] Added IP from {}: {}", self.domain, filename, ip);
                }
            } else {
                warn!("[{}] Invalid line {} in {}: {}", self.domain, line_num + 1, filename, line);
            }
        }
        
        Ok((file_ips, file_ranges))
    }
    
    fn load_from_url(&self, url: &str, data: &mut ZoneData) -> Result<(usize, usize), String> {
        let parsed_url = Url::parse(url)
            .map_err(|e| format!("Invalid URL {}: {}", url, e))?;
        
        if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
            return Err(format!("Unsupported URL scheme: {}. Use http:// or https://", parsed_url.scheme()));
        }
        
        debug!("[{}] Downloading blocklist from {}", self.domain, url);
        
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
        
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            if let Ok(network) = Ipv4Network::from_str(line) {
                data.blocked_ranges.push(network);
                url_ranges += 1;
                debug!("[{}] Added CIDR range from {}: {}", self.domain, url, network);
            } else if let Ok(ip) = Ipv4Addr::from_str(line) {
                if data.blocked_ips.insert(ip) {
                    url_ips += 1;
                    debug!("[{}] Added IP from {}: {}", self.domain, url, ip);
                }
            } else {
                warn!("[{}] Invalid line {} in {}: {}", self.domain, line_num + 1, url, line);
            }
        }
        
        Ok((url_ips, url_ranges))
    }

    fn update_data(&self, new_data: ZoneData) {
        let mut data = self.data.write().unwrap();
        *data = new_data;
    }
}

// Structure principale du serveur
#[derive(Clone)]
struct DNSBLServer {
    zones: Arc<HashMap<String, Zone>>,
}

impl DNSBLServer {
    fn new() -> Self {
        DNSBLServer {
            zones: Arc::new(HashMap::new()),
        }
    }

    fn with_zones(zones: HashMap<String, Zone>) -> Self {
        DNSBLServer {
            zones: Arc::new(zones),
        }
    }

    fn find_zone(&self, domain: &str) -> Option<&Zone> {
        // Try exact match first
        if let Some(zone) = self.zones.get(domain) {
            return Some(zone);
        }
        
        // Try suffix match
        for (zone_domain, zone) in self.zones.iter() {
            if domain.ends_with(zone_domain) {
                return Some(zone);
            }
        }
        
        None
    }

    fn handle_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }

        let id = &query[0..2];
        
        let (domain, parse_success) = self.parse_query_domain(query);
        
        if !parse_success {
            return None;
        }
        
        let domain = match domain {
            Some(d) => d,
            None => return None,
        };
        
        debug!("Query received for domain: {}", domain);
        
        let result = self.find_zone_and_check(&domain);
        
        let mut response = Vec::new();
        response.extend_from_slice(id);
        
        match result {
            Some((zone, ip)) => {
                info!("[{}] Blocked IP: {} (domain: {})", zone.domain, ip, domain);
                
                response.extend_from_slice(&[0x81, 0x80]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                
                self.copy_question_section(query, &mut response)?;
                
                response.extend_from_slice(&[0xC0, 0x0C]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
                response.extend_from_slice(&[0x00, 0x04]);
                response.extend_from_slice(&zone.response_ip.octets());
                
                Some(response)
            }
            None => {
                debug!("IP not blocked (domain: {})", domain);
                
                response.extend_from_slice(&[0x81, 0x83]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                
                self.copy_question_section(query, &mut response)?;
                
                Some(response)
            }
        }
    }
    
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
        response.push(0);
        
        if pos + 4 <= query.len() {
            response.extend_from_slice(&query[pos + 1..pos + 5]);
            Some(())
        } else {
            None
        }
    }
    
    fn find_zone_and_check(&self, domain: &str) -> Option<(&Zone, Ipv4Addr)> {
        let zone = self.find_zone(domain)?;
        
        let ip_part = domain.trim_end_matches(&format!(".{}", zone.domain));
        
        let parts: Vec<&str> = ip_part.split('.').collect();
        if parts.len() < 4 {
            return None;
        }
        
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
        
        if zone.is_blocked(ip) {
            Some((zone, ip))
        } else {
            None
        }
    }

    fn start(&self, interface: &str, verbose: bool) -> io::Result<()> {
        let socket_addr = if interface.contains(':') {
            SocketAddr::from_str(interface).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53)
        };
        
        let socket = UdpSocket::bind(socket_addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        
        info!("DNSBL server started on {}", socket_addr);
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

// Fonction de rechargement qui tourne dans un thread séparé
fn start_reloader(zones: Arc<HashMap<String, Zone>>, interval_minutes: u64) {
    if interval_minutes == 0 {
        return;
    }

    let interval = Duration::from_secs(interval_minutes * 60);
    
    info!("Starting auto-reloader thread (interval: {} minutes)", interval_minutes);
    
    thread::spawn(move || {
        loop {
            thread::sleep(interval);
            
            info!("Auto-reload triggered");
            
            // Recharger chaque zone
            for zone in zones.values() {
                info!("[{}] Reloading...", zone.domain);
                
                match zone.load_from_sources() {
                    Ok(new_data) => {
                        zone.update_data(new_data);
                        info!("[{}] Reload complete", zone.domain);
                    }
                    Err(e) => {
                        error!("[{}] Reload failed: {}", zone.domain, e);
                    }
                }
            }
        }
    });
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
fn parse_args() -> Result<(Vec<ZoneConfig>, String, bool, bool, Option<String>, u64), String> {
    let matches = App::new("DNSBL Server")
        .version("2.1.0")
        .author("Philippe TEMESI")
        .about("A multi-zone DNSBL server")
        .arg(
            Arg::with_name("domain")
                .short("D")
                .long("domain")
                .value_name("DOMAIN")
                .help("DNSBL domain")
                .takes_value(true)
                .multiple(true)
        )
        .arg(
            Arg::with_name("response")
                .short("r")
                .long("response")
                .value_name("IP")
                .help("Response IP for the current zone")
                .takes_value(true)
                .multiple(true)
        )
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("SOURCE")
                .help("Blocklist source")
                .takes_value(true)
                .multiple(true)
        )
        .arg(
            Arg::with_name("reload")
                .short("R")
                .long("reload")
                .value_name("MINUTES")
                .help("Auto-reload interval in minutes")
                .takes_value(true)
                .default_value("0")
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
                .help("Listening interface")
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
        .get_matches();
    
    let reload_minutes = matches.value_of("reload").unwrap_or("0").parse::<u64>()
        .map_err(|_| "Invalid reload interval")?;
    
    let domains = matches.values_of_lossy("domain").unwrap_or_else(|| vec!["dnsbl.tems.be".to_string()]);
    let responses = matches.values_of_lossy("response").unwrap_or_else(|| vec!["127.0.0.2".to_string()]);
    
    if domains.len() != responses.len() {
        return Err(format!(
            "Number of domains ({}) must match number of responses ({})",
            domains.len(), responses.len()
        ));
    }
    
    let all_sources = matches.values_of_lossy("file").unwrap_or_default();
    
    let mut zone_configs = Vec::new();
    let mut source_index = 0;
    
    for i in 0..domains.len() {
        let response_ip = Ipv4Addr::from_str(&responses[i])
            .map_err(|_| format!("Invalid response IP: {}", responses[i]))?;
        
        let mut zone_sources = Vec::new();
        
        if i == domains.len() - 1 {
            while source_index < all_sources.len() {
                zone_sources.push(all_sources[source_index].clone());
                source_index += 1;
            }
        }
        
        zone_configs.push(ZoneConfig {
            domain: domains[i].clone(),
            response_ip,
            sources: zone_sources,
        });
    }
    
    Ok((
        zone_configs,
        matches.value_of("interface").unwrap().to_string(),
        matches.is_present("verbose"),
        matches.is_present("daemon"),
        matches.value_of("log").map(String::from),
        reload_minutes,
    ))
}

struct ZoneConfig {
    domain: String,
    response_ip: Ipv4Addr,
    sources: Vec<String>,
}

fn main() {
    let (zone_configs, interface, verbose, daemon_mode, log_file, reload_minutes) = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    
    if let Err(e) = setup_logging(log_file.as_deref(), verbose) {
        eprintln!("Logging initialization error: {}", e);
        std::process::exit(1);
    }

    info!("DNSBL Server v2.1.0 - 2026, Philippe TEMESI");

    if daemon_mode {
        info!("Starting in daemon mode...");
        let daemonize = Daemonize::new()
            .pid_file("/tmp/dnsbl.pid")
            .chown_pid_file(true)
            .working_directory(".");
        
        if let Err(e) = daemonize.start() {
            error!("Error starting daemon: {}", e);
            std::process::exit(1);
        }
        info!("Daemon started successfully");
    }
    
    // Créer les zones
    let mut zones_map = HashMap::new();
    
    for config in zone_configs {
        info!("Creating zone: {} -> {} ({} sources)", 
              config.domain, config.response_ip, config.sources.len());
        
        let zone = Zone::new(&config.domain, config.response_ip, config.sources);
        zones_map.insert(config.domain.clone(), zone);
    }
    
    // Chargement initial
    info!("Performing initial load...");
    for zone in zones_map.values() {
        match zone.load_from_sources() {
            Ok(data) => {
                zone.update_data(data);
                info!("[{}] Initial load complete", zone.domain);
            }
            Err(e) => {
                error!("[{}] Initial load failed: {}", zone.domain, e);
                std::process::exit(1);
            }
        }
    }
    
    // Créer le serveur avec les zones chargées
    let server = DNSBLServer::with_zones(zones_map);
    
    // Démarrer le reloader si nécessaire
    if reload_minutes > 0 {
        start_reloader(server.zones.clone(), reload_minutes);
    }
    
    // Démarrer le serveur (ne retourne jamais)
    if let Err(e) = server.start(&interface, verbose) {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

