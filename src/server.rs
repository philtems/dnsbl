use std::collections::{HashSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::thread;

use clap::{App, Arg};
use daemonize::Daemonize;
use ipnetwork::{Ipv4Network, IpNetwork};
use log::{info, warn, error, debug};
use reqwest::blocking::Client;
use url::Url;
use rand::RngCore;

use trust_dns_proto::op::{Message, MessageType, Query, ResponseCode};
use trust_dns_proto::rr::{RecordType, Name, RData};
use trust_dns_proto::serialize::binary::{BinEncoder, BinDecoder, BinEncodable, BinDecodable};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

// Constantes DNS
const NS_RECORD_TTL: u32 = 86400;
const A_RECORD_TTL: u32 = 300;
const TXT_RECORD_TTL: u32 = 3600;
const MX_RECORD_TTL: u32 = 3600;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const TEST_IP_PREFIX: [u8; 4] = [127, 0, 0, 2];
const TEST_IP_OCTETS: [u8; 4] = [2, 0, 0, 127];

#[derive(Debug, Clone)]
enum SourceType {
    Http(String),
    File(String),
    Dnsbl(String),
}

#[derive(Clone)]
struct QueryLogger {
    enabled: bool,
    file: Option<Arc<RwLock<File>>>,
}

impl QueryLogger {
    fn new(filename: Option<String>) -> io::Result<Self> {
        match filename {
            Some(path) => {
                if let Some(parent) = Path::new(&path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let file = File::create(path)?;
                Ok(QueryLogger {
                    enabled: true,
                    file: Some(Arc::new(RwLock::new(file))),
                })
            }
            None => Ok(QueryLogger {
                enabled: false,
                file: None,
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn log_query(&self, src: SocketAddr, domain: &str, qtype: u16, 
                 response_code: u8, response_ip: Option<Ipv4Addr>, 
                 response_txt: Option<&str>, source: Option<&str>,
                 action: Option<&str>) {
        if !self.enabled {
            return;
        }

        if let Some(file_lock) = &self.file {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let qtype_str = match qtype {
                1 => "A",
                2 => "NS",
                5 => "CNAME",
                6 => "SOA",
                12 => "PTR",
                15 => "MX",
                16 => "TXT",
                28 => "AAAA",
                48 => "DNSKEY",
                255 => "ANY",
                _ => "UNKNOWN",
            };
            
            let status = if let Some(action) = action {
                format!("ACTION:{}", action)
            } else if response_code == 0 {
                match qtype {
                    1 => format!("A_RESPONSE {}", response_ip.unwrap_or(Ipv4Addr::UNSPECIFIED)),
                    2 => "NS_RESPONSE".to_string(),
                    6 => "SOA_RESPONSE".to_string(),
                    15 => format!("MX_RESPONSE {}", response_ip.unwrap_or(Ipv4Addr::UNSPECIFIED)),
                    16 => format!("TXT_RESPONSE \"{}\"", response_txt.unwrap_or("")),
                    _ => "RESPONSE".to_string(),
                }
            } else {
                match response_code {
                    3 => "NXDOMAIN".to_string(),
                    4 => "NOTIMP".to_string(),
                    5 => "REFUSED".to_string(),
                    _ => format!("ERROR_{}", response_code),
                }
            };
            
            let source_info = match source {
                Some(s) => format!(" [source:{}]", s),
                None => "".to_string(),
            };
            
            let log_line = format!("[{}] {} {} {} {}{}\n", 
                timestamp, src.ip(), domain, qtype_str, status, source_info);
            
            if let Ok(mut file) = file_lock.write() {
                let _ = file.write_all(log_line.as_bytes());
                let _ = file.flush();
            }
        }
    }
}

#[derive(Debug, Clone)]
struct DblSaver {
    enabled: bool,
    file: Option<Arc<RwLock<File>>>,
    saved_ips: Arc<RwLock<HashSet<Ipv4Addr>>>,
}

impl DblSaver {
    fn new(filename: Option<String>) -> io::Result<Self> {
        match filename {
            Some(path) => {
                if let Some(parent) = Path::new(&path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let file = File::create(path)?;
                Ok(DblSaver {
                    enabled: true,
                    file: Some(Arc::new(RwLock::new(file))),
                    saved_ips: Arc::new(RwLock::new(HashSet::new())),
                })
            }
            None => Ok(DblSaver {
                enabled: false,
                file: None,
                saved_ips: Arc::new(RwLock::new(HashSet::new())),
            }),
        }
    }

    fn save_ip(&self, ip: Ipv4Addr) {
        if !self.enabled {
            return;
        }

        let mut saved = self.saved_ips.write().unwrap();
        if saved.insert(ip) {
            if let Some(file_lock) = &self.file {
                let line = format!("{}\n", ip);
                if let Ok(mut file) = file_lock.write() {
                    let _ = file.write_all(line.as_bytes());
                    let _ = file.flush();
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct AccessControl {
    max_requests_per_minute: usize,
    exempt_ips: Vec<IpNetwork>,
    deny_ips: Vec<IpNetwork>,
    requests: Arc<RwLock<HashMap<IpAddr, (usize, Instant)>>>,
}

impl AccessControl {
    fn new(max_requests_per_minute: usize, exempt_ips: Vec<IpNetwork>, deny_ips: Vec<IpNetwork>) -> Self {
        AccessControl {
            max_requests_per_minute,
            exempt_ips,
            deny_ips,
            requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn check(&self, ip: IpAddr) -> (bool, Option<&'static str>, Option<String>) {
        for denied in &self.deny_ips {
            match denied {
                IpNetwork::V4(net) => {
                    if let IpAddr::V4(ip_v4) = ip {
                        if net.contains(ip_v4) {
                            return (false, Some("DENIED"), Some(format!("in deny list: {}", net)));
                        }
                    }
                }
                IpNetwork::V6(net) => {
                    if let IpAddr::V6(ip_v6) = ip {
                        if net.contains(ip_v6) {
                            return (false, Some("DENIED"), Some(format!("in deny list: {}", net)));
                        }
                    }
                }
            }
        }

        for exempt in &self.exempt_ips {
            match exempt {
                IpNetwork::V4(net) => {
                    if let IpAddr::V4(ip_v4) = ip {
                        if net.contains(ip_v4) {
                            return (true, Some("EXEMPT"), Some(format!("exempt from rate limit: {}", net)));
                        }
                    }
                }
                IpNetwork::V6(net) => {
                    if let IpAddr::V6(ip_v6) = ip {
                        if net.contains(ip_v6) {
                            return (true, Some("EXEMPT"), Some(format!("exempt from rate limit: {}", net)));
                        }
                    }
                }
            }
        }

        if self.max_requests_per_minute == 0 {
            return (true, None, None);
        }

        let now = Instant::now();
        let mut requests = self.requests.write().unwrap();

        requests.retain(|_, (_, timestamp)| now.duration_since(*timestamp) < Duration::from_secs(60));

        let entry = requests.entry(ip).or_insert((0, now));
        
        if entry.0 >= self.max_requests_per_minute {
            if now.duration_since(entry.1) >= Duration::from_secs(60) {
                *entry = (1, now);
                (true, None, None)
            } else {
                (false, Some("RATE_LIMITED"), Some(format!("exceeded {} requests/minute", self.max_requests_per_minute)))
            }
        } else {
            entry.0 += 1;
            (true, None, None)
        }
    }

    fn get_stats(&self) -> HashMap<IpAddr, usize> {
        let now = Instant::now();
        let requests = self.requests.read().unwrap();
        
        requests.iter()
            .map(|(ip, (count, timestamp))| {
                if now.duration_since(*timestamp) < Duration::from_secs(60) {
                    (*ip, *count)
                } else {
                    (*ip, 0)
                }
            })
            .collect()
    }
}

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

#[derive(Debug, Clone)]
struct TxtRecord {
    text: String,
}

impl TxtRecord {
    fn with_substitution(&self, ip: Ipv4Addr) -> String {
        let octets = ip.octets();
        let dotted = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
        let reversed = format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]);
        
        self.text
            .replace("@dotted", &dotted)
            .replace("@reversed", &reversed)
            .replace("@", &dotted)
    }
}

#[derive(Debug, Clone)]
struct MxRecord {
    server: String,
    priority: u16,
}

#[derive(Debug, Clone)]
struct DnsblServerInfo {
    name_servers: Vec<Ipv4Addr>,
    last_update: Instant,
    current_index: usize,
}

impl DnsblServerInfo {
    fn new() -> Self {
        DnsblServerInfo {
            name_servers: Vec::new(),
            last_update: Instant::now(),
            current_index: 0,
        }
    }

    fn needs_update(&self) -> bool {
        self.name_servers.is_empty() || self.last_update.elapsed() > Duration::from_secs(3600)
    }

    fn get_next_server(&mut self) -> Option<Ipv4Addr> {
        if self.name_servers.is_empty() {
            return None;
        }
        
        let server = self.name_servers[self.current_index];
        self.current_index = (self.current_index + 1) % self.name_servers.len();
        Some(server)
    }
}

#[derive(Debug, Clone)]
struct Zone {
    domain: String,
    domain_lowercase: String,
    response_ip: Ipv4Addr,
    self_ip: Ipv4Addr,
    txt_records: Vec<TxtRecord>,
    mx_records: Vec<MxRecord>,
    sources: Vec<SourceType>,
    data: Arc<RwLock<ZoneData>>,
    dnsbl_forwarders: Arc<RwLock<HashMap<String, (Ipv4Addr, Instant)>>>,
    dnsbl_servers: Arc<RwLock<HashMap<String, DnsblServerInfo>>>,
    dbl_saver: Arc<DblSaver>,
}

impl Zone {
    fn new(domain: &str, response_ip: Ipv4Addr, self_ip: Ipv4Addr, 
           txt_records: Vec<TxtRecord>, mx_records: Vec<MxRecord>,
           sources: Vec<SourceType>, dbl_saver: Arc<DblSaver>) -> Self {
        Zone {
            domain: domain.to_string(),
            domain_lowercase: domain.to_lowercase(),
            response_ip,
            self_ip,
            txt_records,
            mx_records,
            sources,
            data: Arc::new(RwLock::new(ZoneData::new())),
            dnsbl_forwarders: Arc::new(RwLock::new(HashMap::new())),
            dnsbl_servers: Arc::new(RwLock::new(HashMap::new())),
            dbl_saver,
        }
    }

    fn discover_ns_servers_recursive(&self, domain: &str) -> io::Result<Vec<Ipv4Addr>> {
        debug!("[{}] Attempting NS discovery for {}", self.domain, domain);
        
        match self.discover_ns_servers_for_domain(domain) {
            Ok(servers) if !servers.is_empty() => {
                debug!("[{}] Found NS servers for {}", self.domain, domain);
                return Ok(servers);
            }
            _ => {
                debug!("[{}] No NS found for {}", self.domain, domain);
            }
        }
        
        let parts: Vec<&str> = domain.split('.').collect();
        
        if parts.len() <= 2 {
            debug!("[{}] Cannot strip further, minimum domain reached", self.domain);
            return Err(io::Error::new(io::ErrorKind::Other, "No NS found"));
        }
        
        let parent_domain = parts[1..].join(".");
        debug!("[{}] Trying parent domain: {}", self.domain, parent_domain);
        
        self.discover_ns_servers_recursive(&parent_domain)
    }

    fn discover_ns_servers_for_domain(&self, domain: &str) -> io::Result<Vec<Ipv4Addr>> {
        debug!("[{}] Discovering NS records for {} using trust-dns", self.domain, domain);
        
        let mut ns_servers = Vec::new();
        let mut ns_names = Vec::new();
        
        let resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
            Ok(r) => r,
            Err(e) => {
                debug!("Failed to create resolver: {}", e);
                return Err(io::Error::new(io::ErrorKind::Other, "Failed to create resolver"));
            }
        };
        
        match resolver.ns_lookup(domain) {
            Ok(lookup) => {
                for ns in lookup.iter() {
                    let ns_name = ns.0.to_string();
                    let ns_name = ns_name.trim_end_matches('.').to_string();
                    debug!("Found NS: {}", ns_name);
                    ns_names.push(ns_name);
                }
            }
            Err(e) => {
                debug!("NS lookup failed for {}: {}", domain, e);
                return Err(io::Error::new(io::ErrorKind::Other, format!("NS lookup failed: {}", e)));
            }
        }
        
        if ns_names.is_empty() {
            debug!("No NS records found");
            return Err(io::Error::new(io::ErrorKind::Other, "No NS records found"));
        }
        
        for ns_name in ns_names {
            debug!("Resolving NS name: {}", ns_name);
            
            match resolver.ipv4_lookup(&ns_name) {
                Ok(lookup) => {
                    for a in lookup.iter() {
                        let ip_addr = a.0;
                        debug!("Resolved {} to {}", ns_name, ip_addr);
                        ns_servers.push(ip_addr);
                    }
                }
                Err(e) => {
                    debug!("Failed to resolve {}: {}", ns_name, e);
                }
            }
        }
        
        ns_servers.sort();
        ns_servers.dedup();
        
        if ns_servers.is_empty() {
            debug!("No NS IPs found after resolution");
            Err(io::Error::new(io::ErrorKind::Other, "No NS IPs found"))
        } else {
            info!("[{}] Found {} NS servers for {}", self.domain, ns_servers.len(), domain);
            debug!("NS servers: {:?}", ns_servers);
            Ok(ns_servers)
        }
    }

    fn get_dnsbl_server(&self, dnsbl_domain: &str) -> Option<Ipv4Addr> {
        let mut servers = self.dnsbl_servers.write().unwrap();
        
        let server_info = servers.entry(dnsbl_domain.to_string())
            .or_insert_with(DnsblServerInfo::new);
        
        if server_info.needs_update() {
            debug!("[{}] Discovering NS records for DNSBL: {}", self.domain, dnsbl_domain);
            match self.discover_ns_servers_recursive(dnsbl_domain) {
                Ok(ns_servers) if !ns_servers.is_empty() => {
                    info!("[{}] Found {} NS servers for {}", self.domain, ns_servers.len(), dnsbl_domain);
                    server_info.name_servers = ns_servers;
                    server_info.last_update = Instant::now();
                    server_info.current_index = 0;
                }
                _ => {
                    warn!("[{}] Failed to discover NS servers for {}, will use fallback", 
                          self.domain, dnsbl_domain);
                    server_info.name_servers = vec![
                        Ipv4Addr::new(8,8,8,8),
                        Ipv4Addr::new(1,1,1,1),
                        Ipv4Addr::new(9,9,9,9),
                    ];
                }
            }
        }
        
        server_info.get_next_server()
    }

    fn check_dnsbl(&self, dnsbl_domain: &str, ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        let query_domain = format!("{}.{}.{}.{}.{}",
            octets[3], octets[2], octets[1], octets[0],
            dnsbl_domain);
        
        debug!("[{}] Checking DNSBL {} for IP {} -> {}", 
               self.domain, dnsbl_domain, ip, query_domain);
        
        let now = Instant::now();
        
        {
            let mut cache = self.dnsbl_forwarders.write().unwrap();
            cache.retain(|_, (_, timestamp)| now.duration_since(*timestamp) < Duration::from_secs(300));
            
            if let Some(&(result, _)) = cache.get(&query_domain) {
                debug!("[{}] Cache hit for {}: {}", self.domain, query_domain, result);
                return result != Ipv4Addr::UNSPECIFIED;
            }
        }
        
        if let Some(dns_server) = self.get_dnsbl_server(dnsbl_domain) {
            debug!("[{}] Using DNS server {} for {}", self.domain, dns_server, dnsbl_domain);
            
            match self.resolve_dnsbl_query_with_server(&query_domain, dns_server) {
                Some(ip_result) if ip_result != Ipv4Addr::UNSPECIFIED => {
                    debug!("[{}] DNSBL returned: {} for {}", self.domain, ip_result, query_domain);
                    self.dbl_saver.save_ip(ip);
                    let mut cache = self.dnsbl_forwarders.write().unwrap();
                    cache.insert(query_domain, (ip_result, now));
                    true
                }
                Some(_) => {
                    debug!("[{}] DNSBL returned NXDOMAIN for {}", self.domain, query_domain);
                    let mut cache = self.dnsbl_forwarders.write().unwrap();
                    cache.insert(query_domain, (Ipv4Addr::UNSPECIFIED, now));
                    false
                }
                None => {
                    debug!("[{}] DNSBL query failed for {}", self.domain, query_domain);
                    false
                }
            }
        } else {
            debug!("[{}] No specific DNS server, using fallback for {}", self.domain, query_domain);
            match self.resolve_dnsbl_query_fallback(&query_domain) {
                Some(ip_result) if ip_result != Ipv4Addr::UNSPECIFIED => {
                    self.dbl_saver.save_ip(ip);
                    let mut cache = self.dnsbl_forwarders.write().unwrap();
                    cache.insert(query_domain, (ip_result, now));
                    true
                }
                _ => false
            }
        }
    }

    fn resolve_dnsbl_query_with_server(&self, query_domain: &str, dns_server: Ipv4Addr) -> Option<Ipv4Addr> {
        use std::net::UdpSocket;
        
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to bind socket: {}", e);
                return None;
            }
        };
        
        if let Err(e) = socket.set_read_timeout(Some(DNS_QUERY_TIMEOUT)) {
            debug!("Failed to set timeout: {}", e);
            return None;
        }
        
        let server_addr = SocketAddr::new(IpAddr::V4(dns_server), 53);
        
        let mut msg = Message::new();
        let id = rand::thread_rng().next_u32() as u16;
        msg.set_id(id);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(false);
        
        let name = match Name::from_utf8(query_domain) {
            Ok(n) => n,
            Err(e) => {
                debug!("Invalid domain name {}: {}", query_domain, e);
                return None;
            }
        };
        
        let query = Query::query(name, RecordType::A);
        msg.add_query(query);
        
        let mut buf = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            if msg.emit(&mut encoder).is_err() {
                debug!("Failed to encode DNS query");
                return None;
            }
        }
        
        debug!("Sending DNS query to {}:{}: {} bytes", dns_server, 53, buf.len());
        
        if let Err(e) = socket.send_to(&buf, server_addr) {
            debug!("Send error: {}", e);
            return None;
        }
        
        let mut recv_buf = [0u8; 512];
        match socket.recv_from(&mut recv_buf) {
            Ok((size, _)) => {
                let mut decoder = BinDecoder::new(&recv_buf[..size]);
                match Message::read(&mut decoder) {
                    Ok(response) => {
                        if response.id() != id {
                            debug!("ID mismatch");
                            return None;
                        }
                        
                        match response.response_code() {
                            ResponseCode::NoError => {
                                for answer in response.answers() {
                                    if let Some(rdata) = answer.data() {
                                        if let RData::A(ip) = rdata {
                                            let ip_addr = ip.0;
                                            debug!("DNSBL returned: {}", ip_addr);
                                            return Some(ip_addr);
                                        }
                                    }
                                }
                                debug!("No A records in response");
                                None
                            }
                            ResponseCode::NXDomain => {
                                debug!("DNSBL returned NXDOMAIN");
                                Some(Ipv4Addr::UNSPECIFIED)
                            }
                            code => {
                                debug!("DNS error: {:?}", code);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to decode response: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                debug!("Receive error: {}", e);
                None
            }
        }
    }

    fn resolve_dnsbl_query_fallback(&self, query_domain: &str) -> Option<Ipv4Addr> {
        let resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
            Ok(r) => r,
            Err(e) => {
                debug!("Failed to create resolver: {}", e);
                return None;
            }
        };
        
        match resolver.ipv4_lookup(query_domain) {
            Ok(lookup) => {
                for a in lookup.iter() {
                    let ip_addr = a.0;
                    debug!("Fallback resolver returned: {}", ip_addr);
                    return Some(ip_addr);
                }
                None
            }
            Err(e) => {
                debug!("Fallback resolver failed: {}", e);
                None
            }
        }
    }

    fn extract_ip_from_domain(&self, domain: &str) -> Option<Ipv4Addr> {
        let domain_lower = domain.to_lowercase();
        let zone_domain_lower = self.domain_lowercase.to_lowercase();
        
        if !domain_lower.ends_with(&format!(".{}", zone_domain_lower)) {
            return None;
        }
        
        let ip_part = &domain_lower[..domain_lower.len() - zone_domain_lower.len() - 1];
        
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
        
        Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    }

    fn is_test_query(&self, ip_octets: [u8; 4]) -> bool {
        ip_octets == TEST_IP_OCTETS
    }

    fn is_blocked(&self, ip: Ipv4Addr) -> (bool, Option<String>) {
        if self.is_test_query(ip.octets()) {
            debug!("[{}] Test query detected for IP {}, returning positive", self.domain, ip);
            return (true, Some("test".to_string()));
        }

        {
            let data = self.data.read().unwrap();
            if data.is_blocked(ip) {
                debug!("[{}] IP {} blocked by local data", self.domain, ip);
                return (true, Some("local".to_string()));
            }
        }
        
        for source in &self.sources {
            if let SourceType::Dnsbl(dnsbl_domain) = source {
                debug!("[{}] Checking DNSBL {} for IP {}", self.domain, dnsbl_domain, ip);
                let blocked = self.check_dnsbl(dnsbl_domain, ip);
                if blocked {
                    debug!("[{}] IP {} blocked by DNSBL {}", self.domain, ip, dnsbl_domain);
                    return (true, Some(format!("dnsbl:{}", dnsbl_domain)));
                }
            }
        }
        
        debug!("[{}] IP {} not blocked", self.domain, ip);
        (false, None)
    }

    fn get_txt_for_ip(&self, ip: Ipv4Addr) -> Option<String> {
        if self.txt_records.is_empty() {
            return None;
        }
        
        Some(self.txt_records[0].with_substitution(ip))
    }

    fn load_from_sources(&self) -> Result<ZoneData, String> {
        let mut new_data = ZoneData::new();
        let mut total_ips = 0;
        let mut total_ranges = 0;
        
        for source in &self.sources {
            match source {
                SourceType::Http(url) => {
                    match self.load_from_url(url, &mut new_data) {
                        Ok((url_ips, url_ranges)) => {
                            total_ips += url_ips;
                            total_ranges += url_ranges;
                            info!("[{}] Loaded {} IPs and {} CIDR ranges from URL: {}", 
                                  self.domain, url_ips, url_ranges, url);
                        }
                        Err(e) => {
                            error!("[{}] Error loading from URL {}: {}", self.domain, url, e);
                            return Err(format!("Failed to load {}: {}", url, e));
                        }
                    }
                }
                SourceType::File(filename) => {
                    match self.load_from_file(filename, &mut new_data) {
                        Ok((file_ips, file_ranges)) => {
                            total_ips += file_ips;
                            total_ranges += file_ranges;
                            info!("[{}] Loaded {} IPs and {} CIDR ranges from file: {}", 
                                  self.domain, file_ips, file_ranges, filename);
                        }
                        Err(e) => {
                            error!("[{}] Error loading from file {}: {}", self.domain, filename, e);
                            return Err(format!("Failed to load {}: {}", filename, e));
                        }
                    }
                }
                SourceType::Dnsbl(domain) => {
                    info!("[{}] Registered DNSBL forwarder: {}", self.domain, domain);
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
            .user_agent("DNSBL-Server/2.8 (https://www.tems.be)")
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

#[derive(Clone)]
struct DNSBLServer {
    zones: Arc<HashMap<String, Zone>>,
    zones_by_lowercase: Arc<HashMap<String, String>>,
    access_control: Arc<AccessControl>,
    query_logger: Arc<QueryLogger>,
}

impl DNSBLServer {
    fn with_zones_and_access_control(zones: HashMap<String, Zone>, access_control: AccessControl, 
                                     query_logger: QueryLogger) -> Self {
        let mut zones_by_lowercase = HashMap::new();
        for (domain, zone) in &zones {
            zones_by_lowercase.insert(zone.domain_lowercase.clone(), domain.clone());
        }
        
        DNSBLServer {
            zones: Arc::new(zones),
            zones_by_lowercase: Arc::new(zones_by_lowercase),
            access_control: Arc::new(access_control),
            query_logger: Arc::new(query_logger),
        }
    }

    fn find_zone(&self, domain: &str) -> Option<&Zone> {
        let domain_lower = domain.to_lowercase();
        
        if let Some(original_domain) = self.zones_by_lowercase.get(&domain_lower) {
            return self.zones.get(original_domain);
        }
        
        for (zone_domain_lower, original_domain) in self.zones_by_lowercase.iter() {
            if domain_lower.ends_with(zone_domain_lower) {
                return self.zones.get(original_domain);
            }
        }
        
        None
    }

    fn handle_query(&self, query: &[u8], src_addr: SocketAddr) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }

        let (allowed, action, reason) = self.access_control.check(src_addr.ip());
        
        if !allowed {
            warn!("Access denied for IP {}: {}", src_addr.ip(), reason.unwrap_or_default());
            
            let (domain, parse_success, qtype_bytes) = self.parse_query_domain_with_type(query);
            if parse_success {
                if let Some(domain) = domain {
                    let qtype_value = u16::from_be_bytes([qtype_bytes[0], qtype_bytes[1]]);
                    self.query_logger.log_query(
                        src_addr, &domain, qtype_value, 5,
                        None, None, None, action
                    );
                }
            }
            
            return None;
        }

        let id = &query[0..2];
        
        let (domain, parse_success, qtype_bytes) = self.parse_query_domain_with_type(query);
        
        if !parse_success {
            return None;
        }
        
        let domain = match domain {
            Some(d) => d,
            None => return None,
        };
        
        let qtype_value = u16::from_be_bytes([qtype_bytes[0], qtype_bytes[1]]);
        debug!("Query received for domain: {} (type: {}) from {}", 
               domain, self.qtype_to_string(&qtype_bytes), src_addr);

        if self.is_self_domain_query(&domain) {
            let (response, response_code) = self.handle_self_domain_query(id, query, &domain, &qtype_bytes);
            
            if let Some(ref _resp) = response {
                self.query_logger.log_query(
                    src_addr, &domain, qtype_value, 
                    response_code, 
                    Some(self.find_zone(&domain).unwrap().self_ip),
                    None,
                    None,
                    action
                );
            }
            
            return response;
        }
        
        if qtype_value == 1 {
            let (result, source, ip) = self.find_zone_and_check_a(&domain);
            
            let mut response = Vec::new();
            response.extend_from_slice(id);
            
            match result {
                Some(zone) => {
                    info!("[{}] Blocked IP: {} (domain: {} from {})", 
                          zone.domain, ip.unwrap(), domain, src_addr.ip());
                    
                    response.extend_from_slice(&[0x81, 0x80]);
                    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                    
                    if self.copy_question_section(query, &mut response).is_none() {
                        return None;
                    }
                    
                    response.extend_from_slice(&[0xC0, 0x0C]);
                    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                    response.extend_from_slice(&A_RECORD_TTL.to_be_bytes());
                    response.extend_from_slice(&[0x00, 0x04]);
                    response.extend_from_slice(&zone.response_ip.octets());
                    
                    self.query_logger.log_query(
                        src_addr, &domain, qtype_value, 0, 
                        Some(zone.response_ip), None, source.as_deref(),
                        action
                    );
                    
                    Some(response)
                }
                None => {
                    debug!("IP not blocked (domain: {} from {})", domain, src_addr.ip());
                    
                    response.extend_from_slice(&[0x81, 0x83]);
                    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
                    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                    
                    if self.copy_question_section(query, &mut response).is_none() {
                        return None;
                    }
                    
                    self.query_logger.log_query(
                        src_addr, &domain, qtype_value, 3, None, None, None,
                        action
                    );
                    
                    Some(response)
                }
            }
        } else if qtype_value == 16 {
            let (result, source, ip, txt_opt) = self.find_zone_and_check_txt(&domain);
            
            let mut response = Vec::new();
            response.extend_from_slice(id);
            
            match result {
                Some(zone) => {
                    info!("[{}] TXT query for IP: {} (domain: {} from {})", 
                          zone.domain, ip.unwrap(), domain, src_addr.ip());
                    
                    if let Some(txt) = txt_opt {
                        response.extend_from_slice(&[0x81, 0x80]);
                        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                        
                        if self.copy_question_section(query, &mut response).is_none() {
                            return None;
                        }
                        
                        let txt_data = txt.as_bytes();
                        let txt_len = 1 + txt_data.len();
                        
                        response.extend_from_slice(&[0xC0, 0x0C]);
                        response.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);
                        response.extend_from_slice(&TXT_RECORD_TTL.to_be_bytes());
                        response.extend_from_slice(&(txt_len as u16).to_be_bytes());
                        
                        response.push(txt_data.len() as u8);
                        response.extend_from_slice(txt_data);
                        
                        self.query_logger.log_query(
                            src_addr, &domain, qtype_value, 0, 
                            None, Some(&txt), source.as_deref(),
                            action
                        );
                        
                        Some(response)
                    } else {
                        response.extend_from_slice(&[0x81, 0x83]);
                        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
                        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                        
                        if self.copy_question_section(query, &mut response).is_none() {
                            return None;
                        }
                        
                        self.query_logger.log_query(
                            src_addr, &domain, qtype_value, 3, None, None, source.as_deref(),
                            action
                        );
                        
                        Some(response)
                    }
                }
                None => {
                    debug!("TXT not found (domain: {} from {})", domain, src_addr.ip());
                    
                    response.extend_from_slice(&[0x81, 0x83]);
                    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
                    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                    
                    if self.copy_question_section(query, &mut response).is_none() {
                        return None;
                    }
                    
                    self.query_logger.log_query(
                        src_addr, &domain, qtype_value, 3, None, None, None,
                        action
                    );
                    
                    Some(response)
                }
            }
        } else {
            let mut response = Vec::new();
            response.extend_from_slice(id);
            response.extend_from_slice(&[0x81, 0x04]);
            response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
            response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            
            if self.copy_question_section(query, &mut response).is_none() {
                return None;
            }
            
            self.query_logger.log_query(
                src_addr, &domain, qtype_value, 4, None, None, None,
                action
            );
            
            Some(response)
        }
    }
    
    fn is_self_domain_query(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.zones_by_lowercase.contains_key(&domain_lower)
    }
    
    fn handle_self_domain_query(&self, id: &[u8], query: &[u8], domain: &str, 
                                qtype: &[u8]) -> (Option<Vec<u8>>, u8) {
        let zone = match self.find_zone(domain) {
            Some(z) => z,
            None => return (None, 4),
        };
        
        let qtype_value = u16::from_be_bytes([qtype[0], qtype[1]]);
        
        info!("Self-domain query for: {} (type: {})", 
              domain, self.qtype_to_string(qtype));
        
        let mut response = Vec::new();
        response.extend_from_slice(id);
        
        match qtype_value {
            1 => {
                response.extend_from_slice(&[0x81, 0x80]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                
                if self.copy_question_section(query, &mut response).is_none() {
                    return (None, 2);
                }
                
                response.extend_from_slice(&[0xC0, 0x0C]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                response.extend_from_slice(&A_RECORD_TTL.to_be_bytes());
                response.extend_from_slice(&[0x00, 0x04]);
                response.extend_from_slice(&zone.self_ip.octets());
                
                (Some(response), 0)
            }
            
            2 => {
                response.extend_from_slice(&[0x81, 0x80]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]);
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                
                if self.copy_question_section(query, &mut response).is_none() {
                    return (None, 2);
                }
                
                response.extend_from_slice(&[0xC0, 0x0C]);
                response.extend_from_slice(&[0x00, 0x02, 0x00, 0x01]);
                response.extend_from_slice(&NS_RECORD_TTL.to_be_bytes());
                
                let ns_name = self.domain_to_labels(domain);
                let ns_name_len = ns_name.len() as u16;
                response.extend_from_slice(&ns_name_len.to_be_bytes());
                response.extend_from_slice(&ns_name);
                
                response.extend_from_slice(&[0xC0, 0x0C]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                response.extend_from_slice(&A_RECORD_TTL.to_be_bytes());
                response.extend_from_slice(&[0x00, 0x04]);
                response.extend_from_slice(&zone.self_ip.octets());
                
                (Some(response), 0)
            }
            
            6 => {
                response.extend_from_slice(&[0x81, 0x80]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                
                if self.copy_question_section(query, &mut response).is_none() {
                    return (None, 2);
                }
                
                response.extend_from_slice(&[0xC0, 0x0C]);
                response.extend_from_slice(&[0x00, 0x06, 0x00, 0x01]);
                response.extend_from_slice(&NS_RECORD_TTL.to_be_bytes());
                
                let mname = self.domain_to_labels(domain);
                let rname = self.domain_to_labels(&format!("hostmaster.{}", domain));
                
                let soa_len = mname.len() + rname.len() + 20;
                response.extend_from_slice(&(soa_len as u16).to_be_bytes());
                
                response.extend_from_slice(&mname);
                response.extend_from_slice(&rname);
                
                response.extend_from_slice(&1u32.to_be_bytes());
                response.extend_from_slice(&7200u32.to_be_bytes());
                response.extend_from_slice(&3600u32.to_be_bytes());
                response.extend_from_slice(&86400u32.to_be_bytes());
                response.extend_from_slice(&300u32.to_be_bytes());
                
                (Some(response), 0)
            }
            
            15 => {
                if zone.mx_records.is_empty() {
                    return (None, 4);
                }
                
                response.extend_from_slice(&[0x81, 0x80]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                
                if self.copy_question_section(query, &mut response).is_none() {
                    return (None, 2);
                }
                
                let mx = &zone.mx_records[0];
                
                response.extend_from_slice(&[0xC0, 0x0C]);
                response.extend_from_slice(&[0x00, 0x0F, 0x00, 0x01]);
                response.extend_from_slice(&MX_RECORD_TTL.to_be_bytes());
                
                let mx_name = self.domain_to_labels(&mx.server);
                let mx_len = 2 + mx_name.len();
                response.extend_from_slice(&(mx_len as u16).to_be_bytes());
                
                response.extend_from_slice(&mx.priority.to_be_bytes());
                response.extend_from_slice(&mx_name);
                
                (Some(response), 0)
            }
            
            16 => {
                if zone.txt_records.is_empty() {
                    return (None, 4);
                }
                
                response.extend_from_slice(&[0x81, 0x80]);
                response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                
                if self.copy_question_section(query, &mut response).is_none() {
                    return (None, 2);
                }
                
                let txt = &zone.txt_records[0];
                let txt_data = txt.text.as_bytes();
                let txt_len = 1 + txt_data.len();
                
                response.extend_from_slice(&[0xC0, 0x0C]);
                response.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);
                response.extend_from_slice(&TXT_RECORD_TTL.to_be_bytes());
                response.extend_from_slice(&(txt_len as u16).to_be_bytes());
                
                response.push(txt_data.len() as u8);
                response.extend_from_slice(txt_data);
                
                (Some(response), 0)
            }
            
            _ => {
                (None, 4)
            }
        }
    }
    
    fn parse_query_domain_with_type(&self, query: &[u8]) -> (Option<String>, bool, [u8; 2]) {
        if query.len() < 12 {
            return (None, false, [0, 0]);
        }
        
        let mut pos = 12;
        let mut domain_parts = Vec::new();
        
        while pos < query.len() && query[pos] != 0 {
            let len = query[pos] as usize;
            if pos + len + 1 >= query.len() {
                return (None, false, [0, 0]);
            }
            
            let part = &query[pos + 1..pos + 1 + len];
            match String::from_utf8(part.to_vec()) {
                Ok(part_str) => domain_parts.push(part_str),
                Err(_) => return (None, false, [0, 0]),
            }
            pos += len + 1;
            
            if pos >= query.len() {
                return (None, false, [0, 0]);
            }
        }
        
        if pos >= query.len() {
            return (None, false, [0, 0]);
        }
        
        pos += 1;
        
        if pos + 4 <= query.len() {
            let qtype = [query[pos], query[pos+1]];
            (Some(domain_parts.join(".")), true, qtype)
        } else {
            (None, false, [0, 0])
        }
    }
    
    fn domain_to_labels(&self, domain: &str) -> Vec<u8> {
        let mut result = Vec::new();
        for part in domain.split('.') {
            result.push(part.len() as u8);
            result.extend_from_slice(part.as_bytes());
        }
        result.push(0);
        result
    }
    
    fn qtype_to_string(&self, qtype: &[u8]) -> String {
        if qtype.len() < 2 {
            return "UNKNOWN".to_string();
        }
        let value = u16::from_be_bytes([qtype[0], qtype[1]]);
        match value {
            1 => "A".to_string(),
            2 => "NS".to_string(),
            5 => "CNAME".to_string(),
            6 => "SOA".to_string(),
            12 => "PTR".to_string(),
            15 => "MX".to_string(),
            16 => "TXT".to_string(),
            28 => "AAAA".to_string(),
            48 => "DNSKEY".to_string(),
            255 => "ANY".to_string(),
            _ => format!("TYPE-{}", value),
        }
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
    
    fn find_zone_and_check_a(&self, domain: &str) -> (Option<&Zone>, Option<String>, Option<Ipv4Addr>) {
        let zone = match self.find_zone(domain) {
            Some(z) => z,
            None => return (None, None, None),
        };
        
        let ip = match zone.extract_ip_from_domain(domain) {
            Some(ip) => ip,
            None => return (None, None, None),
        };
        
        let (blocked, source) = zone.is_blocked(ip);
        if blocked {
            (Some(zone), source, Some(ip))
        } else {
            (None, None, None)
        }
    }
    
    fn find_zone_and_check_txt(&self, domain: &str) -> (Option<&Zone>, Option<String>, Option<Ipv4Addr>, Option<String>) {
        let zone = match self.find_zone(domain) {
            Some(z) => z,
            None => return (None, None, None, None),
        };
        
        let ip = match zone.extract_ip_from_domain(domain) {
            Some(ip) => ip,
            None => return (None, None, None, None),
        };
        
        let (blocked, source) = zone.is_blocked(ip);
        if blocked {
            let txt = zone.get_txt_for_ip(ip);
            (Some(zone), source, Some(ip), txt)
        } else {
            (None, None, None, None)
        }
    }

    fn start(&self, interface: &str, verbose: bool, stats_interval: Option<u64>) -> io::Result<()> {
        let socket_addr = if interface.contains(':') {
            SocketAddr::from_str(interface).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53)
        };
        
        let socket = UdpSocket::bind(socket_addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        
        info!("DNSBL server v2.8.0 started on {}", socket_addr);
        info!("Self-domain A/NS/SOA/MX/TXT record support enabled (case-insensitive)");
        info!("TXT record IP substitution enabled (@, @dotted, @reversed)");
        info!("Real-time DNSBL forwarding support enabled with recursive NS discovery");
        info!("Test query support enabled (2.0.0.127.* -> {})", Ipv4Addr::from(TEST_IP_PREFIX));
        
        if self.query_logger.enabled {
            info!("Query logging enabled");
        }
        
        if !self.access_control.deny_ips.is_empty() {
            info!("Deny list: {} IPs/ranges", self.access_control.deny_ips.len());
        }
        if !self.access_control.exempt_ips.is_empty() {
            info!("Exempt list: {} IPs/ranges", self.access_control.exempt_ips.len());
        }
        if self.access_control.max_requests_per_minute > 0 {
            info!("Rate limiting: {} requests per minute", self.access_control.max_requests_per_minute);
        } else {
            info!("Rate limiting: disabled");
        }
        
        for zone in self.zones.values() {
            let dnsbl_count = zone.sources.iter()
                .filter(|s| matches!(s, SourceType::Dnsbl(_)))
                .count();
            info!("Zone: {} -> {} (self: {}, TXT: {}, MX: {}, {} sources, {} DNSBL forwarders)",
                  zone.domain, zone.response_ip, zone.self_ip, 
                  zone.txt_records.len(), zone.mx_records.len(),
                  zone.sources.len(), dnsbl_count);
        }
        
        info!("Press Ctrl+C to stop the server");
        
        if let Some(interval) = stats_interval {
            let access_control = self.access_control.clone();
            thread::spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(interval));
                    let stats = access_control.get_stats();
                    if !stats.is_empty() {
                        debug!("Rate limiting stats:");
                        for (ip, count) in stats {
                            debug!("  {}: {} requests in last minute", ip, count);
                        }
                    }
                }
            });
        }
        
        let mut buf = [0u8; 512];
        
        loop {
            match socket.recv_from(&mut buf) {
                Ok((size, src_addr)) => {
                    if verbose {
                        debug!("Request received from {}", src_addr);
                    }
                    
                    if let Some(response) = self.handle_query(&buf[..size], src_addr) {
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

fn read_source_file(filename: &str) -> io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut sources = Vec::new();
    
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?.trim().to_string();
        if !line.is_empty() && !line.starts_with('#') {
            if line.starts_with("http://") || line.starts_with("https://") || 
               line.starts_with("dnsbl://") || Path::new(&line).exists() {
                sources.push(line);
            } else {
                warn!("Invalid source at line {}: {} (ignored)", line_num + 1, line);
            }
        }
    }
    
    Ok(sources)
}

fn read_ip_list_file(filename: &str) -> io::Result<Vec<IpNetwork>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut ips = Vec::new();
    
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        if let Ok(network) = IpNetwork::from_str(&line) {
            ips.push(network);
        } else if let Ok(ip) = IpAddr::from_str(&line) {
            let network = match ip {
                IpAddr::V4(ipv4) => IpNetwork::V4(Ipv4Network::new(ipv4, 32).unwrap()),
                IpAddr::V6(ipv6) => IpNetwork::V6(ipnetwork::Ipv6Network::new(ipv6, 128).unwrap()),
            };
            ips.push(network);
        } else {
            warn!("Invalid IP or CIDR range at line {}: {} (ignored)", line_num + 1, line);
        }
    }
    
    Ok(ips)
}

struct ZoneConfig {
    domain: String,
    response_ip: Ipv4Addr,
    self_ip: Ipv4Addr,
    txt_records: Vec<TxtRecord>,
    mx_records: Vec<MxRecord>,
    sources: Vec<String>,
}

struct AccessControlConfig {
    max_requests_per_minute: usize,
    exempt_ips: Vec<IpNetwork>,
    deny_ips: Vec<IpNetwork>,
    stats_interval: u64,
}

fn parse_args() -> Result<(Vec<ZoneConfig>, String, bool, bool, Option<String>, u64, 
                          AccessControlConfig, Option<String>, Option<String>), String> {
    let matches = App::new("DNSBL Server")
        .version("2.8.0")
        .author("Philippe TEMESI")
        .about("A multi-zone DNSBL server with NS/SOA/MX/TXT record support and real-time DNSBL forwarding")
        .arg(Arg::with_name("domain")
            .short("D")
            .long("domain")
            .value_name("DOMAIN")
            .help("DNSBL domain")
            .takes_value(true)
            .multiple(true))
        .arg(Arg::with_name("response")
            .short("r")
            .long("response")
            .value_name("IP")
            .help("Response IP for blocked queries")
            .takes_value(true)
            .multiple(true))
        .arg(Arg::with_name("self-ip")
            .short("s")
            .long("self-ip")
            .value_name("IP")
            .help("IP address to return for A/NS/SOA queries on the domain itself")
            .takes_value(true)
            .multiple(true))
        .arg(Arg::with_name("txt")
            .long("txt")
            .value_name("TEXT")
            .help("TXT record for the domain (supports @, @dotted, @reversed substitution)")
            .takes_value(true)
            .multiple(true))
        .arg(Arg::with_name("mx")
            .long("mx")
            .value_name("SERVER,PRIORITY")
            .help("MX record for the domain (format: server,priority)")
            .takes_value(true)
            .multiple(true))
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .value_name("SOURCE")
            .help("Blocklist source (file, http://, https://, or dnsbl://domain)")
            .takes_value(true)
            .multiple(true))
        .arg(Arg::with_name("file-list")
            .short("F")
            .long("file-list")
            .value_name("FILE")
            .help("File containing one source per line")
            .takes_value(true)
            .multiple(true))
        .arg(Arg::with_name("reload")
            .short("R")
            .long("reload")
            .value_name("MINUTES")
            .help("Auto-reload interval in minutes")
            .takes_value(true)
            .default_value("0"))
        .arg(Arg::with_name("max-requests")
            .long("max-requests")
            .value_name("COUNT")
            .help("Maximum number of requests per minute per IP (0 = unlimited)")
            .takes_value(true)
            .default_value("0"))
        .arg(Arg::with_name("no-request-limit")
            .long("no-request-limit")
            .value_name("IP,RANGE,...")
            .help("Comma-separated list of IPs or CIDR ranges exempt from rate limiting")
            .takes_value(true))
        .arg(Arg::with_name("no-request-limit-file")
            .long("no-request-limit-file")
            .value_name("FILE")
            .help("File containing IPs or CIDR ranges exempt from rate limiting (one per line)")
            .takes_value(true))
        .arg(Arg::with_name("deny-file")
            .long("deny-file")
            .value_name("FILE")
            .help("File containing IPs or CIDR ranges not allowed to query the server (one per line)")
            .takes_value(true))
        .arg(Arg::with_name("stats-interval")
            .long("stats-interval")
            .value_name("SECONDS")
            .help("Interval for rate limiting stats logging (0 = disabled)")
            .takes_value(true)
            .default_value("0"))
        .arg(Arg::with_name("query-log")
            .long("query-log")
            .value_name("FILE")
            .help("Log all DNS queries to this file")
            .takes_value(true))
        .arg(Arg::with_name("dbl-save")
            .long("dbl-save")
            .value_name("FILE")
            .help("Save IPs found in remote DNSBLs to this file (one IP per line)")
            .takes_value(true))
        .arg(Arg::with_name("daemon")
            .short("d")
            .long("daemon")
            .help("Run in daemon mode"))
        .arg(Arg::with_name("interface")
            .short("i")
            .long("interface")
            .value_name("INTERFACE")
            .help("Listening interface")
            .takes_value(true)
            .default_value("0.0.0.0:53"))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Verbose mode"))
        .arg(Arg::with_name("log")
            .short("l")
            .long("log")
            .value_name("LOG_FILE")
            .help("Log file")
            .takes_value(true))
        .get_matches();
    
    let reload_minutes = matches.value_of("reload").unwrap_or("0").parse::<u64>()
        .map_err(|_| "Invalid reload interval")?;
    
    let max_requests = matches.value_of("max-requests").unwrap_or("0").parse::<usize>()
        .map_err(|_| "Invalid max-requests value")?;
    
    let stats_interval = matches.value_of("stats-interval").unwrap_or("0").parse::<u64>()
        .map_err(|_| "Invalid stats-interval value")?;
    
    let query_log = matches.value_of("query-log").map(String::from);
    let dbl_save = matches.value_of("dbl-save").map(String::from);
    
    let mut exempt_ips = Vec::new();
    
    if let Some(no_limit_input) = matches.value_of("no-request-limit") {
        for item in no_limit_input.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            
            if let Ok(network) = IpNetwork::from_str(item) {
                exempt_ips.push(network);
                info!("Added exempt network from CLI: {}", network);
                continue;
            }
            
            if let Ok(ip) = IpAddr::from_str(item) {
                let network = match ip {
                    IpAddr::V4(ipv4) => IpNetwork::V4(Ipv4Network::new(ipv4, 32).unwrap()),
                    IpAddr::V6(ipv6) => IpNetwork::V6(ipnetwork::Ipv6Network::new(ipv6, 128).unwrap()),
                };
                exempt_ips.push(network);
                info!("Added exempt IP from CLI: {} as {}", ip, network);
                continue;
            }
            
            return Err(format!("Invalid IP or CIDR range in --no-request-limit: {}", item));
        }
    }
    
    if let Some(no_limit_file) = matches.value_of("no-request-limit-file") {
        match read_ip_list_file(no_limit_file) {
            Ok(ips) => {
                info!("Loaded {} exempt IPs/ranges from file: {}", ips.len(), no_limit_file);
                exempt_ips.extend(ips);
            }
            Err(e) => {
                return Err(format!("Error reading no-request-limit-file {}: {}", no_limit_file, e));
            }
        }
    }
    
    let mut deny_ips = Vec::new();
    if let Some(deny_file) = matches.value_of("deny-file") {
        match read_ip_list_file(deny_file) {
            Ok(ips) => {
                info!("Loaded {} denied IPs/ranges from file: {}", ips.len(), deny_file);
                deny_ips = ips;
            }
            Err(e) => {
                return Err(format!("Error reading deny-file {}: {}", deny_file, e));
            }
        }
    }
    
    let domains = matches.values_of_lossy("domain").unwrap_or_else(|| vec!["dnsbl.tems.be".to_string()]);
    let responses = matches.values_of_lossy("response").unwrap_or_else(|| vec!["127.0.0.2".to_string()]);
    let self_ips = matches.values_of_lossy("self-ip").unwrap_or_else(|| {
        vec!["127.0.0.2".to_string()]
    });
    
    let txt_records_all = matches.values_of_lossy("txt").unwrap_or_default();
    let mx_records_all = matches.values_of_lossy("mx").unwrap_or_default();
    
    if domains.len() != responses.len() {
        return Err(format!(
            "Number of domains ({}) must match number of response IPs ({})",
            domains.len(), responses.len()
        ));
    }
    
    if domains.len() != self_ips.len() {
        return Err(format!(
            "Number of domains ({}) must match number of self IPs ({})",
            domains.len(), self_ips.len()
        ));
    }
    
    let mut all_sources = matches.values_of_lossy("file").unwrap_or_default();
    
    if let Some(file_lists) = matches.values_of_lossy("file-list") {
        for list_file in file_lists {
            match read_source_file(&list_file) {
                Ok(sources) => {
                    info!("Loaded {} sources from file: {}", sources.len(), list_file);
                    all_sources.extend(sources);
                }
                Err(e) => {
                    return Err(format!("Error reading file list {}: {}", list_file, e));
                }
            }
        }
    }
    
    let mut zone_configs = Vec::new();
    let mut source_index = 0;
    
    for i in 0..domains.len() {
        let response_ip = Ipv4Addr::from_str(&responses[i])
            .map_err(|_| format!("Invalid response IP: {}", responses[i]))?;
        
        let self_ip = Ipv4Addr::from_str(&self_ips[i])
            .map_err(|_| format!("Invalid self IP: {}", self_ips[i]))?;
        
        let mut zone_sources = Vec::new();
        
        if i < domains.len() - 1 {
            let sources_per_zone = if !all_sources.is_empty() { all_sources.len() / domains.len() } else { 0 };
            let start = i * sources_per_zone;
            let end = start + sources_per_zone;
            for j in start..end.min(all_sources.len()) {
                zone_sources.push(all_sources[j].clone());
            }
        } else {
            while source_index < all_sources.len() {
                zone_sources.push(all_sources[source_index].clone());
                source_index += 1;
            }
        }
        
        let mut zone_txt = Vec::new();
        let mut zone_mx = Vec::new();
        
        if i < txt_records_all.len() {
            zone_txt.push(TxtRecord {
                text: txt_records_all[i].clone(),
            });
        }
        
        if i < mx_records_all.len() {
            let parts: Vec<&str> = mx_records_all[i].split(',').collect();
            if parts.len() == 2 {
                if let Ok(priority) = parts[1].parse::<u16>() {
                    zone_mx.push(MxRecord {
                        server: parts[0].to_string(),
                        priority,
                    });
                } else {
                    warn!("Invalid MX priority for {}: {}", domains[i], mx_records_all[i]);
                }
            } else {
                warn!("Invalid MX format for {}: {} (expected server,priority)", 
                      domains[i], mx_records_all[i]);
            }
        }
        
        zone_configs.push(ZoneConfig {
            domain: domains[i].clone(),
            response_ip,
            self_ip,
            txt_records: zone_txt,
            mx_records: zone_mx,
            sources: zone_sources,
        });
    }
    
    let access_control_config = AccessControlConfig {
        max_requests_per_minute: max_requests,
        exempt_ips,
        deny_ips,
        stats_interval,
    };
    
    Ok((
        zone_configs,
        matches.value_of("interface").unwrap().to_string(),
        matches.is_present("verbose"),
        matches.is_present("daemon"),
        matches.value_of("log").map(String::from),
        reload_minutes,
        access_control_config,
        query_log,
        dbl_save,
    ))
}

fn main() {
    let (zone_configs, interface, verbose, daemon_mode, log_file, reload_minutes, 
         access_config, query_log, dbl_save) = match parse_args() {
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

    info!("DNSBL Server v2.8.0 - 2026, Philippe TEMESI");
    info!("Self-domain A/NS/SOA/MX/TXT record support enabled (case-insensitive)");
    info!("TXT record IP substitution enabled (@, @dotted, @reversed)");
    info!("Real-time DNSBL forwarding support enabled with recursive NS discovery");
    info!("Test query support enabled (2.0.0.127.*)");

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
    
    let query_logger = match QueryLogger::new(query_log) {
        Ok(logger) => logger,
        Err(e) => {
            error!("Failed to create query logger: {}", e);
            std::process::exit(1);
        }
    };
    
    let dbl_saver = match DblSaver::new(dbl_save) {
        Ok(saver) => Arc::new(saver),
        Err(e) => {
            error!("Failed to create DBL saver: {}", e);
            std::process::exit(1);
        }
    };
    
    let mut zones_map = HashMap::new();
    
    for config in zone_configs {
        let mut typed_sources = Vec::new();
        
        for source in config.sources {
            if source.starts_with("http://") || source.starts_with("https://") {
                typed_sources.push(SourceType::Http(source));
            } else if source.starts_with("dnsbl://") {
                let domain = source.trim_start_matches("dnsbl://").to_string();
                typed_sources.push(SourceType::Dnsbl(domain));
            } else {
                typed_sources.push(SourceType::File(source));
            }
        }
        
        info!("Creating zone: {} -> {} (self: {}, TXT: {}, MX: {}, {} sources)", 
              config.domain, config.response_ip, config.self_ip, 
              config.txt_records.len(), config.mx_records.len(),
              typed_sources.len());
        
        let zone = Zone::new(
            &config.domain, 
            config.response_ip, 
            config.self_ip,
            config.txt_records,
            config.mx_records,
            typed_sources,
            dbl_saver.clone(),
        );
        zones_map.insert(config.domain.clone(), zone);
    }
    
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
    
    let access_control = AccessControl::new(
        access_config.max_requests_per_minute,
        access_config.exempt_ips,
        access_config.deny_ips,
    );
    
    let server = DNSBLServer::with_zones_and_access_control(zones_map, access_control, query_logger);
    
    if reload_minutes > 0 {
        start_reloader(server.zones.clone(), reload_minutes);
    }
    
    let stats_interval = if access_config.stats_interval > 0 {
        Some(access_config.stats_interval)
    } else {
        None
    };
    
    if let Err(e) = server.start(&interface, verbose, stats_interval) {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

