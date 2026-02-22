use std::collections::{HashSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::str::FromStr;
use std::io;

use log::{info, warn, debug};
use ipnetwork::Ipv4Network;
use trust_dns_proto::op::{Message, ResponseCode};
use trust_dns_proto::rr::{RecordType, Name, RData};
use trust_dns_proto::serialize::binary::{BinEncoder, BinDecoder, BinEncodable, BinDecodable};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use rand::RngCore;

use crate::dns::types::*;
use crate::zones::source::SourceType;
use crate::logging::dbl_saver::DblSaver;

#[derive(Debug, Clone, Default)]
pub struct ZoneData {
    pub blocked_ips: HashSet<Ipv4Addr>,
    pub blocked_ranges: Vec<Ipv4Network>,
}

impl ZoneData {
    pub fn new() -> Self {
        ZoneData {
            blocked_ips: HashSet::new(),
            blocked_ranges: Vec::new(),
        }
    }

    pub fn is_blocked(&self, ip: Ipv4Addr) -> bool {
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
pub struct Zone {
    pub domain: String,
    pub domain_lowercase: String,
    pub response_ip: Ipv4Addr,
    pub self_ip: Ipv4Addr,
    pub txt_records: Vec<TxtRecord>,
    pub mx_records: Vec<MxRecord>,
    pub sources: Vec<SourceType>,
    pub data: Arc<RwLock<ZoneData>>,
    pub dnsbl_forwarders: Arc<RwLock<HashMap<String, (Ipv4Addr, Instant)>>>,
    pub dnsbl_servers: Arc<RwLock<HashMap<String, DnsblServerInfo>>>,
    pub dbl_saver: Arc<DblSaver>,
}

impl Zone {
    pub fn new(domain: &str, response_ip: Ipv4Addr, self_ip: Ipv4Addr, 
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

    pub fn discover_ns_servers_recursive(&self, domain: &str) -> io::Result<Vec<Ipv4Addr>> {
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

    pub fn get_dnsbl_server(&self, dnsbl_domain: &str) -> Option<Ipv4Addr> {
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

    pub fn check_dnsbl(&self, dnsbl_domain: &str, ip: Ipv4Addr) -> bool {
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
        
        let server_addr = SocketAddr::new(std::net::IpAddr::V4(dns_server), 53);
        
        let mut msg = trust_dns_proto::op::Message::new();
        let id = rand::thread_rng().next_u32() as u16;
        msg.set_id(id);
        msg.set_message_type(trust_dns_proto::op::MessageType::Query);
        msg.set_recursion_desired(false);
        
        let name = match Name::from_utf8(query_domain) {
            Ok(n) => n,
            Err(e) => {
                debug!("Invalid domain name {}: {}", query_domain, e);
                return None;
            }
        };
        
        let query = trust_dns_proto::op::Query::query(name, RecordType::A);
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
                                            let ip_addr = ip;
                                            debug!("DNSBL returned: {}", ip_addr);
                                            return Some(ip_addr.0);
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
                            _ => {
                                debug!("DNS error");
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

    pub fn extract_ip_from_domain(&self, domain: &str) -> Option<Ipv4Addr> {
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

    pub fn is_test_query(&self, ip_octets: [u8; 4]) -> bool {
        ip_octets == TEST_IP_OCTETS
    }

    pub fn is_blocked(&self, ip: Ipv4Addr) -> (bool, Option<String>) {
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

    pub fn get_txt_for_ip(&self, ip: Ipv4Addr) -> Option<String> {
        if self.txt_records.is_empty() {
            return None;
        }
        
        Some(self.txt_records[0].with_substitution(ip))
    }

    pub fn load_from_sources(&self) -> Result<ZoneData, String> {
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
                            warn!("[{}] Error loading from URL {}: {}", self.domain, url, e);
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
                            warn!("[{}] Error loading from file {}: {}", self.domain, filename, e);
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
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        use std::path::Path;
        
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
        use reqwest::blocking::Client;
        use url::Url;
        use std::time::Duration;
        
        let parsed_url = Url::parse(url)
            .map_err(|e| format!("Invalid URL {}: {}", url, e))?;
        
        if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
            return Err(format!("Unsupported URL scheme: {}. Use http:// or https://", parsed_url.scheme()));
        }
        
        debug!("[{}] Downloading blocklist from {}", self.domain, url);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("DNSBL-Server/2.9 (https://www.tems.be)")
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
        
        let response = match client.get(url).send() {
            Ok(r) => r,
            Err(e) => {
                return Err(format!("Failed to download {}: {}", url, e));
            }
        };
        
        if !response.status().is_success() {
            return Err(format!("HTTP error {} when downloading {}", response.status(), url));
        }
        
        let content = match response.text() {
            Ok(c) => c,
            Err(e) => {
                return Err(format!("Failed to read response body from {}: {}", url, e));
            }
        };
        
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

    pub fn update_data(&self, new_data: ZoneData) {
        let mut data = self.data.write().unwrap();
        *data = new_data;
    }
}

