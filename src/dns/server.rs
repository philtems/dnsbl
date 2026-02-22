use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::io;
use std::thread;

use log::{info, warn, debug, error};

use crate::dns::message::{DnsMessageBuilder, parse_query_domain, qtype_to_string};
use crate::dns::types::{TEST_IP_PREFIX, TEST_IP_OCTETS};
use crate::zones::zone::Zone;
use crate::security::access_control::AccessControl;
use crate::logging::query_logger::QueryLogger;

#[derive(Clone)]
pub struct DNSBLServer {
    pub zones: Arc<HashMap<String, Zone>>,
    zones_by_lowercase: Arc<HashMap<String, String>>,
    access_control: Arc<AccessControl>,
    query_logger: Arc<QueryLogger>,
}

impl DNSBLServer {
    pub fn with_zones_and_access_control(zones: HashMap<String, Zone>, access_control: AccessControl, 
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

    pub fn find_zone(&self, domain: &str) -> Option<&Zone> {
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

    pub fn handle_query(&self, query: &[u8], src_addr: SocketAddr) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }

        let (allowed, action, reason) = self.access_control.check(src_addr.ip());
        
        if !allowed {
            warn!("Access denied for IP {}: {}", src_addr.ip(), reason.unwrap_or_default());
            
            let (domain, parse_success, qtype_bytes) = parse_query_domain(query);
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

        let id = [query[0], query[1]];
        
        let (domain, parse_success, qtype_bytes) = parse_query_domain(query);
        
        if !parse_success {
            return None;
        }
        
        let domain = match domain {
            Some(d) => d,
            None => return None,
        };
        
        let qtype_value = u16::from_be_bytes([qtype_bytes[0], qtype_bytes[1]]);
        debug!("Query received for domain: {} (type: {}) from {}", 
               domain, qtype_to_string(&qtype_bytes), src_addr);

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
            
            match result {
                Some(zone) => {
                    info!("[{}] Blocked IP: {} (domain: {} from {})", 
                          zone.domain, ip.unwrap(), domain, src_addr.ip());
                    
                    let response = DnsMessageBuilder::build_a_response(id, query, zone.response_ip);
                    
                    self.query_logger.log_query(
                        src_addr, &domain, qtype_value, 0, 
                        Some(zone.response_ip), None, source.as_deref(),
                        action
                    );
                    
                    Some(response)
                }
                None => {
                    debug!("IP not blocked (domain: {} from {})", domain, src_addr.ip());
                    
                    let response = DnsMessageBuilder::build_nxdomain_response(id, query);
                    
                    self.query_logger.log_query(
                        src_addr, &domain, qtype_value, 3, None, None, None,
                        action
                    );
                    
                    Some(response)
                }
            }
        } else if qtype_value == 16 {
            let (result, source, ip, txt_opt) = self.find_zone_and_check_txt(&domain);
            
            match result {
                Some(zone) => {
                    info!("[{}] TXT query for IP: {} (domain: {} from {})", 
                          zone.domain, ip.unwrap(), domain, src_addr.ip());
                    
                    if let Some(txt) = txt_opt {
                        let response = DnsMessageBuilder::build_txt_response(id, query, &txt);
                        
                        self.query_logger.log_query(
                            src_addr, &domain, qtype_value, 0, 
                            None, Some(&txt), source.as_deref(),
                            action
                        );
                        
                        Some(response)
                    } else {
                        let response = DnsMessageBuilder::build_nxdomain_response(id, query);
                        
                        self.query_logger.log_query(
                            src_addr, &domain, qtype_value, 3, None, None, source.as_deref(),
                            action
                        );
                        
                        Some(response)
                    }
                }
                None => {
                    debug!("TXT not found (domain: {} from {})", domain, src_addr.ip());
                    
                    let response = DnsMessageBuilder::build_nxdomain_response(id, query);
                    
                    self.query_logger.log_query(
                        src_addr, &domain, qtype_value, 3, None, None, None,
                        action
                    );
                    
                    Some(response)
                }
            }
        } else {
            let response = DnsMessageBuilder::build_notimpl_response(id, query);
            
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
    
    fn handle_self_domain_query(&self, id: [u8; 2], query: &[u8], domain: &str, 
                                qtype: &[u8]) -> (Option<Vec<u8>>, u8) {
        let zone = match self.find_zone(domain) {
            Some(z) => z,
            None => return (None, 4),
        };
        
        let qtype_value = u16::from_be_bytes([qtype[0], qtype[1]]);
        
        info!("Self-domain query for: {} (type: {})", 
              domain, qtype_to_string(qtype));
        
        match qtype_value {
            1 => {
                let response = DnsMessageBuilder::build_a_response(id, query, zone.self_ip);
                (Some(response), 0)
            }
            
            2 => {
                let response = DnsMessageBuilder::build_ns_response(id, query, domain, zone.self_ip);
                (Some(response), 0)
            }
            
            6 => {
                let response = DnsMessageBuilder::build_soa_response(id, query, domain);
                (Some(response), 0)
            }
            
            15 => {
                if zone.mx_records.is_empty() {
                    return (None, 4);
                }
                
                let mx = &zone.mx_records[0];
                let response = DnsMessageBuilder::build_mx_response(id, query, &mx.server, mx.priority);
                (Some(response), 0)
            }
            
            16 => {
                if zone.txt_records.is_empty() {
                    return (None, 4);
                }
                
                let txt = &zone.txt_records[0];
                let response = DnsMessageBuilder::build_txt_response(id, query, &txt.text);
                (Some(response), 0)
            }
            
            _ => {
                (None, 4)
            }
        }
    }
    
    fn find_zone_and_check_a(&self, domain: &str) -> (Option<&Zone>, Option<String>, Option<Ipv4Addr>) {
        let zone = match self.find_zone(domain) {
            Some(z) => z,
            None => return (None, None, None),
        };
        
        let domain_lower = domain.to_lowercase();
        let zone_domain_lower = zone.domain_lowercase.to_lowercase();
        
        if !domain_lower.ends_with(&format!(".{}", zone_domain_lower)) {
            return (None, None, None);
        }
        
        let ip_part = &domain_lower[..domain_lower.len() - zone_domain_lower.len() - 1];
        let parts: Vec<&str> = ip_part.split('.').collect();
        
        if parts.len() < 4 {
            return (None, None, None);
        }
        
        let last_four = &parts[parts.len() - 4..];
        
        let domain_octets: Result<Vec<u8>, _> = last_four
            .iter()
            .map(|s| s.parse::<u8>())
            .collect();
        
        let domain_octets = match domain_octets {
            Ok(o) if o.len() == 4 => o,
            _ => return (None, None, None),
        };
        
        if domain_octets == TEST_IP_OCTETS {
            debug!("[{}] Test query detected for domain {}, returning positive", zone.domain, domain);
            return (Some(zone), Some("test".to_string()), Some(zone.response_ip));
        }
        
        let ip = Ipv4Addr::new(
            domain_octets[3], domain_octets[2], domain_octets[1], domain_octets[0]
        );
        
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

    pub fn start(&self, interface: &str, verbose: bool, _no_daemon: bool, stats_interval: Option<u64>) -> io::Result<()> {
        let socket_addr = if interface.contains(':') {
            SocketAddr::from_str(interface).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53)
        };
        
        let socket = UdpSocket::bind(socket_addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        
        info!("DNSBL server v2.9.0 started on {}", socket_addr);
        info!("Self-domain A/NS/SOA/MX/TXT record support enabled (case-insensitive)");
        info!("TXT record IP substitution enabled (@, @dotted, @reversed)");
        info!("Real-time DNSBL forwarding support enabled with recursive NS discovery");
        info!("Test query support enabled (2.0.0.127.* -> {})", Ipv4Addr::from(TEST_IP_PREFIX));
        
        if self.query_logger.is_enabled() {
            info!("Query logging enabled");
        }
        
        if !self.access_control.deny_ips().is_empty() {
            info!("Deny list: {} IPs/ranges", self.access_control.deny_ips().len());
        }
        if !self.access_control.exempt_ips().is_empty() {
            info!("Exempt list: {} IPs/ranges", self.access_control.exempt_ips().len());
        }
        if self.access_control.max_requests_per_minute() > 0 {
            info!("Rate limiting: {} requests per minute", self.access_control.max_requests_per_minute());
        } else {
            info!("Rate limiting: disabled");
        }
        
        for zone in self.zones.values() {
            let dnsbl_count = zone.sources.iter()
                .filter(|s| matches!(s, crate::zones::source::SourceType::Dnsbl(_)))
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

pub fn start_reloader(zones: Arc<HashMap<String, Zone>>, interval_minutes: u64) {
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

