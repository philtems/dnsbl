use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;

#[derive(Debug, Clone)]
pub struct AccessControl {
    max_requests_per_minute: usize,
    exempt_ips: Vec<IpNetwork>,
    deny_ips: Vec<IpNetwork>,
    requests: Arc<RwLock<HashMap<IpAddr, (usize, Instant)>>>,
}

impl AccessControl {
    pub fn new(max_requests_per_minute: usize, exempt_ips: Vec<IpNetwork>, deny_ips: Vec<IpNetwork>) -> Self {
        AccessControl {
            max_requests_per_minute,
            exempt_ips,
            deny_ips,
            requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn max_requests_per_minute(&self) -> usize {
        self.max_requests_per_minute
    }

    pub fn exempt_ips(&self) -> &[IpNetwork] {
        &self.exempt_ips
    }

    pub fn deny_ips(&self) -> &[IpNetwork] {
        &self.deny_ips
    }

    pub fn check(&self, ip: IpAddr) -> (bool, Option<&'static str>, Option<String>) {
        for denied in &self.deny_ips {
            if denied.contains(ip) {
                return (false, Some("DENIED"), Some(format!("in deny list: {}", denied)));
            }
        }

        for exempt in &self.exempt_ips {
            if exempt.contains(ip) {
                return (true, Some("EXEMPT"), Some(format!("exempt from rate limit: {}", exempt)));
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

    pub fn get_stats(&self) -> HashMap<IpAddr, usize> {
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

