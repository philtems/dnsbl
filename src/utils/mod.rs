use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

/// Convertit une chaîne en IpNetwork (IP seule ou CIDR)
pub fn parse_ip_or_cidr(s: &str) -> Result<IpNetwork, String> {
    if let Ok(network) = IpNetwork::from_str(s) {
        Ok(network)
    } else if let Ok(ip) = IpAddr::from_str(s) {
        let network = match ip {
            IpAddr::V4(ipv4) => IpNetwork::V4(Ipv4Network::new(ipv4, 32).unwrap()),
            IpAddr::V6(ipv6) => IpNetwork::V6(Ipv6Network::new(ipv6, 128).unwrap()),
        };
        Ok(network)
    } else {
        Err(format!("Invalid IP or CIDR: {}", s))
    }
}

/// Vérifie si un chemin est un fichier
pub fn is_file(path: &str) -> bool {
    std::path::Path::new(path).is_file()
}

/// Crée les répertoires parents si nécessaire
pub fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

