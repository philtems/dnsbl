use std::collections::HashMap;
use std::sync::Arc;

use daemonize::Daemonize;
use log::{info, error};

use dnsbl_server::config::{self};
use dnsbl_server::zones::source::SourceType;
use dnsbl_server::dns::server::{DNSBLServer, start_reloader};
use dnsbl_server::logging::{QueryLogger, DblSaver};
use dnsbl_server::zones::zone::Zone;

fn main() {
    let (zone_configs, interface, verbose, daemon_mode, log_file, reload_minutes, 
         access_control, query_log, dbl_save) = match config::parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    
    if let Err(e) = config::setup_logging(log_file.as_deref(), verbose) {
        eprintln!("Logging initialization error: {}", e);
        std::process::exit(1);
    }

    info!("DNSBL Server v2.9.0 - 2026, Philippe TEMESI");
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
    
    let stats_interval = if access_control.max_requests_per_minute() > 0 {
        Some(access_control.max_requests_per_minute() as u64)
    } else {
        None
    };
    
    let server = DNSBLServer::with_zones_and_access_control(zones_map, access_control, query_logger);
    
    if reload_minutes > 0 {
        start_reloader(server.zones.clone(), reload_minutes);
    }
    
    if let Err(e) = server.start(&interface, verbose, !daemon_mode, stats_interval) {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}
