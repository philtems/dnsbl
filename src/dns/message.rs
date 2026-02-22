use std::net::Ipv4Addr;

use crate::dns::types::{A_RECORD_TTL, NS_RECORD_TTL, TXT_RECORD_TTL, MX_RECORD_TTL};

pub struct DnsMessageBuilder;

impl DnsMessageBuilder {
    pub fn build_a_response(id: [u8; 2], query: &[u8], response_ip: Ipv4Addr) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&id);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        if let Some(question) = Self::copy_question_section(query) {
            response.extend_from_slice(&question);
        }
        
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&A_RECORD_TTL.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x04]);
        response.extend_from_slice(&response_ip.octets());
        
        response
    }
    
    pub fn build_nxdomain_response(id: [u8; 2], query: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&id);
        response.extend_from_slice(&[0x81, 0x83]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        if let Some(question) = Self::copy_question_section(query) {
            response.extend_from_slice(&question);
        }
        
        response
    }
    
    pub fn build_notimpl_response(id: [u8; 2], query: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&id);
        response.extend_from_slice(&[0x81, 0x04]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        if let Some(question) = Self::copy_question_section(query) {
            response.extend_from_slice(&question);
        }
        
        response
    }
    
    pub fn build_txt_response(id: [u8; 2], query: &[u8], txt: &str) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&id);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        if let Some(question) = Self::copy_question_section(query) {
            response.extend_from_slice(&question);
        }
        
        let txt_data = txt.as_bytes();
        let txt_len = 1 + txt_data.len();
        
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);
        response.extend_from_slice(&TXT_RECORD_TTL.to_be_bytes());
        response.extend_from_slice(&(txt_len as u16).to_be_bytes());
        
        response.push(txt_data.len() as u8);
        response.extend_from_slice(txt_data);
        
        response
    }
    
    pub fn build_ns_response(id: [u8; 2], query: &[u8], domain: &str, self_ip: Ipv4Addr) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&id);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        if let Some(question) = Self::copy_question_section(query) {
            response.extend_from_slice(&question);
        }
        
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&[0x00, 0x02, 0x00, 0x01]);
        response.extend_from_slice(&NS_RECORD_TTL.to_be_bytes());
        
        let ns_name = Self::domain_to_labels(domain);
        let ns_name_len = ns_name.len() as u16;
        response.extend_from_slice(&ns_name_len.to_be_bytes());
        response.extend_from_slice(&ns_name);
        
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&A_RECORD_TTL.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x04]);
        response.extend_from_slice(&self_ip.octets());
        
        response
    }
    
    pub fn build_soa_response(id: [u8; 2], query: &[u8], domain: &str) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&id);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        if let Some(question) = Self::copy_question_section(query) {
            response.extend_from_slice(&question);
        }
        
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&[0x00, 0x06, 0x00, 0x01]);
        response.extend_from_slice(&NS_RECORD_TTL.to_be_bytes());
        
        let mname = Self::domain_to_labels(domain);
        let rname = Self::domain_to_labels(&format!("hostmaster.{}", domain));
        
        let soa_len = mname.len() + rname.len() + 20;
        response.extend_from_slice(&(soa_len as u16).to_be_bytes());
        
        response.extend_from_slice(&mname);
        response.extend_from_slice(&rname);
        
        response.extend_from_slice(&1u32.to_be_bytes());
        response.extend_from_slice(&7200u32.to_be_bytes());
        response.extend_from_slice(&3600u32.to_be_bytes());
        response.extend_from_slice(&86400u32.to_be_bytes());
        response.extend_from_slice(&300u32.to_be_bytes());
        
        response
    }
    
    pub fn build_mx_response(id: [u8; 2], query: &[u8], mx_server: &str, priority: u16) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&id);
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        if let Some(question) = Self::copy_question_section(query) {
            response.extend_from_slice(&question);
        }
        
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&[0x00, 0x0F, 0x00, 0x01]);
        response.extend_from_slice(&MX_RECORD_TTL.to_be_bytes());
        
        let mx_name = Self::domain_to_labels(mx_server);
        let mx_len = 2 + mx_name.len();
        response.extend_from_slice(&(mx_len as u16).to_be_bytes());
        
        response.extend_from_slice(&priority.to_be_bytes());
        response.extend_from_slice(&mx_name);
        
        response
    }
    
    fn copy_question_section(query: &[u8]) -> Option<Vec<u8>> {
        let mut pos = 12;
        let mut question = Vec::new();
        
        while pos < query.len() && query[pos] != 0 {
            let len = query[pos] as usize;
            if pos + len + 1 >= query.len() {
                return None;
            }
            question.extend_from_slice(&query[pos..=pos + len]);
            pos += len + 1;
        }
        if pos >= query.len() || query[pos] != 0 {
            return None;
        }
        question.push(0);
        
        if pos + 4 <= query.len() {
            question.extend_from_slice(&query[pos + 1..pos + 5]);
            Some(question)
        } else {
            None
        }
    }
    
    fn domain_to_labels(domain: &str) -> Vec<u8> {
        let mut result = Vec::new();
        for part in domain.split('.') {
            result.push(part.len() as u8);
            result.extend_from_slice(part.as_bytes());
        }
        result.push(0);
        result
    }
}

pub fn parse_query_domain(query: &[u8]) -> (Option<String>, bool, [u8; 2]) {
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

pub fn qtype_to_string(qtype: &[u8]) -> String {
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

