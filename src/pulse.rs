use chrono::prelude::{DateTime};
use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::field::SiemField;
use usiem::events::SiemLog;
use std::collections::BTreeMap;

pub fn parse_general_log(mut log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_line = log.message();
    let _log_line = match log_line.find(" Query ") {
        None => return Err(LogParsingError::NoValidParser(log)),
        Some(pos) => {
            if pos >= 39 {
                &log_line[pos-37..]
            }else{
                log_line
            }
        }
    };
    log.set_service(Cow::Borrowed("PulseSecure"));
    log.set_product(Cow::Borrowed("PulseSecure"));
    log.set_category(Cow::Borrowed("VPN"));
    return Ok(log)
    
}


pub fn extract_fields<'a>(message: &'a str) -> BTreeMap<&'a str, &'a str> {
    let mut field_map = BTreeMap::new();
    let mut equal_pos = 0;
    let mut prev_equal = 0;
    let mut last_whitespace = 0;
    let mut last_char = ' ';
    let mut is_string = false;
    let mut start_key_pos = 0;
    let mut prev_start_key = 0;
    for (i, c) in message.char_indices() {
        if !is_string {
            if c == '=' {
                prev_start_key = start_key_pos;
                start_key_pos = if last_whitespace == 0 {
                    0
                }else {
                    last_whitespace + 1
                };
                if equal_pos != prev_equal && (equal_pos + 1) != last_whitespace{
                    if &message[equal_pos + 1..equal_pos+2] == "\"" {
                        field_map.insert(&message[prev_start_key..equal_pos], &message[equal_pos+2..last_whitespace-1]);
                    }else{
                        field_map.insert(&message[prev_start_key..equal_pos], &message[equal_pos+1..last_whitespace]);
                    }
                }
                prev_equal = equal_pos;
                equal_pos = i;
            }else if c == ' ' {
                last_whitespace = i;
            }else if c == '"' {
                is_string = true;
            }
        }else{
            if last_char != '\\' && c == '"' {
                is_string = false;
            }
        }
        last_char = c;
    }
    if (equal_pos+2) < message.len() && &message[equal_pos + 1..equal_pos+2] == "\"" {
        field_map.insert(&message[last_whitespace + 1..equal_pos], &message[equal_pos + 2.. message.len() - 1]);
    }else{
        field_map.insert(&message[last_whitespace + 1..equal_pos], &message[equal_pos + 1..]);
    }
    field_map
}

#[cfg(test)]
mod filterlog_tests {
    use super::{parse_general_log, extract_fields};
    use usiem::events::{SiemLog, SiemEvent};
    use usiem::events::field::{SiemIp, SiemField};
    use usiem::events::auth::{AuthLoginType,LoginOutcome};

    #[test]
    fn test_extract_fields() {
        let log = "id=firewall time=\"2021-04-08 11:57:48\" pri=6 fw=10.0.0.9 vpn=ive ivs=Default Network user=usettest1 realm=\"\" roles=\"\" proto=auth src=82.213.178.130 dst= dstname= type=vpn op= arg=\"\" result= sent= rcvd= agent=\"\" duration= msg=\"AUT22673: Logout from 82.213.178.130 (session:00000000)\"";
        let map = extract_fields(log);
        assert_eq!(map.get("id"), Some(&"firewall"));
        assert_eq!(map.get("time"), Some(&"2021-04-08 11:57:48"));
        assert_eq!(map.get("fw"), Some(&"10.0.0.9"));
        assert_eq!(map.get("user"), Some(&"usettest1"));
        assert_eq!(map.get("ivs"), Some(&"Default Network"));
        assert_eq!(map.get("msg"), Some(&"AUT22673: Logout from 82.213.178.130 (session:00000000)"));
    }
}
