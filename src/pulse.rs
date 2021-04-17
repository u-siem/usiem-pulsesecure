use chrono::prelude::{NaiveDateTime};
use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::{SiemLog, SiemEvent};
use usiem::events::auth::{AuthEvent,AuthLoginType, LoginOutcome, RemoteLogin};
use std::collections::BTreeMap;

pub fn parse_general_log(mut log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_line = log.message().to_string();
    let log_line = match log_line.find(" id=") {
        None => return Err(LogParsingError::NoValidParser(log)),
        Some(pos) => &log_line[pos + 1..]
    };
    let fields = extract_fields(log_line);
    
    let timestamp = match fields.get("time") {
        Some(timestamp) => {
            match NaiveDateTime::parse_from_str(*timestamp, "%Y-%m-%d %H:%M:%S") {
                Ok(timestamp) => timestamp.timestamp_millis(),
                Err(_err) => return Err(LogParsingError::NoValidParser(log)),
            }
        },
        None => return Err(LogParsingError::NoValidParser(log))
    };
    let observer_ip = match fields.get("fw") {
        Some(fw) => {
            match SiemIp::from_ip_str(fw) {
                Ok(ip) => ip,
                Err(_) => return Err(LogParsingError::ParserError(log)),
            }
        },
        None => return Err(LogParsingError::NoValidParser(log))
    };
    let log = parse_msg_field(&fields, log);
    match log {
        Ok(mut log) => {
            log.add_field("observer.ip", SiemField::IP(observer_ip));
            log.set_event_created(timestamp);
            log.set_service(Cow::Borrowed("PulseSecure"));
            log.set_product(Cow::Borrowed("PulseSecure"));
            log.set_category(Cow::Borrowed("VPN"));
            return Ok(log)
        },
        Err(e) => return Err(e)
    };
    
    
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


pub fn parse_msg_field(fields : &BTreeMap<&str, &str>, mut log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let msg = match fields.get("msg") {
        Some(fw) => *fw,
        None => return Ok(log)
    };
    let (id, content) = match msg.find(": ") {
        Some(pos) => (&msg[..pos], &msg[pos + 2..]),
        None => return Err(LogParsingError::ParserError(log))
    };
    let typ = &id[0..3];
    let id = match (&id[3..]).parse::<u32>() {
        Ok(id) => id,
        Err(_) => return Err(LogParsingError::ParserError(log))
    };
    let user = match fields.get("user") {
        Some(user) => user,
        None => ""
    };
    let user_domain = match fields.get("realm") {
        Some(dm) => dm,
        None => "_NONE_"
    };
    let hostname = match fields.get("fw") {
        Some(user) => user,
        None => "_NONE_"
    };
    let source = match fields.get("src") {
        Some(src) => *src,
        None => "_NONE_"
    };
    match fields.get("agent") {
        Some(agnt) => {
            if agnt.len() > 0{
                log.add_field("user_agent.original", SiemField::Text(Cow::Owned(agnt.to_string())));
            }
        },
        None => {}
    };
    
    // Add Event ID from msg field and dataset
    log.add_field("event.code", SiemField::U32(id));
    log.add_field("event.dataset", SiemField::from_str(typ.to_string()));
    match typ {
        "AUT" => {
            match id {
                31504 => {
                    //Login succeded
                    log.set_event(SiemEvent::Auth(AuthEvent {
                        hostname : Cow::Owned(hostname.to_string()),
                        outcome : LoginOutcome::SUCESS,
                        login_type : AuthLoginType::Remote(RemoteLogin {
                            user_name : Cow::Owned(user.to_string()),
                            domain : Cow::Owned(user_domain.to_string()),
                            source_address : Cow::Owned(source.to_string()),
                        })
                    }));
                },
                24412 => {
                    // SOAP login succeeded for
                    log.set_event(SiemEvent::Auth(AuthEvent {
                        hostname : Cow::Owned(hostname.to_string()),
                        outcome : LoginOutcome::SUCESS,
                        login_type : AuthLoginType::Remote(RemoteLogin {
                            user_name : Cow::Owned(user.to_string()),
                            domain : Cow::Owned(user_domain.to_string()),
                            source_address : Cow::Owned(source.to_string()),
                        })
                    }));
                },
                24414 => {
                    // SOAP login succeeded for
                    log.set_event(SiemEvent::Auth(AuthEvent {
                        hostname : Cow::Owned(hostname.to_string()),
                        outcome : LoginOutcome::SUCESS,
                        login_type : AuthLoginType::Remote(RemoteLogin {
                            user_name : Cow::Owned(user.to_string()),
                            domain : Cow::Owned(user_domain.to_string()),
                            source_address : Cow::Owned(source.to_string()),
                        })
                    }));
                },
                24326  => {
                    //Primary authentication successful
                    log.set_event(SiemEvent::Auth(AuthEvent {
                        hostname : Cow::Owned(hostname.to_string()),
                        outcome : LoginOutcome::ESTABLISH,
                        login_type : AuthLoginType::Remote(RemoteLogin {
                            user_name : Cow::Owned(user.to_string()),
                            domain : Cow::Owned(user_domain.to_string()),
                            source_address : Cow::Owned(source.to_string()),
                        })
                    }));
                },
                30684 => {
                    //Primary authentication successful for admin
                    log.set_event(SiemEvent::Auth(AuthEvent {
                        hostname : Cow::Owned(hostname.to_string()),
                        outcome : LoginOutcome::ESTABLISH,
                        login_type : AuthLoginType::Remote(RemoteLogin {
                            user_name : Cow::Owned(user.to_string()),
                            domain : Cow::Owned(user_domain.to_string()),
                            source_address : Cow::Owned(source.to_string()),
                        })
                    }));
                },
                24327 => {
                    //Primary authentication failed
                    log.set_event(SiemEvent::Auth(AuthEvent {
                        hostname : Cow::Owned(hostname.to_string()),
                        outcome : LoginOutcome::FAIL,
                        login_type : AuthLoginType::Remote(RemoteLogin {
                            user_name : Cow::Owned(user.to_string()),
                            domain : Cow::Owned(user_domain.to_string()),
                            source_address : Cow::Owned(source.to_string()),
                        })
                    }));
                },
                30685 => {
                    //Primary authentication failed for admin
                    log.set_event(SiemEvent::Auth(AuthEvent {
                        hostname : Cow::Owned(hostname.to_string()),
                        outcome : LoginOutcome::FAIL,
                        login_type : AuthLoginType::Remote(RemoteLogin {
                            user_name : Cow::Owned(user.to_string()),
                            domain : Cow::Owned(user_domain.to_string()),
                            source_address : Cow::Owned(source.to_string()),
                        })
                    }));
                },
                22673 => {
                    //Logout
                    
                },
                31085 => {
                    //Concurrent connection limit
                },
                _ => {}
            }
            return Ok(log)
        },
        "USR" => {
            return Ok(log)
        },
        "ADM" => {
            match id {
                22668 => {
                    //Login succeded
                    log.set_event(SiemEvent::Auth(AuthEvent {
                        hostname : Cow::Owned(hostname.to_string()),
                        outcome : LoginOutcome::SUCESS,
                        login_type : AuthLoginType::Remote(RemoteLogin {
                            user_name : Cow::Owned(user.to_string()),
                            domain : Cow::Owned(user_domain.to_string()),
                            source_address : Cow::Owned(source.to_string()),
                        })
                    }));
                },
                20716 => {
                    // User accounts modified
                },
                23452 => {
                    //Super admin session created using token
                },
                24511 => {
                    //Admin token is created
                },
                22671 => {
                    //Logout
                },
                _ => {}
            }
            return Ok(log)
        },
        "PTR" => {
            // Policy Trace
            return Ok(log)
        },
        "NWC" => {
            // Network Connect
            return Ok(log)
        },
        "ERR" => {
            // System Error
            return Ok(log)
        },
        "WEB" => {
            // WebRequest
            return Ok(log)
        },
        "ARC" => {
            // Archive
            return Ok(log)
        },
        _ => return Ok(log)
    }
}

fn extract_from_msg<'a>(msg : &'a str) -> Option<&'a str> {
    let pos = match msg.find(" from ") {
        Some(p) => p,
        None => return None
    };
    match &msg[pos + 6..].find(" ") {
        Some(p) => return Some(&msg[pos + 6..*p]),
        None => return Some(&msg[pos + 6..])
    };
}

#[cfg(test)]
mod filterlog_tests {
    use super::{parse_general_log, extract_fields};
    use usiem::events::{SiemLog, SiemEvent};
    use usiem::events::field::{SiemIp, SiemField};
    use usiem::events::auth::{AuthLoginType,LoginOutcome};
    use std::borrow::Cow;

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
    #[test]
    fn test_parser() {
        let log = "2021-04-08T12:14:18-07:00 10.0.0.111 PulseSecure: id=firewall time=\"2021-04-08 12:14:18\" pri=6 fw=10.0.0.9 vpn=ive ivs=Default Network user=usertest2 realm=\"Users\" roles=\"Users\" proto=auth src=82.213.178.130 dst= dstname= type=vpn op= arg=\"\" result= sent= rcvd= agent=\"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0\" duration= msg=\"AUT31504: Login succeeded for usertest2/Users (session:00000000) from 82.213.178.130 with Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0.\"";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let res = parse_general_log(log);
        match res {
            Ok(log) => {
                assert_eq!(log.field("user.name"), Some(&SiemField::User(String::from("usertest2"))));
                assert_eq!(log.field("source.ip"), Some(&SiemField::IP(SiemIp::from_ip_str("82.213.178.130").unwrap())));
                assert_eq!(log.field("user.domain"), Some(&SiemField::Domain(String::from("Users"))));
                assert_eq!(log.field("event.code"), Some(&SiemField::U32(31504)));
                assert_eq!(log.field("observer.ip"), Some(&SiemField::IP(SiemIp::from_ip_str("10.0.0.9").unwrap())));
                assert_eq!(log.field("user_agent.original"), Some(&SiemField::from_str("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0")));
            },
            Err(_) => panic!("Must be parsed")
        }
    }
}
