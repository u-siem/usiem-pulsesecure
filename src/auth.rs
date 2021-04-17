pub fn parse_auth_log(mut log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_line = log.message();
    let log_line = match log_line.find(" Query ") {
        None => {
            match log_line.find(" Connect ") {
                None => {
                    match log_line.find(" Quit") {
                        None => {
                            return Err(LogParsingError::NoValidParser(log))
                        },
                        Some(pos) => {
                            if pos >= 39 {
                                &log_line[pos-37..]
                            }else{
                                log_line
                            }
                        }
                    }
                },
                Some(pos) => {
                    if pos >= 39 {
                        &log_line[pos-37..]
                    }else{
                        log_line
                    }
                }
            }
        },
        Some(pos) => {
            if pos >= 39 {
                &log_line[pos-37..]
            }else{
                log_line
            }
        }
    };

    // Checks
    let fisr_char = match log_line.chars().next() {
        Some(chr) => chr,
        None => return Err(LogParsingError::NoValidParser(log))
    };
    if fisr_char > '9' || fisr_char < '0' {
        return Err(LogParsingError::NoValidParser(log));
    }
    if log_line.len() < 42 {
        return Err(LogParsingError::NoValidParser(log));
    }
    if &log_line[37..38] != " " || &log_line[27..28] != " " {
        return Err(LogParsingError::NoValidParser(log));
    }
    // Extraction
    let fields = extract_general_fields(log_line);
    if fields.len() != 4 {
        return Err(LogParsingError::NoValidParser(log))
    }
    let event_created = match DateTime::parse_from_rfc3339(fields[0]) {
        Ok(timestamp) => timestamp.timestamp_millis(),
        Err(_err) => return Err(LogParsingError::NoValidParser(log)),
    };
    let event_dataset = fields[2].to_string();
    let session_id = fields[1].to_string();
    let content = fields[3].to_string();
    match &event_dataset[..] {
        "Quit" => {},
        "Query" => {
            log.add_field("database.query", SiemField::Text(Cow::Owned(content)));
        },
        "Connect" => {
            log = match parse_connection(log, &content[..]) {
                Err(log) => log,
                Ok(log) => log,
            };
        },
        _ => {}
    }
    log.set_event_created(event_created);
    match session_id.parse::<u32>() {
        Ok(session_id) => {
            log.add_field("session.id", SiemField::U32(session_id));
        },
        Err(_) => {
            log.add_field("session.name", SiemField::Text(Cow::Owned(session_id)));
        }
    };
    
    log.add_field("event.dataset", SiemField::Text(Cow::Owned(event_dataset)));
    log.set_service(Cow::Borrowed("MySQL"));
    log.set_product(Cow::Borrowed("MySQL"));
    log.set_category(Cow::Borrowed("Database"));
    return Ok(log)
    
}