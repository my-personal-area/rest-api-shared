use service_sdk::my_http_server::{HttpContext, HttpFailResult};

const MIN_PASSWORD_LEN: usize = 8;

pub fn validate_email(_ctx: &HttpContext, value: &str) -> Result<(), HttpFailResult> {
    if validate_email_text(value) {
        return Ok(());
    }

    Err(HttpFailResult::as_validation_error(
        "Invalid Email format".to_string(),
    ))
}

pub fn validate_password(_ctx: &HttpContext, value: &str) -> Result<(), HttpFailResult> {
    match validate_password_text(value, MIN_PASSWORD_LEN) {
        Ok(_) => Ok(()),
        Err(err_text) => Err(HttpFailResult::as_validation_error(err_text)),
    }
}

fn validate_email_text(src: &str) -> bool {
    let mut indexes = Vec::new();

    let mut non_symbols = 0;

    let mut index: usize = 0;

    for i in src.as_bytes() {
        if *i == b'@' {
            indexes.push(index);
        }

        if *i <= 32 {
            non_symbols += 1;
        }

        index += 1;
    }

    if non_symbols > 0 {
        return false;
    }

    if indexes.len() != 1 {
        return false;
    }

    let at_index = *indexes.get(0).unwrap();

    if at_index == 0 || at_index == src.len() - 1 {
        return false;
    }

    true
}

const SPECIAL_SYMBOLS: [char; 13] = [
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '=',
];

fn validate_password_text(value: &str, min_len: usize) -> Result<(), String> {
    if value.len() < min_len {
        return Err(format!("Password must be at least {} symbols", min_len));
    }

    let mut amount_of_special_symbols = 0;

    let mut amount_of_spaces = 0;

    for v in value.as_bytes() {
        if *v <= 32 {
            amount_of_spaces += 1;
        }
        let found_it = SPECIAL_SYMBOLS.iter().find(|c| **c as u8 == *v);

        if found_it.is_some() {
            amount_of_special_symbols += 1;
        }
    }

    if amount_of_spaces > 0 {
        return Err(format!("Password must contain no space characters"));
    }

    if amount_of_special_symbols == 0 {
        return Err(format!(
            "Password must contain at least 1 special symbol such as {:?}",
            SPECIAL_SYMBOLS
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_email_is_correct() {
        assert!(validate_email_text("test@test.tt"));

        assert_eq!(false, validate_email_text("@test.tt"));

        assert_eq!(false, validate_email_text("test.tt@"));

        assert_eq!(false, validate_email_text(" test.tt@sss.tr"));
    }
}
