//! Sample authentication module used by the evaluation seed.

pub fn issue(user: &str) -> String {
    format!("token-for-{user}")
}

pub fn refresh(token: &str) -> String {
    format!("refreshed-{token}")
}

pub fn revoke(_token: &str) {
    // revocation is a no-op in the fixture
}

#[cfg(test)]
mod tests {
    #[test]
    fn issue_and_refresh_roundtrip() {
        let t = super::issue("u");
        assert!(super::refresh(&t).starts_with("refreshed-"));
    }
}
