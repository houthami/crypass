//! Decides which accounts belong to the window being filled.
//!
//! Sites are compared by exact origin (scheme, host and port). That's strict on
//! purpose: `http://bank.com` and `bank.com.evil.net` must never match
//! `https://bank.com`. A different subdomain asks once, then is remembered.

const BROWSERS: [&str; 7] = [
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "arc.exe",
];

/// Returns `scheme://host[:port]` in lower case for http and https addresses.
pub fn origin_from_url(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }

    let authority = rest.split(['/', '?', '#']).next()?;
    // In `https://bank.com@evil.net` the real host is the part after the last @.
    let host = authority.rsplit('@').next()?.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    let host = host.strip_suffix(default_port).unwrap_or(&host);
    Some(format!("{scheme}://{host}"))
}

pub fn is_browser(process: &str) -> bool {
    BROWSERS.contains(&process.to_ascii_lowercase().as_str())
}

/// The identity accounts are saved against, or `None` if it can't be confirmed.
/// A browser is only ever identified by its page address, never by its name.
pub fn context_key(process: Option<&str>, url: Option<&str>) -> Option<String> {
    let process = process?;
    if is_browser(process) {
        return origin_from_url(url?);
    }
    Some(format!("app:{}", process.to_ascii_lowercase()))
}

/// The text to show for a saved key: `bank.com`, or `notepad.exe` for an app.
/// Plain http keeps its scheme so an insecure site stays visible.
pub fn display_key(key: &str) -> &str {
    key.strip_prefix("app:")
        .or_else(|| key.strip_prefix("https://"))
        .unwrap_or(key)
}

#[derive(Debug, PartialEq)]
pub enum Warning {
    /// The account is saved for somewhere else.
    DifferentSite { saved: String },
    /// The account is saved for specific sites, but this one can't be confirmed.
    UnconfirmedSite { saved: String },
}

#[derive(Debug, PartialEq)]
pub struct Decision {
    pub warning: Option<Warning>,
    /// A key to save against the account once the fill succeeds.
    pub learn: Option<String>,
}

/// First use of an account trusts the current site. After that, anywhere else
/// needs a deliberate confirmation, and an unconfirmed site is never learned.
pub fn check(saved: &[String], key: Option<&str>) -> Decision {
    let first_saved = || saved.first().map(|s| display_key(s).to_string());
    match key {
        Some(key) if saved.iter().any(|s| s == key) => Decision {
            warning: None,
            learn: None,
        },
        Some(key) => Decision {
            warning: first_saved().map(|saved| Warning::DifferentSite { saved }),
            learn: Some(key.to_string()),
        },
        None => Decision {
            warning: first_saved().map(|saved| Warning::UnconfirmedSite { saved }),
            learn: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(url: &str) -> Option<String> {
        origin_from_url(url)
    }

    #[test]
    fn an_address_reduces_to_its_origin() {
        let bank = Some("https://bank.com".to_string());
        assert_eq!(origin("https://bank.com/login?next=/home#top"), bank);
        assert_eq!(origin("HTTPS://BANK.COM"), bank);
        assert_eq!(origin("https://bank.com:443/"), bank);
        assert_eq!(origin("https://bank.com?x=1"), bank);
        assert_eq!(
            origin("http://127.0.0.1:8080/a").as_deref(),
            Some("http://127.0.0.1:8080")
        );
    }

    #[test]
    fn lookalike_addresses_are_not_the_real_site() {
        let bank = origin("https://bank.com");
        assert_eq!(origin("https://bank.com@evil.net/").as_deref(), Some("https://evil.net"));
        assert_ne!(origin("https://bank.com.evil.net/"), bank);
        assert_ne!(origin("https://evil.net/https://bank.com"), bank);
        assert_ne!(origin("https://evil.net#bank.com"), bank);
        assert_ne!(origin("https://evil.net?bank.com"), bank);
        assert_ne!(origin("http://bank.com"), bank);
        assert_ne!(origin("https://bank.com:8443"), bank);
    }

    #[test]
    fn pages_without_a_web_address_have_no_origin() {
        for url in ["", "bank.com", "file:///C:/login.html", "about:blank", "javascript:alert(1)", "https://"] {
            assert_eq!(origin(url), None, "{url}");
        }
    }

    #[test]
    fn a_browser_is_identified_by_its_page_and_never_by_its_name() {
        assert_eq!(
            context_key(Some("Chrome.exe"), Some("https://bank.com/x")).as_deref(),
            Some("https://bank.com")
        );
        assert_eq!(context_key(Some("chrome.exe"), None), None);
        assert_eq!(context_key(Some("msedge.exe"), Some("file:///a.html")), None);
    }

    #[test]
    fn a_desktop_app_is_identified_by_its_program_name() {
        assert_eq!(
            context_key(Some("Slack.EXE"), Some("https://ignored.example")).as_deref(),
            Some("app:slack.exe")
        );
        assert_eq!(context_key(None, Some("https://bank.com")), None);
    }

    #[test]
    fn the_first_fill_is_trusted_and_learned() {
        let decision = check(&[], Some("https://bank.com"));
        assert_eq!(decision.warning, None);
        assert_eq!(decision.learn.as_deref(), Some("https://bank.com"));
    }

    #[test]
    fn a_saved_site_fills_without_asking() {
        let saved = ["https://bank.com".to_string()];
        assert_eq!(
            check(&saved, Some("https://bank.com")),
            Decision { warning: None, learn: None }
        );
    }

    #[test]
    fn a_different_site_warns_and_is_only_learned_after_filling() {
        let saved = ["https://bank.com".to_string()];
        let decision = check(&saved, Some("https://evil.net"));
        assert_eq!(
            decision.warning,
            Some(Warning::DifferentSite { saved: "bank.com".into() })
        );
        assert_eq!(decision.learn.as_deref(), Some("https://evil.net"));
    }

    #[test]
    fn an_unconfirmed_site_warns_and_is_never_learned() {
        let saved = ["https://bank.com".to_string()];
        let decision = check(&saved, None);
        assert_eq!(
            decision.warning,
            Some(Warning::UnconfirmedSite { saved: "bank.com".into() })
        );
        assert_eq!(decision.learn, None);
        assert_eq!(check(&[], None), Decision { warning: None, learn: None });
    }

    #[test]
    fn keys_display_without_noise_but_plain_http_stays_visible() {
        assert_eq!(display_key("https://bank.com"), "bank.com");
        assert_eq!(display_key("http://bank.com"), "http://bank.com");
        assert_eq!(display_key("app:slack.exe"), "slack.exe");
    }
}
