#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config error: {0}")]
    Config(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("caldav {method} {href} -> {status}: {body}")]
    CalDav {
        status: u16,
        method: String,
        href: String,
        body: String,
    },

    #[error("xml parse error: {0}")]
    Xml(String),

    #[error("ical error: {0}")]
    ICal(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;
