use tracing::Level;

pub fn get_log_level(level: &str) -> Level {
    if level.to_ascii_lowercase() == "trace" {
        return Level::TRACE;
    }
    if level.to_ascii_lowercase() == "debug" {
        return Level::DEBUG;
    }
    if level.to_ascii_lowercase() == "info" {
        return Level::INFO;
    }
    if level.to_ascii_lowercase() == "warn" {
        return Level::WARN;
    }
    if level.to_ascii_lowercase() == "error" {
        return Level::ERROR;
    }

    Level::INFO
}
