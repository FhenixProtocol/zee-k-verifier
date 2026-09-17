//! Shared logging library for CoFHE Rust services
//!
//! Provides a unified logging interface with support for:
//! - JSON and text output formats via `LOG_FORMAT` env var
//! - Configurable log levels via `LOG_LEVEL` or `RUST_LOG` env vars
//! - Optional file logging via `LOG_FILE` env var
//! - Color control via `NO_COLOR` env var
//! - Serde-based configuration for TOML files

use anyhow::Result;
use serde::Deserialize;
use std::{env, fmt};
use strum::{Display, EnumString};
use tracing::{Level, Subscriber};
use tracing_subscriber::{
    fmt::{
        self as fmt_subscriber,
        format::{self, FormatEvent, FormatFields},
        FmtContext,
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Environment variable name for log format (json or text)
pub const LOG_FORMAT_ENV_VAR: &str = "LOG_FORMAT";
/// Environment variable name for log level
pub const LOG_LEVEL_ENV_VAR: &str = "LOG_LEVEL";
/// Environment variable name for log file path
pub const LOG_FILE_ENV_VAR: &str = "LOG_FILE";
/// Environment variable name to disable colors
pub const NO_COLOR_ENV_VAR: &str = "NO_COLOR";

/// Log level enum with serde support for TOML configuration
#[derive(Debug, Clone, Copy, Deserialize, Display, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

/// Log format enum with serde support for TOML configuration
#[derive(Debug, Clone, Copy, Deserialize, Display, EnumString, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Logger configuration with serde support for TOML files
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggerConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub show_thread_id: bool,
    pub show_thread_name: bool,
    pub show_file: bool,
    pub show_line_number: bool,
    pub show_target: bool,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::default(),
            format: LogFormat::default(),
            show_thread_id: true,
            show_thread_name: true,
            show_file: true,
            show_line_number: true,
            show_target: true,
        }
    }
}

/// Custom JSON formatter for Google Cloud Logging compatibility.
struct GcloudJsonFormat;

impl<S, N> FormatEvent<S, N> for GcloudJsonFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        // Map tracing level to Google Cloud severity
        let severity = match *event.metadata().level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARNING",
            Level::INFO => "INFO",
            Level::DEBUG | Level::TRACE => "DEBUG",
        };

        let mut message = String::new();
        ctx.format_fields(format::Writer::new(&mut message), event)?;

        let record = serde_json::json!({
            "timestamp": chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "severity": severity,
            "target": event.metadata().target(),
            "message": message,
        });

        let line = serde_json::to_string(&record).map_err(|_| fmt::Error)?;
        writeln!(writer, "{}", line)
    }
}

/// Initialize the logger with the given configuration
///
/// The log format and level can be controlled via:
/// 1. Environment variables (take precedence): `LOG_FORMAT`, `LOG_LEVEL`, `RUST_LOG`
/// 2. `config` fields in LoggerConfig
///
/// # Example
/// ```rust,ignore
/// use rust_logger::{init_logger, LoggerConfig, LogLevel};
///
/// let config = LoggerConfig {
///     level: LogLevel::Debug,
///     show_file: false,
///     ..Default::default()
/// };
///
/// init_logger("my-service", &config).expect("Failed to initialize logger");
/// ```
pub fn init_logger(service_name: &str, config: &LoggerConfig) -> Result<()> {
    init_logger_internal(service_name, config, None)
}

/// Initialize the logger with default configuration
///
/// This is equivalent to calling `init_logger(service_name, &LoggerConfig::default())`
pub fn init_default_logger(service_name: &str) -> Result<()> {
    init_logger(service_name, &LoggerConfig::default())
}

/// Initialize the logger with file output support
///
/// When `log_file` is provided, logs are written to both stdout and the specified file.
/// The file path can also be set via the `LOG_FILE` environment variable.
pub fn init_logger_with_file(
    service_name: &str,
    config: &LoggerConfig,
    log_file: Option<String>,
) -> Result<()> {
    init_logger_internal(service_name, config, log_file)
}

fn init_logger_internal(
    service_name: &str,
    config: &LoggerConfig,
    log_file: Option<String>,
) -> Result<()> {
    // Note: LogTracer is automatically initialized by try_init() because we enabled
    // the "tracing-log" feature on tracing-subscriber. This bridges `log` crate messages
    // (from libraries like sqlx, lapin) to our tracing subscriber.

    // Determine log level: LOG_LEVEL env var > RUST_LOG env var > config
    let log_level = env::var(LOG_LEVEL_ENV_VAR)
        .or_else(|_| env::var("RUST_LOG"))
        .unwrap_or_else(|_| config.level.to_string());

    // Build filter with service-specific level and quieter settings for noisy crates
    let filter = EnvFilter::new(format!(
        "{},{}={},tonic=info,lapin=info,tokio=info,hyper=info,h2=info,tower=info",
        log_level, service_name, log_level
    ));

    // Check LOG_FORMAT env var first, then fall back to config
    let format = env::var(LOG_FORMAT_ENV_VAR)
        .ok()
        .and_then(|v| v.to_lowercase().parse::<LogFormat>().ok())
        .unwrap_or(config.format);
    let use_json = format == LogFormat::Json;

    // Check NO_COLOR env var for disabling colors in text format
    let use_colors = env::var(NO_COLOR_ENV_VAR).is_err();

    // Determine log file path from env var or parameter
    let log_file_path = env::var(LOG_FILE_ENV_VAR).ok().or(log_file);

    // Initialize based on whether file logging is requested
    if let Some(file_path) = log_file_path {
        init_with_file(
            service_name,
            config,
            &filter,
            use_json,
            use_colors,
            &file_path,
        )?;
    } else {
        init_stdout_only(config, filter, use_json, use_colors)?;
    }

    tracing::info!("Logger initialized for {}", service_name);
    Ok(())
}

fn init_stdout_only(
    config: &LoggerConfig,
    filter: EnvFilter,
    use_json: bool,
    use_colors: bool,
) -> Result<()> {
    if use_json {
        // JSON format for log aggregators - Google Cloud Logging compatible
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt_subscriber::layer()
                    .with_file(false)
                    .with_line_number(false)
                    .with_target(true)
                    .event_format(GcloudJsonFormat),
            )
            .try_init()?;
    } else {
        // Text format (default) with caller info and colors
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt_subscriber::layer()
                    .with_ansi(use_colors)
                    .with_thread_ids(config.show_thread_id)
                    .with_thread_names(config.show_thread_name)
                    .with_file(config.show_file)
                    .with_line_number(config.show_line_number)
                    .with_target(config.show_target),
            )
            .try_init()?;
    }
    Ok(())
}

fn init_with_file(
    _service_name: &str,
    config: &LoggerConfig,
    filter: &EnvFilter,
    use_json: bool,
    use_colors: bool,
    file_path: &str,
) -> Result<()> {
    // Create file appender
    let file_appender = tracing_appender::rolling::never(".", file_path);
    let (non_blocking_file, guard) = tracing_appender::non_blocking(file_appender);

    // Leak the guard to keep the file appender alive for the application lifetime
    std::mem::forget(guard);

    // Clone filter for file layer (EnvFilter doesn't implement Clone, so we recreate it)
    let filter_str = filter.to_string();
    let stdout_filter = EnvFilter::new(&filter_str);
    let file_filter = EnvFilter::new(&filter_str);

    if use_json {
        // JSON format for log aggregators - Google Cloud Logging compatible
        let stdout_layer = fmt_subscriber::layer()
            .with_file(false)
            .with_line_number(false)
            .with_target(true)
            .event_format(GcloudJsonFormat);

        let file_layer = fmt_subscriber::layer()
            .with_file(false)
            .with_line_number(false)
            .with_target(true)
            .with_ansi(false)
            .with_writer(non_blocking_file)
            .event_format(GcloudJsonFormat);

        tracing_subscriber::registry()
            .with(stdout_filter)
            .with(stdout_layer)
            .with(file_filter)
            .with(file_layer)
            .init();
    } else {
        // Text format with caller info
        let stdout_layer = fmt_subscriber::layer()
            .with_ansi(use_colors)
            .with_thread_ids(config.show_thread_id)
            .with_thread_names(config.show_thread_name)
            .with_file(config.show_file)
            .with_line_number(config.show_line_number)
            .with_target(config.show_target);

        let file_layer = fmt_subscriber::layer()
            .with_ansi(false)
            .with_thread_ids(config.show_thread_id)
            .with_thread_names(config.show_thread_name)
            .with_file(config.show_file)
            .with_line_number(config.show_line_number)
            .with_target(config.show_target)
            .with_writer(non_blocking_file);

        tracing_subscriber::registry()
            .with(stdout_filter)
            .with(stdout_layer)
            .with(file_filter)
            .with(file_layer)
            .init();
    }

    Ok(())
}

/// Get log level from environment variable or return default
pub fn get_log_level(default: &str) -> String {
    env::var(LOG_LEVEL_ENV_VAR)
        .or_else(|_| env::var("RUST_LOG"))
        .unwrap_or_else(|_| default.to_string())
}

/// Get log file path from environment variable or return default
pub fn get_logfile(default: &str) -> String {
    env::var(LOG_FILE_ENV_VAR).unwrap_or_else(|_| default.to_string())
}
