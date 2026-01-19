use crate::recovery::context::RecoveryContext;
use async_trait::async_trait;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryCategory {
    Browsers,
    Messengers,
    Gaming,
    EmailClients,
    VPNs,
    Wallets,
    System,
    Other,
}

impl fmt::Display for RecoveryCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Browsers => write!(f, "Browsers"),
            Self::Messengers => write!(f, "Messengers"),
            Self::Gaming => write!(f, "Gaming"),
            Self::EmailClients => write!(f, "Email Clients"),
            Self::VPNs => write!(f, "VPNs"),
            Self::Wallets => write!(f, "Wallets"),
            Self::System => write!(f, "System"),
            Self::Other => write!(f, "Other"),
        }
    }
}

impl FromStr for RecoveryCategory {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "browsers" => Ok(Self::Browsers),
            "messengers" => Ok(Self::Messengers),
            "gaming" => Ok(Self::Gaming),
            "email" | "email clients" | "emailclients" => Ok(Self::EmailClients),
            "vpn" | "vpns" => Ok(Self::VPNs),
            "wallet" | "wallets" => Ok(Self::Wallets),
            "system" => Ok(Self::System),
            "other" => Ok(Self::Other),
            _ => Err("unknown recovery category"),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RecoveryArtifact {
    pub label: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified: Option<SystemTime>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum RecoveryStatus {
    Success,
    Partial,
    NotFound,
    Failed,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RecoveryOutcome {
    pub task: String,
    pub category: RecoveryCategory,
    pub duration: Duration,
    pub status: RecoveryStatus,
    pub artifacts: Vec<RecoveryArtifact>,
    pub error: Option<String>,
}

#[async_trait]
pub trait RecoveryTask: Send + Sync + 'static {
    fn label(&self) -> String;
    fn category(&self) -> RecoveryCategory;

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError>;
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("io failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("custom recovery failure: {0}")]
    Custom(String),
}

impl From<tokio::task::JoinError> for RecoveryError {
    fn from(err: tokio::task::JoinError) -> Self {
        RecoveryError::Custom(format!("task join failed: {err}"))
    }
}
