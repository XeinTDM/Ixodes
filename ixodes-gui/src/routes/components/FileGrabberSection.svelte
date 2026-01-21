<script lang="ts">
  import { FileSearch, Plus, X } from "@lucide/svelte";
  import { Button } from "$lib/components/ui/button";
  import { Input } from "$lib/components/ui/input";
  import { Badge } from "$lib/components/ui/badge";

  type Props = {
    customExtensions?: string[];
    customKeywords?: string[];
    onAddExtension?: (ext: string) => void;
    onRemoveExtension?: (ext: string) => void;
    onAddKeyword?: (kw: string) => void;
    onRemoveKeyword?: (kw: string) => void;
  };

  let {
    customExtensions = [],
    customKeywords = [],
    onAddExtension = () => undefined,
    onRemoveExtension = () => undefined,
    onAddKeyword = () => undefined,
    onRemoveKeyword = () => undefined,
  }: Props = $props();

  let extInput = $state("");
  let kwInput = $state("");

  const handleAddExtension = () => {
    const trimmed = extInput.trim();
    if (!trimmed) return;
    onAddExtension(trimmed);
    extInput = "";
  };

  const handleAddKeyword = () => {
    const trimmed = kwInput.trim();
    if (!trimmed) return;
    onAddKeyword(trimmed);
    kwInput = "";
  };
</script>

<div class="space-y-4">
  <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
    <FileSearch class="h-4 w-4 text-primary" />
    Custom File Grabber
  </div>
  
  <div class="grid gap-6 md:grid-cols-2">
    <!-- Extensions -->
    <div class="space-y-2">
      <div class="text-xs font-medium text-muted-foreground uppercase tracking-wider">Target Extensions</div>
      <div class="flex gap-2">
        <Input 
          placeholder="e.g. .kdbx, .wallet" 
          bind:value={extInput} 
          onkeydown={(e) => e.key === "Enter" && handleAddExtension()}
        />
        <Button variant="outline" size="icon" onclick={handleAddExtension}>
          <Plus class="h-4 w-4" />
        </Button>
      </div>
      <div class="flex flex-wrap gap-2 min-h-[2rem]">
        {#if customExtensions.length === 0}
            <span class="text-xs text-muted-foreground/50 italic">Default extensions only</span>
        {:else}
            {#each customExtensions as ext}
            <Badge variant="secondary" class="gap-1 pl-2.5 pr-1">
                {ext}
                <button 
                class="ml-1 ring-offset-background rounded-full outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 hover:bg-muted-foreground/20 p-0.5"
                onclick={() => onRemoveExtension(ext)}
                >
                <X class="h-3 w-3" />
                <span class="sr-only">Remove</span>
                </button>
            </Badge>
            {/each}
        {/if}
      </div>
    </div>

    <!-- Keywords -->
    <div class="space-y-2">
      <div class="text-xs font-medium text-muted-foreground uppercase tracking-wider">Target Keywords</div>
      <div class="flex gap-2">
        <Input 
          placeholder="e.g. secret, report" 
          bind:value={kwInput}
          onkeydown={(e) => e.key === "Enter" && handleAddKeyword()}
        />
        <Button variant="outline" size="icon" onclick={handleAddKeyword}>
          <Plus class="h-4 w-4" />
        </Button>
      </div>
      <div class="flex flex-wrap gap-2 min-h-[2rem]">
        {#if customKeywords.length === 0}
            <span class="text-xs text-muted-foreground/50 italic">Default keywords only</span>
        {:else}
            {#each customKeywords as kw}
            <Badge variant="secondary" class="gap-1 pl-2.5 pr-1">
                {kw}
                <button 
                class="ml-1 ring-offset-background rounded-full outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 hover:bg-muted-foreground/20 p-0.5"
                onclick={() => onRemoveKeyword(kw)}
                >
                <X class="h-3 w-3" />
                <span class="sr-only">Remove</span>
                </button>
            </Badge>
            {/each}
        {/if}
      </div>
    </div>
  </div>
</div>
