<script lang="ts">
  import { X, Check, ChevronsUpDown, Globe } from "@lucide/svelte";
  import { Button } from "$lib/components/ui/button";
  import {
    Command,
    CommandEmpty,
    CommandGroup,
    CommandInput,
    CommandItem,
    CommandList,
  } from "$lib/components/ui/command";
  import {
    Popover,
    PopoverContent,
    PopoverTrigger,
  } from "$lib/components/ui/popover";
  import { Badge } from "$lib/components/ui/badge";
  import { cn } from "$lib/utils";
  import { countries } from "$lib/data/countries";
    import Separator from "$lib/components/ui/separator/separator.svelte";

  type Props = {
    blockedCountries?: string[];
    onToggleCountry?: (code: string) => void;
    onSetCountries?: (codes: string[]) => void;
  };

  let {
    blockedCountries = [],
    onToggleCountry = () => undefined,
    onSetCountries = () => undefined,
  }: Props = $props();

  let open = $state(false);

  const quickRegions = [
    { label: "North America", value: "NA", codes: ["US", "CA", "MX"] },
    { label: "Europe", value: "EUR", codes: ["GB", "FR", "DE", "IT", "ES"] },
    { label: "Asia-Pacific", value: "AP", codes: ["CN", "JP", "IN", "KR", "AU"] },
  ];

  const handleQuickRegion = (codes: string[]) => {
    if (isRegionSelected(codes)) {
      const filtered = blockedCountries.filter((code) => !codes.includes(code));
      onSetCountries(filtered);
    } else {
      const merged = Array.from(new Set([...blockedCountries, ...codes]));
      onSetCountries(merged);
    }
    open = true;
  };

  const isRegionSelected = (codes: string[]) =>
    codes.every((code) => blockedCountries.includes(code));

  const handleClearAll = () => {
    onSetCountries([]);
  };

  const getLabel = (value: string) => countries.find((c) => c.value === value)?.label ?? value;
</script>

<div class="space-y-3">
  <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
    <Globe class="h-4 w-4 text-primary" />
    Geo-Blocking
  </div>
  <div class="space-y-2">
    <p class="text-xs text-muted-foreground">
        Prevent execution if the target machine is located in selected countries.
    </p>
    
    <div class="flex items-center gap-2">
      <Popover bind:open>
        <PopoverTrigger>
          {#snippet child({ props })}
            <Button
              variant="outline"
              role="combobox"
              aria-expanded={open}
              class="w-full justify-between"
              {...props}
            >
              {#if blockedCountries.length === 0}
                Select countries to block...
              {:else}
                {blockedCountries.length} countries blocked
              {/if}
              <ChevronsUpDown class="ml-2 h-4 w-4 shrink-0 opacity-50" />
            </Button>
          {/snippet}
        </PopoverTrigger>
        <PopoverContent class="w-75 p-0">
          <Command>
            <CommandInput placeholder="Search country..." />
            <CommandList>
              <CommandEmpty>No country found.</CommandEmpty>
              <CommandGroup class="max-h-64 overflow-y-auto">
                {#each quickRegions as region}
                  <CommandItem
                    value={region.label}
                    onSelect={() => handleQuickRegion(region.codes)}
                  >
                    <Check
                      class={cn(
                        "h-4 w-4",
                        isRegionSelected(region.codes) ? "opacity-100" : "opacity-0"
                      )}
                    />
                    {region.label}
                    <span class="ml-auto text-xs text-muted-foreground">{region.value}</span>
                  </CommandItem>
                {/each}
                <Separator class="my-2" />
                {#each countries as country}
                  <CommandItem
                    value={country.label}
                    onSelect={() => {
                      onToggleCountry(country.value);
                      open = true;
                    }}
                  >
                    <Check
                      class={cn(
                        "h-4 w-4",
                        blockedCountries.includes(country.value)
                          ? "opacity-100"
                          : "opacity-0"
                      )}
                    />
                    {country.label}
                    <span class="ml-auto text-xs text-muted-foreground">{country.value}</span>
                  </CommandItem>
                {/each}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
      <Button
        variant="ghost"
        size="icon"
        aria-label="Clear blocked countries"
        onclick={handleClearAll}
      >
        <X class="h-4 w-4" />
      </Button>
    </div>

    {#if blockedCountries.length > 0}
        <div class="flex flex-wrap gap-2 pt-2">
            {#each blockedCountries as code}
                <Badge variant="secondary" class="gap-1">
                    {getLabel(code)}
                    <button 
                        class="cursor-pointer"
                        onclick={() => onToggleCountry(code)}
                    >
                        <X class="h-3 w-3" />
                    </button>
                </Badge>
            {/each}
        </div>
    {/if}
  </div>
</div>
