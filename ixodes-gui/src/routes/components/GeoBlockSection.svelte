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

  type Country = {
    value: string;
    label: string;
  };

  type Props = {
    blockedCountries?: string[];
    onToggleCountry?: (code: string) => void;
  };

  let {
    blockedCountries = [],
    onToggleCountry = () => undefined,
  }: Props = $props();

  let open = $state(false);

  // TODO: Add full ISO list.
  const countries: Country[] = [
    { value: "US", label: "United States" },
    { value: "RU", label: "Russia" },
    { value: "CN", label: "China" },
    { value: "UA", label: "Ukraine" },
    { value: "DE", label: "Germany" },
    { value: "FR", label: "France" },
    { value: "GB", label: "United Kingdom" },
    { value: "CA", label: "Canada" },
    { value: "BR", label: "Brazil" },
    { value: "IN", label: "India" },
    { value: "JP", label: "Japan" },
    { value: "KR", label: "South Korea" },
    { value: "AU", label: "Australia" },
    { value: "NL", label: "Netherlands" },
    { value: "SG", label: "Singapore" },
    { value: "BY", label: "Belarus" },
    { value: "KZ", label: "Kazakhstan" },
    { value: "AM", label: "Armenia" },
    { value: "MD", label: "Moldova" },
  ];

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
              {#each countries as country}
                <CommandItem
                  value={country.label}
                  onSelect={() => {
                    onToggleCountry(country.value);
                  }}
                >
                  <Check
                    class={cn(
                      "mr-2 h-4 w-4",
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

    {#if blockedCountries.length > 0}
        <div class="flex flex-wrap gap-2 pt-2">
            {#each blockedCountries as code}
                <Badge variant="secondary" class="gap-1">
                    {getLabel(code)}
                    <button 
                        class="ml-1 ring-offset-background rounded-full outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                        onclick={() => onToggleCountry(code)}
                    >
                        <span class="sr-only">Remove</span>
                        <X class="h-3 w-3" />
                    </button>
                </Badge>
            {/each}
        </div>
    {/if}
  </div>
</div>
