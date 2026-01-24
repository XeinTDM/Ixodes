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
  import type { Country } from "$lib/data/countries";
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

  const northAmericaCodes = [
    "AG","AI","AW","BB","BS","BZ","CA","CR","CU","DM","DO","GD","GL","GP","GT","HN","HT","JM","KN","KY","LC","MF","MQ","MS","MX","NI","PA","PR","SX","TC","TT","US","VC","VG","VI"
  ];
  const southAmericaCodes = [
    "AR","BO","BR","CL","CO","EC","FK","GF","GY","PE","PY","SR","UY","VE"
  ];
  const europeCodes = [
    "AL","AD","AT","BY","BE","BA","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU","IS","IE","IT","XK","LV","LI","LT","LU","MT","MD","MC","ME","NL","MK","NO","PL","PT","RO","RS","SK","SI","ES","SE","CH","TR","UA","GB","VA"
  ];
  const asiaPacificCodes = [
    "AF","AM","AZ","BH","BD","BT","BN","KH","CN","CY","GE","IN","ID","IQ","IL","JP","JO","KZ","KP","KR","KW","KG","LA","LB","MY","MV","MN","MM","NP","OM","PK","PS","PH","QA","SA","SG","LK","SY","TW","TJ","TH","TL","TM","AE","UZ","VN","YE","AU","NZ","FJ","PG","SB","VU","NC","WS","TO","KI","PW","NR","FM","MH","TV"
  ];
  const africaCodes = [
    "DZ","AO","BJ","BW","BF","BI","CM","CV","CF","TD","KM","CG","CD","CI","DJ","EG","GQ","ER","ET","GA","GM","GH","GN","GW","KE","LS","LR","LY","MG","MW","ML","MR","MU","MA","MZ","NA","NE","NG","RE","RW","SH","SN","SC","SL","SO","ZA","SS","SD","SZ","TG","TN","UG","ZM","ZW"
  ];

  type QuickRegion = {
    label: string;
    value: string;
    codes: string[];
  };

  const dedupeCountriesByValue = (list: Country[]) => {
    const seen = new Set<string>();
    const normalized: Country[] = [];

    for (const country of list) {
      const key = country.value.trim().toUpperCase();
      if (seen.has(key)) continue;
      seen.add(key);
      normalized.push(country);
    }

    return normalized;
  };

  const normalizedCountries = dedupeCountriesByValue(countries);

  const quickRegions: QuickRegion[] = [
    { label: "All Countries", value: "ALL", codes: normalizedCountries.map((country) => country.value) },
    { label: "North America", value: "NA", codes: northAmericaCodes },
    { label: "South America", value: "SA", codes: southAmericaCodes },
    { label: "Europe", value: "EUR", codes: europeCodes },
    { label: "Asia-Pacific", value: "AP", codes: asiaPacificCodes },
    { label: "Africa", value: "AFR", codes: africaCodes },
  ];

  let open = $state(false);
  let searchTerm = $state("");
  let matchedCountries = $state<Country[]>(normalizedCountries);
  let filteredQuickRegions = $state<QuickRegion[]>(quickRegions);
  let searchActive = $derived(() => searchTerm.trim().length > 0);

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

  const getLabel = (value: string) =>
    normalizedCountries.find((c) => c.value === value)?.label ?? value;

  $effect(() => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) {
      matchedCountries = normalizedCountries;
      filteredQuickRegions = quickRegions;
      return;
    }

    filteredQuickRegions = quickRegions.filter((region) => {
      const label = region.label.toLowerCase();
      const value = region.value.toLowerCase();
      return label.includes(term) || value.includes(term);
    });

    const lowerTerm = term;
    const allMatches = normalizedCountries.filter((country) => {
      const label = country.label.toLowerCase();
      const value = country.value.toLowerCase();
      return label.includes(lowerTerm) || value.includes(lowerTerm);
    });

    const seen = new Set<string>();
    const uniqueMatches: Country[] = [];
    for (const match of allMatches) {
      const key = match.value.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      uniqueMatches.push(match);
    }

    const exactMatches = uniqueMatches.filter((country) => {
      const label = country.label.toLowerCase();
      const value = country.value.toLowerCase();
      return label === lowerTerm || value === lowerTerm;
    });

    matchedCountries = exactMatches.length > 0 ? exactMatches : uniqueMatches.slice(0, 60);
  });

  $effect(() => {
    if (!open) {
      searchTerm = "";
      matchedCountries = normalizedCountries;
      filteredQuickRegions = quickRegions;
    }
  });
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
        <PopoverContent class="w-62 p-0">
          <Command>
            <CommandInput placeholder="Search country..." bind:value={searchTerm} />
            <CommandList>
              {#if matchedCountries.length === 0}
                <CommandEmpty>No countries match "{searchTerm}"</CommandEmpty>
              {/if}
              <CommandGroup class="max-h-64 overflow-y-auto">
                {#if filteredQuickRegions.length > 0 && !searchActive}
                  {#each filteredQuickRegions as region}
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
                  {#if matchedCountries.length > 0}
                    <Separator class="my-2" />
                  {/if}
                {/if}
                {#if matchedCountries.length > 0}
                  {#each matchedCountries as country (country.value)}
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
                {/if}
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
