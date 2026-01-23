<script lang="ts">
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { Network } from "@lucide/svelte";

  let {
    proxyServer = "",
    onProxyServerChange = (val: string) => {},
  } = $props();
</script>

<div class="space-y-3">
  <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
    <Network class="h-4 w-4 text-primary" />
    Network Configuration
  </div>
  <div class="space-y-2">
    <Label class="text-xs text-muted-foreground" for="proxy-server">
      Proxy Server (Optional)
    </Label>
    <Input
      id="proxy-server"
      placeholder="http://user:pass@host:port"
      value={proxyServer}
      oninput={(e) => onProxyServerChange(e.currentTarget.value)}
    />
    <p class="text-[10px] text-muted-foreground">
      Route all traffic through this proxy (HTTP/S/SOCKS5 supported).
    </p>
  </div>
</div>
