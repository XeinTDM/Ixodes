<script lang="ts">
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { Bitcoin, Coins, Wallet } from "@lucide/svelte";

  type Props = {
    btcAddress?: string;
    ethAddress?: string;
    ltcAddress?: string;
    xmrAddress?: string;
    dogeAddress?: string;
    dashAddress?: string;
    solAddress?: string;
    trxAddress?: string;
    adaAddress?: string;
    onBtcChange?: (val: string) => void;
    onEthChange?: (val: string) => void;
    onLtcChange?: (val: string) => void;
    onXmrChange?: (val: string) => void;
    onDogeChange?: (val: string) => void;
    onDashChange?: (val: string) => void;
    onSolChange?: (val: string) => void;
    onTrxChange?: (val: string) => void;
    onAdaChange?: (val: string) => void;
  };

  let {
    btcAddress = "",
    ethAddress = "",
    ltcAddress = "",
    xmrAddress = "",
    dogeAddress = "",
    dashAddress = "",
    solAddress = "",
    trxAddress = "",
    adaAddress = "",
    onBtcChange = () => undefined,
    onEthChange = () => undefined,
    onLtcChange = () => undefined,
    onXmrChange = () => undefined,
    onDogeChange = () => undefined,
    onDashChange = () => undefined,
    onSolChange = () => undefined,
    onTrxChange = () => undefined,
    onAdaChange = () => undefined,
  }: Props = $props();
</script>

<div class="space-y-4">
  <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
    <Wallet class="h-4 w-4 text-primary" />
    Attacker Wallet Addresses
  </div>
  <div class="grid gap-4 md:grid-cols-2">
    <div class="space-y-2">
      <Label class="text-xs text-muted-foreground flex items-center gap-1" for="btc-addr">
        <Bitcoin class="h-3 w-3" /> BTC Address
      </Label>
      <Input
        id="btc-addr"
        placeholder="1... or bc1..."
        value={btcAddress}
        oninput={(e) => onBtcChange(e.currentTarget.value)}
      />
    </div>
    <div class="space-y-2">
      <Label class="text-xs text-muted-foreground flex items-center gap-1" for="eth-addr">
        <Coins class="h-3 w-3" /> ETH / ERC20 Address
      </Label>
      <Input
        id="eth-addr"
        placeholder="0x..."
        value={ethAddress}
        oninput={(e) => onEthChange(e.currentTarget.value)}
      />
    </div>
    <div class="space-y-2">
      <Label class="text-xs text-muted-foreground flex items-center gap-1" for="ltc-addr">
        <Coins class="h-3 w-3" /> LTC Address
      </Label>
      <Input
        id="ltc-addr"
        placeholder="L... or M... or bc1..."
        value={ltcAddress}
        oninput={(e) => onLtcChange(e.currentTarget.value)}
      />
    </div>
    <div class="space-y-2">
      <Label class="text-xs text-muted-foreground flex items-center gap-1" for="xmr-addr">
        <Coins class="h-3 w-3" /> XMR (Monero) Address
      </Label>
      <Input
        id="xmr-addr"
        placeholder="4..."
        value={xmrAddress}
        oninput={(e) => onXmrChange(e.currentTarget.value)}
      />
    </div>
    <div class="space-y-2">
      <Label class="text-xs text-muted-foreground flex items-center gap-1" for="doge-addr">
        <Coins class="h-3 w-3" /> DOGE Address
      </Label>
      <Input
        id="doge-addr"
        placeholder="D..."
        value={dogeAddress}
        oninput={(e) => onDogeChange(e.currentTarget.value)}
      />
    </div>
    <div class="space-y-2">
      <Label class="text-xs text-muted-foreground flex items-center gap-1" for="dash-addr">
        <Coins class="h-3 w-3" /> DASH Address
      </Label>
      <Input
        id="dash-addr"
        placeholder="X..."
        value={dashAddress}
        oninput={(e) => onDashChange(e.currentTarget.value)}
      />
    </div>
    <div class="space-y-2">
      <Label class="text-xs text-muted-foreground flex items-center gap-1" for="sol-addr">
        <Coins class="h-3 w-3" /> SOL Address
      </Label>
      <Input
        id="sol-addr"
        placeholder="Address..."
        value={solAddress}
        oninput={(e) => onSolChange(e.currentTarget.value)}
      />
    </div>
    <div class="space-y-2">
      <Label class="text-xs text-muted-foreground flex items-center gap-1" for="trx-addr">
        <Coins class="h-3 w-3" /> TRX (Tron) Address
      </Label>
      <Input
        id="trx-addr"
        placeholder="T..."
        value={trxAddress}
        oninput={(e) => onTrxChange(e.currentTarget.value)}
      />
    </div>
    <div class="space-y-2">
      <Label class="text-xs text-muted-foreground flex items-center gap-1" for="ada-addr">
        <Coins class="h-3 w-3" /> ADA (Cardano) Address
      </Label>
      <Input
        id="ada-addr"
        placeholder="addr1..."
        value={adaAddress}
        oninput={(e) => onAdaChange(e.currentTarget.value)}
      />
    </div>
  </div>
</div>
