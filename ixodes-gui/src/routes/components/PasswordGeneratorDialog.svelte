<script lang="ts">
  import { Settings2 } from "@lucide/svelte";
  import { Button } from "$lib/components/ui/button";
  import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
  } from "$lib/components/ui/dialog";
  import { Label } from "$lib/components/ui/label";
  import { Switch } from "$lib/components/ui/switch";
  import { Slider } from "$lib/components/ui/slider";

  type Props = {
    length: number;
    useUppercase: boolean;
    useNumbers: boolean;
    useSymbols: boolean;
    onLengthChange: (val: number) => void;
    onToggleUppercase: () => void;
    onToggleNumbers: () => void;
    onToggleSymbols: () => void;
  };

  let {
    length = 16,
    useUppercase = true,
    useNumbers = true,
    useSymbols = true,
    onLengthChange = () => {},
    onToggleUppercase = () => {},
    onToggleNumbers = () => {},
    onToggleSymbols = () => {},
  }: Props = $props();
</script>

<Dialog>
  <DialogTrigger>
    {#snippet child({ props })}
      <Button variant="outline" size="icon" {...props}>
        <Settings2 class="h-4 w-4" />
      </Button>
    {/snippet}
  </DialogTrigger>
  <DialogContent class="sm:max-w-[425px]">
    <DialogHeader>
      <DialogTitle>Generator Settings</DialogTitle>
    </DialogHeader>
    <div class="grid gap-4 py-4">
      <div class="flex flex-col gap-4">
        <div class="flex items-center justify-between">
          <Label>Length: {length}</Label>
        </div>
        <Slider
          type="single"
          value={length}
          min={8}
          max={64}
          step={1}
          onValueChange={(val: number) => onLengthChange(val)}
        />
      </div>

      <div class="flex items-center justify-between space-x-2">
        <Label for="uppercase">Uppercase (A-Z)</Label>
        <Switch
          id="uppercase"
          checked={useUppercase}
          onCheckedChange={onToggleUppercase}
        />
      </div>

      <div class="flex items-center justify-between space-x-2">
        <Label for="numbers">Numbers (0-9)</Label>
        <Switch
          id="numbers"
          checked={useNumbers}
          onCheckedChange={onToggleNumbers}
        />
      </div>

      <div class="flex items-center justify-between space-x-2">
        <Label for="symbols">Symbols (!@#$)</Label>
        <Switch
          id="symbols"
          checked={useSymbols}
          onCheckedChange={onToggleSymbols}
        />
      </div>
    </div>
  </DialogContent>
</Dialog>
