<script lang="ts">
  import { Weight } from "@lucide/svelte";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
  } from "$lib/components/ui/select";

  type Props = {
    pumpSize?: number;
    pumpUnit?: "kb" | "mb" | "gb";
    onPumpSizeChange?: (value: number) => void;
    onPumpUnitChange?: (value: "kb" | "mb" | "gb") => void;
  };

  let {
    pumpSize = 0,
    pumpUnit = "mb",
    onPumpSizeChange = () => undefined,
    onPumpUnitChange = () => undefined,
  }: Props = $props();

  const handleSizeChange = (e: Event) => {
    const value = (e.target as HTMLInputElement).value;
    const num = parseInt(value, 10);
    if (!isNaN(num) && num >= 0) {
      onPumpSizeChange(num);
    } else {
        onPumpSizeChange(0);
    }
  };
</script>

<div class="space-y-3">
  <div class="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-muted-foreground">
    <Weight class="h-4 w-4 text-primary" />
    File Pumper
  </div>
  <div class="space-y-2">
    <p class="text-xs text-muted-foreground">
      Artificially inflate the executable size by appending random data. 
      (0 to disable)
    </p>
    <div class="flex gap-2">
      <div class="flex-1">
        <Input 
            type="number" 
            placeholder="Size to add" 
            min="0"
            value={pumpSize}
            oninput={handleSizeChange}
        />
      </div>
      <div class="w-24">
        <Select 
            type="single" 
            value={pumpUnit} 
            onValueChange={(val) => onPumpUnitChange(val as "kb" | "mb" | "gb")}
        >
          <SelectTrigger>
            <span>Unit</span>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="kb">KB</SelectItem>
            <SelectItem value="mb">MB</SelectItem>
            <SelectItem value="gb">GB</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
  </div>
</div>
