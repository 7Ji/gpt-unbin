# gpt-unbin

This does one thing only: to hack `gpt.bin` you could dump from new Amlogic USB Bunring images so you could change the partition layout before bunring.

In short Amlogic has deprecated their proprietary partition table format on new SoCs and decided to use gpt instead, but instead of simply `sfdisk` they choose to use yet another complicated way...

A common use case would be:
1. Use [ampack] to unpack the image
2. Use this tool to modify the partition infos
3. Use [ampack] again to repack the image

[ampack]: https://github.com/7Ji/ampack

## Build

```
cargo build --release
```

The result binary would be `target/release/gpt-unbin`

## Usage

**To dump partition infos from gpt.bin to parts.csv:**

```
gpt-unbin dump [gpt.bin] [parts.csv]
```
e.g.
```
gpt-unbin dump out/gpt.bin parts.csv
```

The dumped info csv would look like following:
```
name,size_mb,flagx
vendor_boot_a,64,1000000000000
vendor_boot_b,64,1000000000000
bootloader_a,8,1000000000000
bootloader_b,8,1000000000000
tee,32,1000000000000
logo,8,1000000000000
misc,2,1000000000000
dtbo_a,2,1000000000000
dtbo_b,2,1000000000000
cri_data,8,2000000000000
param,16,2000000000000
odm_ext_a,16,1000000000000
odm_ext_b,16,1000000000000
oem_a,32,1000000000000
oem_b,32,1000000000000
boot_a,64,1000000000000
boot_b,64,1000000000000
init_boot_a,8,1000000000000
init_boot_b,8,1000000000000
metadata,64,1001000000000000
vbmeta_a,2,1000000000000
vbmeta_b,2,1000000000000
vbmeta_system_a,2,1000000000000
vbmeta_system_b,2,1000000000000
super,3200,1000000000000
rsv,64,1000000000000
userdata,-,1004000000000000
```

You can add partitions as you like

**To apply partition infos from parts.csv to gpt.bin:**

```
gpt-unbin apply [gpt.bin] [parts.csv]
```
e.g.
```
gpt-unbin apply out/gpt.bin parts.csv
```
While it seems `out/gpt.bin` is needed to exist to be modified, it does not have to be, the result `gpt.bin` is re-created from 0; in other word, the existing `gpt.bin` would be purged before created.

## License
**gpt-unbin**, to modify Amlogic's gpt.bin

Copyright (C) 2025-present Guoxin "7Ji" Pu

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
