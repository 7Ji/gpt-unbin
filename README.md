This does one thing only: to hack `gpt.bin` you could dump from new Amlogic USB Bunring images so you could change the partition layout before bunring.

In short Amlogic has deprecated their proprietary partition table format on new SoCs and decided to use gpt instead, but instead of simply `sfdisk` they choose to use yet another complicated way...

A common use case would be:
1. Use [ampack] to unpack the image
2. Use this tool to modify the partition infos
3. Use [ampack] again to repack the image

[ampack]: https://github.com/7Ji/ampack


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
