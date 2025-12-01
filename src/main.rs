/*
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
*/

const LEN_CRC32_TABLE: usize = 0x100;

#[derive(Clone, Copy)]
struct CRC32Table {
    table: [u32; LEN_CRC32_TABLE]
}

impl CRC32Table {
    fn new() -> Self {
        let mut table = [0u32; LEN_CRC32_TABLE];
        for id in 0..(LEN_CRC32_TABLE as u32) {
            let mut byte = id;
            for _ in 0..8 {
                let int = byte >> 1;
                if byte & 1 == 0 {
                    byte = int;
                } else {
                    byte = int ^ 0xedb88320;
                }
            }
            table[id as usize] = byte
        }
        Self { table }
    }
}

struct CRC32Hasher<'a> {
    value: u32,
    table: &'a CRC32Table,
}

impl<'a> CRC32Hasher<'a> {
    fn new(table: &'a CRC32Table) -> Self {
        Self {
            value: 0xFFFFFFFF,
            table,
        }
    }

    fn update(&mut self, data: &[u8]) {
        for byte in data.iter() {
            self.value = self.table.table[
                ((self.value ^ *byte as u32) & 0xff) as usize
            ] ^ self.value >> 8;
        }
    }

    fn finalize(&self) -> u32 {
        self.value ^ 0xFFFFFFFF
    }
}

impl CRC32Table {
    fn calculate(&self, bytes: &[u8]) -> u32 {
        let mut hasher = CRC32Hasher::new(self);
        hasher.update(bytes);
        hasher.finalize()
    }
}



#[repr(u8)]
#[derive(Default, Debug, PartialEq)]
enum MBREntryStatus {
    #[default]
    Inactive = 0x00,
    _Active =  0x80
}

#[repr(C, packed)]
#[derive(Debug, PartialEq)]
struct MBREntryAddress {
    head: u8,
    high: u8,
    low: u8
}

impl Default for MBREntryAddress {
    fn default() -> Self {
        Self { head: 0xFF, high: 0xFF, low: 0xFF }
    }
}

#[repr(u8)]
#[derive(Default, Debug, PartialEq)]
enum MBREntryType {
    _Empty = 0x00,
    #[default]
    GPTProtectiveMBR = 0xEE,
}

#[repr(C, packed)]
struct MBREntry {
    status: MBREntryStatus,
    first_chs: MBREntryAddress,
    type_part: MBREntryType,
    last_chs: MBREntryAddress,
    first_lba: u32,
    n_sectors: u32
}

const MBR_FIRST_LBA: u32 = 1;

impl Default for MBREntry {
    fn default() -> Self {
        Self {
            status: Default::default(),
            first_chs: Default::default(),
            type_part: Default::default(),
            last_chs: Default::default(),
            first_lba: MBR_FIRST_LBA,
            n_sectors: Default::default()
        }
    }
}

impl MBREntry {
    fn verify(&self) {
        let addr_default = MBREntryAddress::default();
        assert_eq!(self.status, MBREntryStatus::default());
        assert_eq!(self.first_chs, addr_default);
        assert_eq!(self.type_part, MBREntryType::default());
        assert_eq!(self.last_chs, addr_default);
        let first_lba = self.first_lba;
        assert_eq!(first_lba, MBR_FIRST_LBA);
        let n_sectors = self.n_sectors;
        assert_eq!(n_sectors, 0);
    }
}

const LEN_MBR_BOOTSTRAP: usize = 446;
const LEN_MBR_ENTRY: usize = 16;
const LEN_MBR_ENTRIES_UNUSED: usize = LEN_MBR_ENTRY * 3;
const LEN_MBR_SIGNATURE: usize = 2;

#[repr(C, packed)]
struct ProtectiveMBR {
    bootstrap: [u8; LEN_MBR_BOOTSTRAP],
    part1: MBREntry,
    part234: [u8; LEN_MBR_ENTRIES_UNUSED],
    sigature: [u8; LEN_MBR_SIGNATURE],
}

const MBR_SIGNATURE: [u8; LEN_MBR_SIGNATURE] = [0x55, 0xAA];

impl Default for ProtectiveMBR {
    fn default() -> Self {
        Self {
            bootstrap: [0u8; LEN_MBR_BOOTSTRAP],
            part1: Default::default(),
            part234: [0u8; LEN_MBR_ENTRIES_UNUSED],
            sigature: MBR_SIGNATURE,
        }
    }
}

impl ProtectiveMBR {
    fn verify(&self) {
        assert_eq!(self.bootstrap, [0u8; 446]);
        assert_eq!(self.part234, [0u8; 48]);
        assert_eq!(self.sigature, MBR_SIGNATURE);
        self.part1.verify()
    }
}

const LEN_GPT_ENTRY_NAME_U16: usize = 36;
const LEN_GPT_ENTRY_NAME_U8: usize = LEN_GPT_ENTRY_NAME_U16 * 2;

#[repr(C, packed)]
#[derive(PartialEq, Debug, Clone, Copy)]
struct GPTEntryName([u8; LEN_GPT_ENTRY_NAME_U8]);

impl Default for GPTEntryName {
    fn default() -> Self {
        Self([0u8; LEN_GPT_ENTRY_NAME_U8])
    }
}

impl GPTEntryName {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        let inner = &self.0;
        for i in (0 .. LEN_GPT_ENTRY_NAME_U8).step_by(2) {
            assert_eq!(inner[i + 1], 0, "unsupported character with second byte");
            let this = inner[i];
            if this == 0 {
                break
            }
            match this {
                b'a'..b'z' => (),
                b'0'..b'9' => (),
                b'_' => (),
                _ => panic!("unsupported character in part name")
            }
            buffer.push(this)
        }
        buffer
    }

    fn to_string(&self) -> String {
        let bytes = self.to_bytes();
        String::from_utf8(bytes).expect("Failed to convert to utf-8 string")
    }

    fn from_bytes(b: &[u8]) -> Self {
        let len = b.len();
        assert!(len <= LEN_GPT_ENTRY_NAME_U16);
        let mut name = Self::default();
        for i in 0 .. len {
            let off = i * 2;
            name.0[off] = b[i];
            name.0[off + 1] = 0;
        }
        name
    }

    fn _from_str(s: &str) -> Self {
        Self::from_bytes(s.as_bytes())
    }
}

#[repr(C, packed)]
#[derive(Default, PartialEq, Debug, Clone)]
struct GPTEntry {
    uuid_type: uuid::Uuid,
    uuid_part: uuid::Uuid,
    first_lba: u64,
    last_lba: u64,
    flags: u64,
    name: GPTEntryName,
}

const GPT_GUID_BASIC: uuid::Uuid  = uuid::Uuid::from_bytes([0xA2, 0xA0, 0xD0, 0xEB,  0xE5, 0xB9, 0x33, 0x44,  0x87, 0xC0, 0x68, 0xB6,  0xB7, 0x26, 0x99, 0xC7]);

const GPT_FIRST_LBA_0: u64 = 0x12000;
const GPT_FIRST_LBA_1: u64 = 0x36000;
const GPT_FIRST_LBA_2: u64 = 0x42000;
const GPT_FIRST_LBA_3: u64 = 0x47000;

const GPT_LAST_LBA_0: u64 = 0x31FFF;
const GPT_LAST_LBA_1: u64 = 0x39FFF;
const GPT_LAST_LBA_2: u64 = 0x42FFF;
const GPT_LAST_LBA_3: u64 = 0x4AFFF;

const GPT_FLAGS_0: u64 = 0x0;
const GPT_FLAGS_1: u64 = 0x0;
const GPT_FLAGS_2: u64 = 0x1000000000000;
const GPT_FLAGS_3: u64 = 0x11000000000000;

const GPT_NAME_0: &[u8] = b"reserved";
const GPT_NAME_1: &[u8] = b"env";
const GPT_NAME_2: &[u8] = b"frp";
const GPT_NAME_3: &[u8] = b"factory";

impl GPTEntry {
    fn verify(&self, first_lba: u64, last_lba: u64, flags: u64, name: &[u8]) {
        let this_first_lba = self.first_lba;
        let this_last_lba = self.last_lba;
        let this_flags = self.flags;
        let this_name = self.name.to_bytes();
        println!("Verifying {}", String::from_utf8_lossy(&this_name));
        assert_eq!(this_first_lba, first_lba);
        assert_eq!(this_last_lba, last_lba);
        assert_eq!(this_flags, flags);
        assert_eq!(this_name, name);
    }

    fn new(uuid_part: Option<uuid::Uuid>, first_lba: u64, last_lba: u64, flags: u64, name: &[u8]) -> Self {
        Self {
            uuid_type: GPT_GUID_BASIC.clone(),
            uuid_part: uuid_part.unwrap_or_else(uuid::Uuid::new_v4),
            first_lba: first_lba,
            last_lba: last_lba,
            flags: flags,
            name: GPTEntryName::from_bytes(name),
        }
    }
}

const LEN_GPT_ENTRY: u32 = size_of::<GPTEntry>() as u32;

const LEN_GPT_SIGNATURE: usize = 8;
const GPT_SIGNATURE: [u8; LEN_GPT_SIGNATURE] = [0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54];

const LEN_GPT_REVISION: usize = 4;
const GPT_REVISION: [u8; LEN_GPT_REVISION] = [0x00, 0x00, 0x01, 0x00];

const GPT_LBA_MAX: u64 = u64::MAX;
const GPT_LBA_PRIMARY: u64 = 0x1;
const GPT_LBA_FIRST: u64 = 0x22;
const GPT_LBA_ENTRIES: u64 = 0x02;

#[repr(C, packed)]
#[derive(PartialEq, Debug, Clone)]
struct GPTHeader {
    signature: [u8; LEN_GPT_SIGNATURE],
    revision: [u8; LEN_GPT_REVISION],
    size: u32, // le
    crc32_hdr: u32, // le
    _res: [u8; 4],
    current_lba: u64,
    backup_lba: u64,
    first_lba: u64,
    last_lba: u64,
    guid: uuid::Uuid,
    entries_lba: u64,
    n_entries: u32,
    sz_entry: u32,
    crc32_entries: u32,
}

const LEN_GPT_HEADER: usize = size_of::<GPTHeader>();

impl Default for GPTHeader {
    fn default() -> Self {
        Self {
            signature: GPT_SIGNATURE,
            revision: GPT_REVISION,
            size: LEN_GPT_HEADER as u32,
            crc32_hdr: Default::default(),
            _res: Default::default(),
            current_lba: GPT_LBA_PRIMARY,
            backup_lba: GPT_LBA_MAX,
            first_lba: GPT_LBA_FIRST,
            last_lba: GPT_LBA_MAX,
            guid: uuid::Uuid::new_v4(),
            entries_lba: GPT_LBA_ENTRIES,
            n_entries: Default::default(),
            sz_entry: LEN_GPT_ENTRY,
            crc32_entries: Default::default()
        }
    }
}

const N_GPT_ENTRIES: usize = 128;

impl GPTHeader {
    fn crc32_hdr_must_zero(&self, table: &CRC32Table) -> u32 {
        let p = self as *const GPTHeader as *const u8;
        let bytes = unsafe {
            std::slice::from_raw_parts(p, size_of::<Self>())
        };
        table.calculate(bytes)
    }

    fn crc32_entries(&self, table: &CRC32Table, entries: &[GPTEntry; N_GPT_ENTRIES]) -> u32 {
        let p = entries as *const GPTEntry as *const u8;
        let bytes = unsafe {
            std::slice::from_raw_parts(p, size_of::<[GPTEntry; N_GPT_ENTRIES]>())
        };
        table.calculate(bytes)
    }

    fn verify(&self, entries: &[GPTEntry; N_GPT_ENTRIES]) {
        let table = CRC32Table::new();
        let crc32_hdr = self.crc32_hdr;
        let mut header_dup = self.clone();
        header_dup.crc32_hdr = 0;
        assert_eq!(header_dup.crc32_hdr_must_zero(&table), crc32_hdr);
        let crc32_entries = self.crc32_entries;
        let expected = self.crc32_entries(&table, entries);
        if expected != crc32_entries {
            println!("Warning: crc32 for entries incorrect (recorded 0x{:08x} != expected 0x{:08x}), this should only happen for Amlogic's gpl.bin but not ours", crc32_entries, expected)
        }
    }

    fn update(&mut self, entries: &[GPTEntry; N_GPT_ENTRIES]) {
        let table = CRC32Table::new();
        self.crc32_entries = self.crc32_entries(&table, entries);
        self.crc32_hdr = 0;
        self.crc32_hdr = self.crc32_hdr_must_zero(&table)
    }
}

const LEN_GPT_RES: usize = 420;

#[repr(C, packed)]
struct GPTBin {
    mbr: ProtectiveMBR,
    header_primary: GPTHeader,
    _res_primary: [u8; LEN_GPT_RES],
    entries_primary: [GPTEntry; N_GPT_ENTRIES],
    entries_backup: [GPTEntry; N_GPT_ENTRIES],
    header_backup: GPTHeader,
    _res_backup: [u8; LEN_GPT_RES],
}

impl Default for GPTBin {
    fn default() -> Self {
        Self {
            mbr: Default::default(),
            header_primary: Default::default(),
            _res_primary: [0u8; LEN_GPT_RES],
            entries_primary: unsafe {std::mem::zeroed()},
            entries_backup: unsafe {std::mem::zeroed()},
            header_backup: Default::default(),
            _res_backup: [0u8; LEN_GPT_RES],
        }
    }
}

impl GPTBin {
    fn verify(&self) {
        self.mbr.verify();
        assert_eq!(self.header_primary, self.header_backup); // In real world they should not be identical
        assert_eq!(self.entries_primary, self.entries_backup);
        self.header_primary.verify(&self.entries_primary);
        let entries = &self.entries_primary;
        entries[0].verify(GPT_FIRST_LBA_0, GPT_LAST_LBA_0, GPT_FLAGS_0, GPT_NAME_0);
        entries[1].verify(GPT_FIRST_LBA_1, GPT_LAST_LBA_1, GPT_FLAGS_1, GPT_NAME_1);
        entries[2].verify(GPT_FIRST_LBA_2, GPT_LAST_LBA_2, GPT_FLAGS_2, GPT_NAME_2);
        entries[3].verify(GPT_FIRST_LBA_3, GPT_LAST_LBA_3, GPT_FLAGS_3, GPT_NAME_3);
        // let part_reserved = self.
        for i in 0..(self.header_primary.n_entries as usize) {
            let entry = &entries[i];
            assert_eq!(entry.first_lba % 2048, 0, "partition start does not align at MiB boundary");
            assert_eq!((entry.last_lba + 1) % 2048, 0, "partition end does not align at MiB boundary");
        }
    }

    fn to_csv(&self) -> String {
        let mut buffer = String::from("name,size_mb,flagx\n");
        let n_entries = self.header_primary.n_entries as usize;
        for i in 4..n_entries {
            let entry = &self.entries_primary[i];
            let flags = entry.flags;
            let current = if entry.last_lba == GPT_LBA_MAX {
                format!("{},-,{:x}\n", entry.name.to_string(), flags)
            } else {
                let size_mb = (entry.last_lba - entry.first_lba + 1) / 2048;
                format!("{},{},{:x}\n", entry.name.to_string(), size_mb, flags)
            };
            buffer.push_str(&current);
        }
        buffer
    }

    fn from_csv(csv: &str) -> Self {
        let mut bin = Self::default();
        bin.entries_primary[0] = GPTEntry::new(None, GPT_FIRST_LBA_0, GPT_LAST_LBA_0, GPT_FLAGS_0, GPT_NAME_0);
        bin.entries_primary[1] = GPTEntry::new(None, GPT_FIRST_LBA_1, GPT_LAST_LBA_1, GPT_FLAGS_1, GPT_NAME_1);
        bin.entries_primary[2] = GPTEntry::new(None, GPT_FIRST_LBA_2, GPT_LAST_LBA_2, GPT_FLAGS_2, GPT_NAME_2);
        bin.entries_primary[3] = GPTEntry::new(None, GPT_FIRST_LBA_3, GPT_LAST_LBA_3, GPT_FLAGS_3, GPT_NAME_3);
        let mut last_lba = GPT_LAST_LBA_3;
        let mut id_entry = 4;
        for line in csv.lines().skip(1) {
            let mut step = 0;
            let mut name = "";
            let first_lba = last_lba + 2049;
            let mut flags = 0u64;
            for part in line.split(',') {
                match step {
                    0 => { /* name */
                        name = part;
                    },
                    1 => { /* size MB */
                        if part == "-" {
                            last_lba = GPT_LBA_MAX;
                        } else {
                            let size_mb: u64 = part.parse().expect("Failed to parse size MB");
                            last_lba = first_lba + size_mb * 2048 - 1;
                        }
                    },
                    2 => { /* flags */
                        flags = u64::from_str_radix(part, 16).expect("Failed to parse flag")

                    },
                    _ => panic!("Too many fields")
                }
                step += 1;
            }
            assert_eq!(step, 3, "Too few fields");
            bin.entries_primary[id_entry] = GPTEntry::new(None, first_lba, last_lba, flags, name.as_bytes());
            id_entry += 1;
        }
        bin.header_primary.n_entries = id_entry as u32;
        bin.header_primary.update(&bin.entries_primary);
        bin.entries_backup = bin.entries_primary.clone();
        bin.header_backup = bin.header_primary.clone();
        bin
    }
}


#[derive(clap::ValueEnum, Clone)]
enum Action {
    Dump,
    Apply,
}

#[derive(clap::Parser)]
#[command(version)]
struct Args {
    action: Action,
    blob: String,
    text: String,
}

fn main() {
    let args: Args = clap::Parser::parse();
    match args.action {
        Action::Dump => {
            println!("Dumping '{}' to '{}'", args.blob, args.text);
            let gpt_bin = {
                let mut gpt_bin = std::mem::MaybeUninit::<GPTBin>::zeroed();
                let p = gpt_bin.as_mut_ptr() as *mut u8;
                let buffer = unsafe {std::slice::from_raw_parts_mut(p, size_of::<GPTBin>())};
                let mut f = std::fs::File::open(args.blob).expect("Failed to open file");
                std::io::Read::read(&mut f, buffer).expect("Failed to read");
                unsafe { gpt_bin.assume_init() }
            };
            gpt_bin.verify();
            std::fs::write(args.text, gpt_bin.to_csv()).expect("Failed to write")
        },
        Action::Apply => {
            println!("Applying '{}' from '{}'", args.blob, args.text);
            let gpt_bin = {
                let buffer = std::fs::read_to_string(args.text).expect("Failed to read csv");
                GPTBin::from_csv(&buffer)
            };
            gpt_bin.verify();
            let p = &gpt_bin as *const GPTBin as *const u8;
            let buffer = unsafe {std::slice::from_raw_parts(p, size_of::<GPTBin>())};
            println!("{}", buffer.len());
            std::fs::write(args.blob, buffer).expect("Failed to write new gpt.bin")
        },
    }
}
