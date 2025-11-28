const SZ_SECTOR: usize = 0x100;

const SIGNATURE: u64 = 0x5452415020494645; // "EFI PART"

#[repr(u8)]
#[derive(Default)]
enum MBREntryStatus {
    #[default]
    Inactive = 0x00,
    Active =   0x80
}

#[repr(packed)]
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
#[derive(Default)]
enum MBREntryType {
    #[default]
    GPTProtectiveMBR = 0xEE,
}

#[repr(packed)]
#[derive(Default)]
struct MBREntry {
    status: MBREntryStatus,
    first_chs: MBREntryAddress,
    type_part: MBREntryType,
    last_chs: MBREntryAddress,
    first_lba: u32,
    n_sectors: u32
}

#[repr(packed)]
struct EmptyField<const LEN: usize> ([u8; LEN]);

impl<const LEN: usize> Default for EmptyField<LEN> {
    fn default() -> Self {
        Self([0u8; LEN])
    }
}

#[repr(packed)]
#[derive(Default)]
struct ProtectiveMBR {
    bootstrap: EmptyField<446>,
    part1: MBREntry,
    part234: EmptyField<48>,
    sigature: EmptyField<2>,
}

#[repr(packed)]
struct GPTHeader {
    signature: [u8; 8],
    revision: [u8; 4],
    size: u32, // le
    crc32_hdr: u32, // le
    res: EmptyField<4>,
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

impl Default for GPTHeader {
    fn default() -> Self {
        Self {
            signature: [0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54],
            revision: [0x00, 0x00, 0x01, 0x00],
            size: 0x5c,
            crc32_hdr: Default::default(),
            res: Default::default(),
            current_lba: 0x01,
            backup_lba: 0xFFFFFFFFFFFFFFFF,
            first_lba: 0x22,
            last_lba: 0xFFFFFFFFFFFFFFFF,
            guid: Default::default(),
            entries_lba: 0x02,
            n_entries: Default::default(),
            sz_entry: 0x80,
            crc32_entries: Default::default()
        }
    }
}

#[repr(packed)]
struct GPTEntryName([u8; 72]);

impl Default for GPTEntryName {
    fn default() -> Self {
        Self([0u8; 72])
    }
}

impl GPTEntryName {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        let inner = &self.0;
        for i in (0 .. (size_of::<Self>())).step_by(2) {
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
        assert!(len * 2 <= size_of::<Self>());
        let mut name = Self::default();
        for i in 0 .. len {
            let off = i * 2;
            name.0[off] = b[i];
            name.0[off + 1] = 0;
        }
        name
    }

    fn from_str(s: &str) -> Self {
        Self::from_bytes(s.as_bytes())
    }
}

#[repr(packed)]
#[derive(Default)]
struct GPTEntry {
    uuid_type: uuid::Uuid,
    uuid_part: uuid::Uuid,
    fist_lba: u64,
    last_lba: u64,
    flags: u64,
    name: GPTEntryName,
}

#[repr(packed)]
struct GPTTable {
    header: GPTHeader,
    res: EmptyField<420>,
    entries: [GPTEntry; 128]
}

impl Default for GPTTable {
    fn default() -> Self {
        Self {
            header: Default::default(),
            res: Default::default(),
            entries: unsafe {std::mem::zeroed()}
        }
    }
}

#[repr(packed)]
#[derive(Default)]
struct GPTBin {
    mbr: ProtectiveMBR,
    primary: GPTTable,
    backup: GPTTable,
}


struct GPTUnbin {


}
