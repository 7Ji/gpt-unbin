#[repr(u8)]
#[derive(Default, Debug, PartialEq)]
enum MBREntryStatus {
    #[default]
    Inactive = 0x00,
    _Active =   0x80
}

#[repr(packed)]
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

#[repr(packed)]
struct MBREntry {
    status: MBREntryStatus,
    first_chs: MBREntryAddress,
    type_part: MBREntryType,
    last_chs: MBREntryAddress,
    first_lba: u32,
    n_sectors: u32
}

impl Default for MBREntry {
    fn default() -> Self {
        Self {
            status: Default::default(),
            first_chs: Default::default(),
            type_part: Default::default(),
            last_chs: Default::default(),
            first_lba: 1,
            n_sectors: Default::default()
        }
    }
}

impl MBREntry {
    fn verify(&self) {
        assert_eq!(self.status, MBREntryStatus::Inactive);
        assert_eq!(self.first_chs, MBREntryAddress::default());
        assert_eq!(self.type_part, MBREntryType::default());
        assert_eq!(self.last_chs, MBREntryAddress::default());
        let first_lba = self.first_lba;
        assert_eq!(first_lba, 1);
        let n_sectors = self.n_sectors;
        assert_eq!(n_sectors, 0);
    }
}

// #[repr(packed)]
// struct EmptyField<const LEN: usize> ([u8; LEN]);

// impl<const LEN: usize> Default for EmptyField<LEN> {
//     fn default() -> Self {
//         Self([0u8; LEN])
//     }
// }

#[repr(packed)]
struct ProtectiveMBR {
    bootstrap: [u8; 446],
    part1: MBREntry,
    part234: [u8; 48],
    sigature: [u8; 2],
}

impl Default for ProtectiveMBR {
    fn default() -> Self {
        Self {
            bootstrap: [0u8; 446],
            part1: Default::default(),
            part234: [0u8; 48],
            sigature: [0u8; 2],
        }
    }
}

impl ProtectiveMBR {
    fn verify(&self) {
        assert_eq!(self.bootstrap, [0u8; 446]);
        assert_eq!(self.part234, [0u8; 48]);
        assert_eq!(self.sigature, [0u8; 2]);
        self.part1.verify()
    }
}

#[repr(packed)]
struct GPTHeader {
    signature: [u8; 8],
    revision: [u8; 4],
    size: u32, // le
    crc32_hdr: u32, // le
    res: [u8; 4],
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
struct GPTBin {
    mbr: ProtectiveMBR,
    header_primary: GPTHeader,
    _res_primary: [u8; 420],
    entries_primary: [GPTEntry; 128],
    entries_backup: [GPTEntry; 128],
    header_backup: GPTHeader,
    _res_backup: [u8; 420],
}

impl Default for GPTBin {
    fn default() -> Self {
        Self {
            mbr: Default::default(),
            header_primary: Default::default(),
            _res_primary: [0u8; 420],
            entries_primary: unsafe {std::mem::zeroed()},
            entries_backup: unsafe {std::mem::zeroed()},
            header_backup: Default::default(),
            _res_backup: [0u8; 420],
        }
    }
}

impl GPTBin {
    fn verify(&self) {
        self.mbr.verify();


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
            let mut buffer = [0u8; size_of::<GPTBin>()];
            {
                let mut f = std::fs::File::open(args.blob).expect("Failed to open file");
                std::io::Read::read(&mut f, &mut buffer).expect("Failed to read");
            }
            println!("{:?}", &buffer[0..446]);
            let p = buffer.as_ptr() as *const GPTBin;
            let gpt_bin = unsafe { p.read() };
            println!("{:?}", gpt_bin.mbr.bootstrap);
            let p2 = buffer.as_ptr() as *const ProtectiveMBR;
            let mbr = unsafe {p2.read()};
            println!("{:?}", mbr.bootstrap);
            let bp_dup = mbr.bootstrap;
            println!("{:?}", &buffer[0..446]);
            println!("{:?}", bp_dup)
            // gpt_bin.verify();
            // let n = gpt_bin.primary.header.n_entries;
            // println!("There're {} partitions in the table", n);

        },
        Action::Apply => {
            println!("Applying '{}' from '{}'", args.blob, args.text)
        },
    }
}
