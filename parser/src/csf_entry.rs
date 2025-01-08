use binrw::{parser, writer, BinRead, BinResult, BinWrite, NullString};
use capstone::OwnedInsn;
use modular_bitfield::prelude::*;
use std::any::Any;
use std::fmt::Display;

#[derive(IntoStaticStr, Debug, FromRepr, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CsfEntryType {
    CsfEntryTypeInterface = 0,
    CsfEntryTypeConfig = 1,
    CsfEntryTypeTraceBuffer = 3,
    CsfEntryTypeTimelineMeta = 4,
    CsfEntryTypeBuildMeta = 6,
    CsfEntryTypeFuncList = 7,
    CsfEntryTypeCoreDump = 9,
    CsfEntryTypeUnknown(u8),
}

impl From<u8> for CsfEntryType {
    fn from(value: u8) -> Self {
        CsfEntryType::from_repr(value).unwrap_or(CsfEntryType::CsfEntryTypeUnknown(value))
    }
}

impl Into<u8> for CsfEntryType {
    fn into(self) -> u8 {
        match self {
            CsfEntryType::CsfEntryTypeInterface => 0,
            CsfEntryType::CsfEntryTypeConfig => 1,
            CsfEntryType::CsfEntryTypeTraceBuffer => 3,
            CsfEntryType::CsfEntryTypeTimelineMeta => 4,
            CsfEntryType::CsfEntryTypeBuildMeta => 6,
            CsfEntryType::CsfEntryTypeFuncList => 7,
            CsfEntryType::CsfEntryTypeCoreDump => 9,
            CsfEntryType::CsfEntryTypeUnknown(x) => x,
        }
    }
}

impl Default for CsfEntryType {
    fn default() -> Self {
        CsfEntryType::CsfEntryTypeUnknown(0)
    }
}

#[bitfield]
#[derive(BinRead, BinWrite, Debug, Clone, Copy, Default)]
#[br(map = Self::from_bytes)]
#[bw(map = |x: &HeaderFlags| { x.into_bytes() })]
pub struct HeaderFlags {
    #[allow(unused)]
    unused: B6,
    pub updatable: bool,
    pub optional: bool,
}

#[derive(BinRead, BinWrite, Default, Debug, Clone, Copy)]
#[brw(little)]
pub struct CsfEntryHeader {
    pub entry_type: u8,
    pub entry_size: u8,
    #[brw(pad_before = 1)]
    pub flags: HeaderFlags,
}

impl CsfEntryHeader {
    fn header_size() -> usize {
        return 4;
    }
    fn entry_size(self: &Self) -> usize {
        return self.entry_size as usize;
    }
    fn headless_size(self: &Self) -> usize {
        return self.entry_size as usize - 4;
    }
    fn optional(self: &Self) -> bool {
        return self.flags.optional();
    }
    fn updatable(self: &Self) -> bool {
        return self.flags.updatable();
    }
    fn entry_type(self: &Self) -> CsfEntryType {
        return self.entry_type.into();
    }
}

#[writer(writer: cursor)]
pub fn entry_writer(entries: &Vec<Box<dyn CsfEntry>>, entry_offset_end: usize) -> BinResult<()> {
    for entry in entries.iter() {
        //println!("Begin {} {}", cursor.stream_position()?, entry_offset_end);
        match entry.entry_type() {
            CsfEntryType::CsfEntryTypeInterface => {
                CsfEntryInterface::from_entry(entry).write_le(cursor)?
            }
            CsfEntryType::CsfEntryTypeConfig => {
                CsfEntryConfig::from_entry(entry).write_le(cursor)?
            }
            CsfEntryType::CsfEntryTypeTraceBuffer => {
                CsfEntryTraceBuffer::from_entry(entry).write_le(cursor)?
            }
            CsfEntryType::CsfEntryTypeTimelineMeta => {
                CsfEntryTimelineMeta::from_entry(entry).write_le(cursor)?
            }
            CsfEntryType::CsfEntryTypeFuncList => {
                CsfEntryFuncList::from_entry(entry).write_le(cursor)?
            }
            CsfEntryType::CsfEntryTypeBuildMeta => {
                CsfEntryBuildMeta::from_entry(entry).write_le(cursor)?
            }
            CsfEntryType::CsfEntryTypeCoreDump => {
                CsfEntryCoreDump::from_entry(entry).write_le(cursor)?
            }
            CsfEntryType::CsfEntryTypeUnknown(_) => {
                CsfEntryUnknown::from_entry(entry).write_le(cursor)?
            }
        };
        //println!("End {} {} {:?}", cursor.stream_position()?, entry.entry_size(), entry.entry_type());
    }
    assert!(cursor.stream_position()? as usize == entry_offset_end);
    Ok(())
}

#[parser(reader: cursor)]
pub fn entry_parser(entry_offset_end: usize) -> BinResult<Vec<Box<dyn CsfEntry>>> {
    let mut entries = vec![];
    let mut cur: u64;
    /* println!(
        "Position: {} {}",
        cursor.stream_position()?,
        entry_offset_end
    ); */
    while (cursor.stream_position()? as usize) < entry_offset_end {
        let header = CsfEntryHeader::read(cursor)?;
        cur = cursor.stream_position()?;
        let _ = cursor.seek(binrw::io::SeekFrom::Start(cur - 4));
        let entry: Box<dyn CsfEntry> = match header.entry_type() {
            CsfEntryType::CsfEntryTypeInterface => Box::new(CsfEntryInterface::read_le(cursor)?),
            CsfEntryType::CsfEntryTypeConfig => Box::new(CsfEntryConfig::read_le(cursor)?),
            CsfEntryType::CsfEntryTypeTraceBuffer => {
                Box::new(CsfEntryTraceBuffer::read_le(cursor)?)
            }
            CsfEntryType::CsfEntryTypeTimelineMeta => {
                Box::new(CsfEntryTimelineMeta::read_le(cursor)?)
            }
            CsfEntryType::CsfEntryTypeFuncList => Box::new(CsfEntryFuncList::read_le(cursor)?),
            CsfEntryType::CsfEntryTypeBuildMeta => Box::new(CsfEntryBuildMeta::read_le(cursor)?),
            CsfEntryType::CsfEntryTypeCoreDump => Box::new(CsfEntryCoreDump::read_le(cursor)?),
            CsfEntryType::CsfEntryTypeUnknown(x) if !header.optional() => {
                return Err(binrw::Error::Io(std::io::Error::new::<String>(
                    std::io::ErrorKind::Other,
                    format!("invalid entry type {}", x).into(),
                )));
            }
            _ => {
                println!(
                    "unknown entry type {} @ {} with size {}",
                    Into::<u8>::into(header.entry_type),
                    cursor.stream_position()?,
                    header.entry_size()
                );
                Box::new(CsfEntryUnknown::read_le(cursor)?)
            }
        };
        //println!("{}", entry);
        entries.push(entry);
        //println!("{}", entries.last().unwrap());
    }
    Ok(entries)
}

pub trait FromEntry {
    fn from_entry<'a>(entry: &'a Box<dyn CsfEntry + 'static>) -> &'a Self;
    fn from_entry_mut<'a>(entry: &'a mut Box<dyn CsfEntry + 'static>) -> &'a mut Self;
}

macro_rules! impl_from_entry {
    ($($t:ty),*) => {
        $(
            impl FromEntry for $t {
                fn from_entry<'a>(entry: &'a Box<dyn CsfEntry + 'static>) -> &'a Self {
                    entry.as_any().downcast_ref::<$t>().unwrap()
                }
                fn from_entry_mut<'a>(entry: &'a mut Box<dyn CsfEntry + 'static>) -> &'a mut Self {
                    entry.as_any_mut().downcast_mut::<$t>().unwrap()
                }
            }
        )*
    };
}

impl_from_entry!(
    CsfEntryCoreDump,
    CsfEntryBuildMeta,
    CsfEntryTimelineMeta,
    CsfEntryFuncList,
    CsfEntryTraceBuffer,
    CsfEntryConfig,
    CsfEntryInterface,
    CsfEntryUnknown
);

pub trait CsfEntry: Display + std::fmt::Debug {
    fn entry_type(self: &Self) -> CsfEntryType;
    fn entry_size(self: &Self) -> usize;
    fn as_any(self: &Self) -> &dyn Any;
    fn as_any_mut(self: &mut Self) -> &mut dyn Any;
}

macro_rules! impl_csf_entry {
    ($($t:ty),*) => {
        $(
            impl CsfEntry for $t {
                fn entry_size(self: &Self) -> usize{
                    self.header.entry_size()
                }
                fn entry_type(self: &Self) -> CsfEntryType {
                    self.header.entry_type()
                }
                fn as_any(self: &Self) -> &dyn Any {
                    self
                }
                fn as_any_mut(self: &mut Self) -> &mut dyn Any {
                    self
                }
            }
        )*
    };
}

impl_csf_entry!(
    CsfEntryCoreDump,
    CsfEntryBuildMeta,
    CsfEntryTimelineMeta,
    CsfEntryFuncList,
    CsfEntryTraceBuffer,
    CsfEntryConfig,
    CsfEntryInterface,
    CsfEntryUnknown
);

#[derive(Default, Debug, BinRead, BinWrite)]
pub struct CsfEntryUnknown {
    pub header: CsfEntryHeader,
    #[br(count = header.entry_size() - 4)]
    pub data: Vec<u8>,
}

impl Display for CsfEntryUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown entry type {}", self.header.entry_type)
    }
}

#[derive(Default, Debug, BinRead, BinWrite)]
pub struct CsfEntryCoreDump {
    pub header: CsfEntryHeader,
    pub version: u32,
    #[brw(pad_size_to = header.entry_size() - 8)]
    pub reg_addr: u32,
}

impl Display for CsfEntryCoreDump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:10}\t@ 0x{:08x} V{}",
            "CoreDump", self.reg_addr, self.version
        )?;
        Ok(())
    }
}

#[derive(Default, Debug, BinRead, BinWrite)]
pub struct CsfEntryBuildMeta {
    pub header: CsfEntryHeader,
    #[brw(pad_size_to = header.entry_size() - 4)]
    pub data_start: u32,
}

impl Display for CsfEntryBuildMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:10}\tP 0x{:08x}", "GITSHA", self.data_start,)?;
        Ok(())
    }
}

#[derive(Default, Debug, BinRead, BinWrite)]
pub struct CsfEntryTimelineMeta {
    pub header: CsfEntryHeader,
    pub data_start: u32,
    pub data_size: u32,
    #[brw(pad_size_to = header.entry_size() - 12)]
    pub name: NullString,
}

impl Display for CsfEntryTimelineMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:16}\tP 0x{:08x} - 0x{:08x}",
            self.name,
            self.data_start,
            self.data_start + self.data_size
        )?;
        Ok(())
    }
}

#[derive(Default, Debug, BinRead, BinWrite)]
pub struct CsfEntryFuncList {
    pub header: CsfEntryHeader,
    pub va_start: u32,
    #[brw(pad_size_to = header.entry_size() - 8)]
    pub va_end: u32,
}

impl Display for CsfEntryFuncList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:10}\t@ 0x{:08x} - 0x{:08x}",
            "FuncList", self.va_start, self.va_end
        )
    }
}

#[derive(Default, Debug, BinRead, BinWrite)]
pub struct CsfEntryTraceBuffer {
    pub header: CsfEntryHeader,
    pub typ: u32,
    pub size_addr: u32,
    pub insert_addr: u32,
    pub extract_addr: u32,
    pub data_addr: u32,
    pub enable_addr: u32,
    pub nr_enable: u32,
    #[brw(pad_size_to = header.entry_size() - 32)]
    pub name: NullString,
}
impl Display for CsfEntryTraceBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short_name = self.name.to_string().replace("monitor ", "");
        write!(
            f,
            "{:16} T0x{:01x} S0x{:08x} I0x{:08x} E0x{:08x} D0x{:08x} EN0x{:08x}",
            short_name,
            self.typ,
            self.size_addr,
            self.insert_addr,
            self.extract_addr,
            self.data_addr,
            self.enable_addr,
        )
    }
}

#[derive(Default, Debug, BinRead, BinWrite)]
pub struct CsfEntryConfig {
    pub header: CsfEntryHeader,
    pub addr: u32,
    pub min: u32,
    pub max: u32,
    #[brw(pad_size_to = header.entry_size() - 16)]
    pub name: NullString,
}

impl Display for CsfEntryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:10}\t@ 0x{:08x} [{}, {}]",
            self.name.to_string().split(' ').collect::<Vec<&str>>()[0],
            self.addr,
            self.min,
            self.max
        )?;
        Ok(())
    }
}

#[derive(Default, Debug, BinRead, BinWrite)]
pub struct CsfEntryInterface {
    pub header: CsfEntryHeader,
    pub flags: u32,
    pub virt_start: u32,
    pub virt_end: u32,
    pub data_start: u32,
    pub data_end: u32,
    pub name: NullString,
    #[brw(pad_size_to = header.entry_size() - (name.len() + 1) - 24)]
    pub virt_exe_start: u32,
}

pub enum MemoryCacheMode {
    None = 0,
    Cached = 1,
    UncachedCoherent = 2,
    CachedCoherent = 3,
}

impl CsfEntryInterface {
    pub fn read(self: &Self) -> bool {
        return self.flags & (1 << 0) != 0;
    }
    pub fn write(self: &Self) -> bool {
        return self.flags & (1 << 1) != 0;
    }
    pub fn execute(self: &Self) -> bool {
        return self.flags & (1 << 2) != 0;
    }
    pub fn cache_mode(self: &Self) -> MemoryCacheMode {
        match (self.flags >> 3) & 0b11 {
            0x0 => MemoryCacheMode::None,
            0x1 => MemoryCacheMode::Cached,
            0x2 => MemoryCacheMode::UncachedCoherent,
            0x3 => MemoryCacheMode::CachedCoherent,
            _ => unreachable!(),
        }
    }
    pub fn protected(self: &Self) -> bool {
        return self.flags & (1 << 5) != 0;
    }
    pub fn shared(self: &Self) -> bool {
        return self.flags & (1 << 30) != 0;
    }
    pub fn zerod(self: &Self) -> bool {
        return self.flags & (1 << 31) != 0;
    }
    pub fn virt_start(self: &Self) -> u32 {
        return self.virt_start;
    }
    pub fn virt_end(self: &Self) -> u32 {
        return self.virt_end;
    }
    pub fn data_start(self: &Self) -> u32 {
        return self.data_start;
    }
    pub fn data_end(self: &Self) -> u32 {
        return self.data_end;
    }
    pub fn actual_size(self: &Self) -> usize {
        self.name.len() + 28
    }
}

impl Display for CsfEntryInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let read = if self.read() { "R" } else { "-" };
        let write = if self.write() { "W" } else { "-" };
        let execute = if self.execute() { "X" } else { "-" };
        let cache_mode = match self.cache_mode() {
            MemoryCacheMode::None => "--",
            MemoryCacheMode::Cached => "C-",
            MemoryCacheMode::UncachedCoherent => "-C",
            MemoryCacheMode::CachedCoherent => "CC",
        };
        let protected = if self.protected() { "P" } else { "-" };
        let shared = if self.shared() { "S" } else { "-" };
        let zeroed = if self.zerod() { "Z" } else { "-" };
        write!(
            f,
            "{} V: 0x{:08x} - 0x{:08x} P: 0x{:08x} - 0x{:08x} VE: 0x{:08x} {}{}{} {} {}{}{}",
            self.name,
            self.virt_start,
            self.virt_end,
            self.data_start,
            self.data_end,
            self.virt_exe_start,
            read,
            write,
            execute,
            cache_mode,
            protected,
            shared,
            zeroed
        )
    }
}
