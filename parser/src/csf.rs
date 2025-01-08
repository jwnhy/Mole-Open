use crate::csf_entry::*;
use crate::read_helpers::*;
use crate::vec_table::*;
use binrw::{binrw, helpers::until_eof, BinRead, BinWrite};
use capstone::prelude::*;
use capstone::OwnedInsn;
use std::cmp::max;
use std::io::Cursor;
use std::{error::Error, fs};

#[derive(Default, BinRead, BinWrite)]
#[brw(magic = 0xC3F13A6Eu32)]
pub struct Csf {
    minor_version: u8,
    major_version: u8,
    #[brw(align_before(0x8))]
    hash: u32,
    #[brw(align_before(0x10))]
    pub entry_offset_end: u32,
    #[br(parse_with = entry_parser, args(entry_offset_end as usize))]
    #[bw(write_with = entry_writer, args(*entry_offset_end as usize))]
    pub entries: Vec<Box<dyn CsfEntry>>,
    #[br(parse_with = until_eof)]
    pub raw: Vec<u8>,
}

impl Csf {
    pub fn insert_data(self: &mut Self, data: Vec<u8>) -> u32 {
        const EXTRA_RANGE: u32 = 0x82_0000;
        let existing = self.entries.iter().fold(0, |acc, e| {
            if e.entry_type() == CsfEntryType::CsfEntryTypeInterface {
                let interface = CsfEntryInterface::from_entry(e);
                if interface.virt_end > 0x90_0000 {
                    return acc;
                }
                max(interface.virt_end, acc)
            } else {
                acc
            }
        });

        /* putting a new entry in */
        let start = max(existing, EXTRA_RANGE);
        let new_entry = CsfEntryInterface {
            header: CsfEntryHeader {
                entry_type: crate::CsfEntryType::CsfEntryTypeInterface.into(),
                entry_size: 0x30, // large enough
                flags: HeaderFlags::new(),
            },
            virt_start: start,
            virt_end: start + data.len() as u32,
            data_start: self.entry_offset_end + self.raw.len() as u32,
            data_end: self.entry_offset_end + self.raw.len() as u32 + data.len() as u32,
            flags: 0b0000_0000_0000_0000_0000_0000_0000_1101,
            name: "".into(),
            virt_exe_start: start,
        };
        let new_entry_size = new_entry.entry_size();
        self.entry_offset_end += new_entry_size as u32;
        self.entries.push(Box::new(new_entry));
        self.raw.extend(data);

        /* fix other entries */
        for entry in self.entries.iter_mut() {
            if entry.entry_type() == CsfEntryType::CsfEntryTypeInterface {
                let interface = CsfEntryInterface::from_entry_mut(entry);
                if interface.data_start == interface.data_end {
                    continue;
                }
                interface.data_start += new_entry_size as u32;
                interface.data_end += new_entry_size as u32;
            }
            if entry.entry_type() == CsfEntryType::CsfEntryTypeBuildMeta {
                let build_meta = CsfEntryBuildMeta::from_entry_mut(entry);
                build_meta.data_start += new_entry_size as u32;
            }
        }
        start
    }

    pub fn dump(self: &Self) -> Vec<u8> {
        let mut cursor = Cursor::new(vec![]);
        self.write_le(&mut cursor).unwrap();
        cursor.into_inner()
    }
    pub fn vec_table(self: &Self) -> VecTable {
        let vec_table_data = self.extract_virt_mem(0x0, 0x1000);
        VecTable::new(&vec_table_data, 0x0, 31)
    }
    pub fn load(data: &Vec<u8>) -> Result<Box<Csf>, Box<dyn Error>> {
        let mut csf_cursor = Cursor::new(data);
        let csf: Box<Csf> = Box::new(Csf::read_le(&mut csf_cursor)?);
        csf_cursor.set_position(0x14 as u64);
        Ok(csf)
    }
}

pub fn parse_csf(path: &str) -> Result<Box<Csf>, Box<dyn Error>> {
    let csf_file = fs::read(path)?;
    println!("csf file size: {:x}", csf_file.len());
    Csf::load(&csf_file)
}

impl Csf {
    pub fn list_entries(self: &Self) {
        for entry in self.entries.iter() {
            println!("{}", entry);
        }
    }
    pub fn modify_interface(
        self: &mut Self,
        predicate: fn(&Box<dyn CsfEntry>) -> bool,
        modifier: fn(&mut Box<dyn CsfEntry>),
    ) {
        for entry in self.entries.iter_mut() {
            if entry.entry_type() == CsfEntryType::CsfEntryTypeInterface && predicate(entry) {
                modifier(entry);
            }
        }
    }
    pub fn write_virt_mem(self: &mut Self, addr: u32, data: &[u8]) {
        for entry in self.entries.iter() {
            if entry.entry_type() == CsfEntryType::CsfEntryTypeInterface {
                let interface = CsfEntryInterface::from_entry(entry);
                if interface.virt_start <= addr && addr + data.len() as u32 <= interface.virt_end {
                    let offset = addr - interface.virt_start;
                    let start = (interface.data_start - self.entry_offset_end) as usize;
                    self.raw[start + offset as usize..start + offset as usize + data.len()]
                        .copy_from_slice(data);
                }
            }
        }
    }
    // we assume extraction do NOT overlap TWO sections
    pub fn extract_virt_mem(self: &Self, addr: u32, size: u32) -> Vec<u8> {
        let mut virt_mem = vec![];
        for entry in self.entries.iter() {
            if entry.entry_type() == CsfEntryType::CsfEntryTypeInterface {
                let interface = CsfEntryInterface::from_entry(entry);
                if interface.virt_start <= addr && addr + size <= interface.virt_end {
                    let offset = addr - interface.virt_start;
                    let start = (interface.data_start - self.entry_offset_end) as usize;
                    let end = (interface.data_end - self.entry_offset_end) as usize;
                    virt_mem.extend_from_slice(&self.raw[start + offset as usize..end as usize]);
                }
            }
        }
        virt_mem
    }
}
