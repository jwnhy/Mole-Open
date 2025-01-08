use std::fmt::Display;
use binrw::{NullString, BinWrite};
#[derive(Default, BinWrite)]
pub struct VecTable {
    pub addrs: Vec<(u32, NullString)>,
    pub init_sp: u32
}

const IRQ_NAMES: [&str; 16] = [
    "DUMMY",
    "Reset",
    "NMI",
    "Hard Fault",
    "Mem Fault",
    "Bus Fault",
    "Usage Fault",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "SVC",
    "Debug",
    "Reserved",
    "PendSV",
    "Sys Tick",
];
const IRQ_BEGIN: usize = IRQ_NAMES.len();

impl Display for VecTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Init SP {:08x}\n", self.init_sp)?;
        for (addr, name) in self.addrs.iter() {
            write!(f, "{:16} {:08x}\n", name, addr)?;
        }
        Ok(())
    }
}

impl VecTable {
    pub fn new(raw: &Vec<u8>, start_addr: usize, nr_entries: usize) -> Self {
        let mut vec_table = Self::default();
        vec_table.init_sp = u32::from_le_bytes(raw[start_addr..start_addr + 4].try_into().unwrap());
        for i in 1..nr_entries {
            let name = if i >= IRQ_BEGIN {
                format!("IRQ {}", i-IRQ_BEGIN)
            } else {
                IRQ_NAMES[i].to_string()
            };
            let addr = start_addr + i * 4;
            let data = u32::from_le_bytes(raw[addr..addr + 4].try_into().unwrap());
            vec_table.addrs.push((data as u32, name.to_string().into()));
        }
        vec_table
    }
}
