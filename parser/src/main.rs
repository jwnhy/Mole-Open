extern crate strum; // 0.10.0
#[macro_use]
extern crate strum_macros; // 0.10.0

pub mod csf;
pub mod csf_entry;
pub mod read_helpers;
pub mod vec_table;

use std::collections::HashMap;
use std::io::Write;

use capstone::prelude::*;
use csf::*;
use csf_entry::*;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
use unicorn_engine::{RegisterARM, Unicorn};

fn prepare(csf: &mut Box<Csf>, emu: &mut Unicorn<'_, Vec<u8>>) {
    let raw = csf.dump();
    for ent in csf
        .entries
        .iter()
        .filter(|x| x.entry_type() == CsfEntryType::CsfEntryTypeInterface)
    {
        let ent_if = CsfEntryInterface::from_entry(ent);
        if ent_if.shared() {
            continue;
        }
        let vaddr = ent_if.virt_start as u64;
        let vsize = (ent_if.virt_end - ent_if.virt_start) as usize;
        emu.mem_map(vaddr, vsize, Permission::ALL).unwrap();
        let pstart = ent_if.data_start as usize;
        let pend = ent_if.data_end as usize;
        emu.mem_write(vaddr, &raw[pstart..pend]).unwrap();
    }

    for ent in csf
        .entries
        .iter()
        .filter(|x| x.entry_type() == CsfEntryType::CsfEntryTypeTraceBuffer)
    {
        let ent_tb = CsfEntryTraceBuffer::from_entry(ent);
        emu.mem_write(ent_tb.size_addr as u64, &[0x0, 0x10, 0x0, 0x0])
            .unwrap();
        emu.mem_write(ent_tb.data_addr as u64, &[0x00, 0xbe, 0x07, 0x4])
            .unwrap(); // Trap accesses
        emu.mem_write(ent_tb.insert_addr as u64, &[0x40, 0xbe, 0x07, 0x4])
            .unwrap();
        emu.mem_write(ent_tb.extract_addr as u64, &[0x80, 0xbe, 0x07, 0x4])
            .unwrap();
        emu.mem_write(ent_tb.enable_addr as u64, &[0xff, 0xff, 0xff, 0xff])
            .unwrap();
    }

    let shared_write_callback =
        move |uc: &mut Unicorn<'_, Vec<u8>>, offset: u64, size: usize, value: u64| {
            let pc = uc.reg_read(RegisterARM::PC).expect("failed read");

            println!(
                "shared write {:#04x}, size={}, pc={:#04x} <-- {:#04x}",
                0x400_0000 + offset as u32,
                size,
                pc,
                value
            );

            if offset == 0x0000000 {
                // GLB_VERSION
                let patch = value & 0xffff;
                let minor = (value >> 16) & 0xff;
                let major = (value >> 24) & 0xff;

                println!("** CSF version {}.{}.{}", major, minor, patch)
            }
        };

    let shared_read_callback = move |uc: &mut Unicorn<'_, Vec<u8>>, offset: u64, size: usize| {
        let pc = uc.reg_read(RegisterARM::PC).expect("failed read");
        println!(
            "shared read {:#04x}, size={}, pc={:#04x}",
            0x400_0000 + offset as u32,
            size,
            pc
        );
        if offset == 0x94000 {
            return 0x4094100;
        } else if offset == 0x94004 {
            return 0x4094200;
        } else if offset == 0x94010 {
            return 0x4094300;
        } else if offset == 0x94014 {
            return 0x4094400;
        } else if offset == 0x94018 {
            return 0x4010000;
        }
        0
    };

    emu.mmio_map(
        0x400_0000 as u64,
        0x400_0000 as usize,
        Some(shared_read_callback),
        Some(shared_write_callback),
    )
    .expect("failed to map shared");

    let cb_interrupt = move |uc: &mut Unicorn<'_, Vec<u8>>, intno: u32| {
        let r0 = uc.reg_read(RegisterARM::R0).expect("failed read");
        let r1 = uc.reg_read(RegisterARM::R1).expect("failed read");

        // We only implement the putchar interface
        //assert_eq!(intno, 0x7);
        //assert_eq!(r0, 0x3);

        // Dereference to get the character
        let c = uc.mem_read_as_vec(r1, 1).unwrap()[0];

        if c == b'\n' {
            let output_buffer = &mut uc.get_data_mut();
            println!("DBG: {}", String::from_utf8(output_buffer.clone()).unwrap());
            output_buffer.clear();
        } else {
            uc.get_data_mut().push(c);
        }

        // Advance the program counter past the breakpoint
        let pc = uc.reg_read(RegisterARM::PC).expect("failed read");
        uc.reg_write(RegisterARM::PC, (pc + 2) | 1)
            .expect("failed update of PC");
    };
    emu.add_intr_hook(cb_interrupt).unwrap();

    let read_callback = move |uc: &mut Unicorn<'_, Vec<u8>>, offset: u64, size: usize| {
        let pc = uc.reg_read(RegisterARM::PC).expect("failed read");

        println!(
            "mmio read {:#04x}, size={}, pc={:#04x}",
            0x4000_0000 + offset as u32,
            size,
            pc
        );

        match offset {
            0x20000 => 0xffffffff,
            0x20080 => 0xffffffff,
            0x20180 => 0xffffffff,
            0x20200 => 0xffffffff,
            0x20280 => 0xffffffff,
            0x30004 => {
                let nr_of_cshwif = 1;
                let nr_of_fragment_iterators = 1;
                let nr_of_compute_iterators = 1;
                let nr_of_tiler_iterators = 1;

                nr_of_cshwif
                    | (nr_of_compute_iterators << 6)
                    | (nr_of_fragment_iterators << 11)
                    | (nr_of_tiler_iterators << 16)
            }
            0x30010 | 0x30014 | 0x30018 | 0x3001c => {
                // lower half: number of registers in CSHWIF#i register file
                // upper half: unknown
                8
            }
            _ => 0,
        }
    };

    let write_callback = move |uc: &mut Unicorn<'_, Vec<u8>>, offset, size, value| {
        let pc = uc.reg_read(RegisterARM::PC).expect("failed read");

        println!(
            "mmio write {:#04x}, size={}, pc={:#04x} <-- {:#04x}",
            0x4000_0000 + offset as u32,
            size,
            pc,
            value
        )
    };

    let ppb_read_callback = move |_: &mut Unicorn<'_, Vec<u8>>, offset: u64, size: usize| {
        const PPB_CCSIDR: u32 = 0xD80;
        const PPB_SYST_RVR: u32 = 0xD14;

        match offset as u32 {
            PPB_CCSIDR => 0xF003E019, // 4KB data cache, associativity=3
            PPB_SYST_RVR => 0x10000,
            //_ => panic!("don't know what to return "),
            _ => 0,
        }
    };

    let ppb_write_callback =
        move |uc: &mut Unicorn<'_, Vec<u8>>, offset: u64, size: usize, value: u64| {
            return;
            println!(
                "PPB write {:#04x} pc={:#08x}, size={} <-- {:#04x}",
                0xe000_e000 + offset as u32,
                uc.pc_read().unwrap(),
                size,
                value
            );
            if offset == 0xd9c {
                println!(
                    "MPU Base: {:#010x} @ Rgn: {}",
                    (value >> 5) << 5,
                    value & 0xf
                );
            }
            if offset == 0xda0 {
                println!(
                    "MPU Size: {:#010x} AP: {}",
                    1u64 << (((value >> 1) & 0x1f) + 1),
                    ((value >> 24) & 0x7)
                );
            }
        };

    emu.mmio_map(
        0x4000_0000 as u64,
        0x40000,
        Some(read_callback),
        Some(write_callback),
    )
    .unwrap();

    emu.mmio_map(
        0xe000_e000 as u64,
        0x1000 as usize,
        Some(ppb_read_callback),
        Some(ppb_write_callback),
    )
    .unwrap();
}

fn main() {
    let mut csf = parse_csf("./mali_csffw.bin").unwrap();
    let shellcode = include_bytes!("../fw.bin");
    let resetcode = include_bytes!("../reset.bin");

    csf.write_virt_mem(0x803bee, &0xc0f28402u32.to_be_bytes());
    //csf.write_virt_mem(0x803b62, &0x40f2370eu32.to_be_bytes());
    for (idx, (addr, name)) in csf.vec_table().addrs.iter().enumerate() {
        let copied_u32;
        let copied_u8;
        let mut tmp = if name.starts_with(b"Reset") {
            resetcode.clone()
        } else {
            shellcode.clone()
        };
        unsafe {
            (_, copied_u32, _) = tmp.align_to_mut::<u32>();
        }
        for i in 0..copied_u32.len() {
            if copied_u32[i] == 0xdeadbeef {
                copied_u32[i] = *addr;
            }
        }
        unsafe {
            (_, copied_u8, _) = tmp.align_to_mut::<u8>();
        }
        if name.starts_with(b"IRQ") || name.starts_with(b"Reset") {
            let insert_addr = csf.insert_data(copied_u8.to_vec());
            csf.write_virt_mem(((idx + 1) * 0x4) as u32, &(insert_addr + 1).to_le_bytes());
        }
    }

    csf.modify_interface(
        |x| CsfEntryInterface::from_entry(x).shared(),
        |x| {
            let ent = CsfEntryInterface::from_entry_mut(x);
            ent.virt_end = 0x0530_0000;
        },
    );
    csf.list_entries();
    println!("{}", csf.vec_table());

    let raw = csf.dump();
    let mut new_csf = std::fs::File::create("new_csf.bin").unwrap();
    new_csf.write_all(&raw).unwrap();

    let mut emu: Unicorn<'_, Vec<u8>> =
        Unicorn::new_with_data(Arch::ARM, Mode::MCLASS, vec![]).unwrap();

    prepare(&mut csf, &mut emu);
    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()
        .unwrap();
    emu.add_code_hook(0x801f89, 0x820000, move |emu, address, size| {
        let inst = emu.mem_read_as_vec(address, size as usize).unwrap();
        let disas = cs.disasm_all(&inst, address as u64).unwrap();
        for i in disas.iter() {
            println!("{} {:?}", i, i.bytes());
        }
    });

    //emu.mem_write(0x04094000, &0x04094100u32.to_le_bytes());
    //emu.mem_write(0x04094000, &0x04094200u32.to_le_bytes());

    let res = emu.emu_start(0x820001u32 as u64, 0x09100000, 0, 0);
    println!("{:?}", res);
    let res = emu.emu_start(0x821001u32 as u64, 0x09100000, 0, 0);
    println!("{:?}", res);
    //let res = emu.emu_start(0x0 as u64, 0x00820000, 0, 0);
    //println!("{:?}", res);
}
