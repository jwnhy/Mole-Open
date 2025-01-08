use std::error::Error;

pub(crate) fn check_magic(file: &[u8], cursor: &mut usize) -> Result<(), Box<dyn Error>> {
    let magic: u32 = 0xC3F13A6E;
    let fw_magic: u32 = u32::from_le_bytes(file[*cursor..*cursor + 4].try_into()?);
    if magic != fw_magic {
        return Err("Invalid magic".into());
    }
    *cursor += 4;
    Ok(())
}

pub(crate) fn read_version(file: &[u8], cursor: &mut usize) -> Result<(u8, u8), Box<dyn Error>> {
    let minor_version = file[*cursor];
    *cursor += 1;
    let major_version = file[*cursor];
    *cursor += 1;
    Ok((minor_version, major_version))
}

pub(crate) fn read_hash(file: &[u8], cursor: &mut usize) -> Result<u32, Box<dyn Error>> {
    *cursor = 0x8;
    let hash = u32::from_le_bytes(file[*cursor..*cursor + 4].try_into()?);
    *cursor += 4;
    Ok(hash)
}

pub(crate) fn read_entry_offset_end(file: &[u8], cursor: &mut usize) -> Result<usize, Box<dyn Error>> {
    *cursor = 0x10;
    let entry_offset_end = u32::from_le_bytes(file[*cursor..*cursor + 4].try_into()?);
    *cursor += 4;
    Ok(entry_offset_end as usize)
}

