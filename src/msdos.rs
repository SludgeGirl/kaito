use std::{fs::File, io::Read, path::Path};

use byteorder::{ByteOrder, LittleEndian};
use unicorn_engine::{RegisterX86, Unicorn};

pub struct MSDosFile {
    pub header: MSDosHeader,
    pub data: Vec<u8>,
    pub ip: u64,
    pub cs: u64,
}

impl MSDosFile {
    pub fn load_file(unicorn: &mut Unicorn<'_, ()>, path: &Path) -> Self {
        let mut file = File::open(path).expect("Failed to open file");
        let mut buffer: Vec<u8> = vec![];
        file.read_to_end(&mut buffer).expect("Failed to read file");

        let header = MSDosHeader::load_from_buf(&buffer);
        // HACK: discard the first 512. This is the header size for the test file
        buffer.drain(0..512);
        println!("{:X?}", header);

        unicorn
            .reg_write(
                RegisterX86::SS,
                LittleEndian::read_u16(&header.initial_ss) as u64,
            )
            .expect("Failed to setup ss register");

        unicorn
            .reg_write(
                RegisterX86::SP,
                LittleEndian::read_u16(&header.initial_sp) as u64,
            )
            .expect("Failed to setup sp register");

        let ip = LittleEndian::read_u16(&header.initial_ip) as u64;
        unicorn
            .reg_write(RegisterX86::IP, ip)
            .expect("Failed to setup ip register");

        let cs = LittleEndian::read_u16(&header.initial_cs) as u64;
        unicorn
            .reg_write(RegisterX86::CS, cs)
            .expect("Failed to setup cs register");

        Self {
            header,
            data: buffer,
            ip,
            cs,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct MSDosHeader {
    signature: [u8; 2],
    extra_bytes: [u8; 2],
    pages: [u8; 2],
    relocation_items: [u8; 2],
    header_size: [u8; 2],
    min_allocation: [u8; 2],
    max_allocation: [u8; 2],
    initial_ss: [u8; 2],
    initial_sp: [u8; 2],
    checksum: [u8; 2],
    initial_ip: [u8; 2],
    initial_cs: [u8; 2],
    relocation_table: [u8; 2],
    overlay: [u8; 2],
}

impl MSDosHeader {
    pub fn load_from_buf(buf: &[u8]) -> Self {
        Self {
            signature: [buf[0], buf[1]],
            extra_bytes: [buf[2], buf[3]],
            pages: [buf[4], buf[5]],
            relocation_items: [buf[6], buf[7]],
            header_size: [buf[8], buf[9]],
            min_allocation: [buf[10], buf[11]],
            max_allocation: [buf[12], buf[13]],
            initial_ss: [buf[14], buf[15]],
            initial_sp: [buf[16], buf[17]],
            checksum: [buf[18], buf[19]],
            initial_ip: [buf[20], buf[21]],
            initial_cs: [buf[22], buf[23]],
            relocation_table: [buf[24], buf[25]],
            overlay: [buf[26], buf[27]],
        }
    }

    pub fn get_data_from_buffer(&self) -> &[u8] {
        unsafe {
            ::core::slice::from_raw_parts(
                (self as *const MSDosHeader) as *const u8,
                ::core::mem::size_of::<MSDosHeader>(),
            )
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct MSDosRelocation {
    offset: [u8; 2],
    segment: [u8; 2],
}
