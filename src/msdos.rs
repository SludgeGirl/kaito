use std::{io::Read, path::Path};

use byteorder::{ByteOrder, LittleEndian};
use log::info;
use unicorn_engine::{RegisterX86, Unicorn};

pub struct File {
    pub header: Header,
    pub data: Vec<u8>,
    pub ip: u64,
    pub cs: u64,
}

impl File {
    pub fn load_file(unicorn: &mut Unicorn<'_, ()>, path: &Path) -> Self {
        let mut file = std::fs::File::open(path).expect("Failed to open file");
        let mut buffer: Vec<u8> = vec![];
        file.read_to_end(&mut buffer).expect("Failed to read file");

        let header = Header::load_from_buf(&buffer);
        // HACK: discard the first 512. This is the header size for the test file
        buffer.drain(0..512);
        info!("{:X?}", header);

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
pub struct Header {
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

impl Header {
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
                (self as *const Header) as *const u8,
                ::core::mem::size_of::<Header>(),
            )
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Relocation {
    offset: [u8; 2],
    segment: [u8; 2],
}

#[repr(C)]
#[derive(Debug)]
// https://www.stanislavs.org/helppc/program_segment_prefix.html
pub struct PSP {
    // Usually set to INT 0x20 (0xcd20) prog terminate
    exit: [u8; 2],
    // "Segment of the first byte beyond the memory allocated to the program"
    // Yeah that wording sucks. Basically the segment alloc ends
    // So if we've alloc'd 0x0 -> 0x2000 it'd be 0x2001 /probably/
    alloc_end: [u8; 2],
    resv: [u8; 2],
    // Far call instruction to MSDos function dispatcher
    call_disp: [u8; 5],
    // .COM programs bytes available in segment (CP/M)
    com_bytes: [u8; 2],
    // Terminate address used by INT 22, we need to jump to this addr on exit
    // This forces a child program to return to it's parent program
    term_addr: [u8; 4],
    // The Ctrl-Break exit address, a location of a subroutine for us to run
    // when we encounter a Ctrl-Break
    ctrl_break_addr: [u8; 4],
    // Similar to the above. If we critically error, run the routine here
    crit_err_addr: [u8; 4],
    // Parent process's segment address
    parent_addr: [u8; 2],
    // File handle array for the process. It's completely undocumented for 2.x+
    // /probably/ not in use for our case
    file_handle_array: [u8; 20],
    // Segment address of the environment, or zero
    env_segment_addr: [u8; 2],
    // SS:SP of the last program that called INT 0x21,0
    last_exit_addr: [u8; 4],
    // File handle array size
    file_handle_size: [u8; 2],
    // File handle array pointer
    file_handle_addr: [u8; 4],
    // Pointer to previous PSP
    prev_psp: [u8; 4],
    resv1: [u8; 20],
    // Dos function dispatcher, but not the one we've already referenced?
    // Gods know's what this one is, or why it's 3 bytes
    function_dispatcher: [u8; 3],
    resv2: [u8; 9],
    // Unopened fcb?
    // https://www.stanislavs.org/helppc/fcb.html
    fcb: [u8; 36],
    // Overlays section of fcb
    fcb_overlays: [u8; 20],
    // count of characters in command tail, all bytes following command name
    command_tail_count: [u8; 1],
    // Every byte following the program name
    command_tail: [u8; 127],
}
