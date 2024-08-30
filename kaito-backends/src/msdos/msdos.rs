use std::{io::Read, path::Path};

use byteorder::{ByteOrder, LittleEndian};
use log::{debug, info};
use unicorn_engine::{unicorn_const::Permission, RegisterX86, Unicorn};

pub struct File {
    pub header: Header,
    pub data: Vec<u8>,
    pub alloc: u64,
    pub ip: u64,
    pub cs: u64,
}

impl File {
    pub fn load_file(unicorn: &mut Unicorn<'_, ()>, path: &Path) -> Self {
        let mut file = std::fs::File::open(path).expect("Failed to open file");
        let mut buffer: Vec<u8> = vec![];
        file.read_to_end(&mut buffer).expect("Failed to read file");

        let header = Header::load_from_buf(&buffer);
        // discard the header
        let header_size = LittleEndian::read_u16(&header.header_size) as usize * 16;
        buffer.drain(0..header_size);

        let bound: u64 = 4096;
        let psp_size = std::mem::size_of::<PSP>();
        info!("PSP Size {}", psp_size);
        // std::process::exit(0);
        let needed_alloc: u64 = LittleEndian::read_u16(&header.max_allocation) as u64 * 16
            + buffer.len() as u64
            + psp_size as u64;
        let alloc = (((needed_alloc + bound - 1) / bound) * bound) as usize;

        unicorn
            .mem_map(0x0, alloc, Permission::ALL)
            .expect("failed to map code page");

        info!("Allocating {:X?} for program", alloc);

        let psp = PSP {
            exit: 0x20,
            alloc_end: (alloc + 1) as u16, // Wrong
            resv: 0,
            call_disp: [0xFF; 5], // Wrong
            // com_bytes: 0,
            term_addr: 0xFFFF_FFFF, // Lets go to out of bounds so we can fail hard
            ctrl_break_addr: 0x9999_9999,
            crit_err_addr: 0x9999_9999,
            parent_addr: 0x0,
            file_handle_array: [0; 20],
            env_segment_addr: 0x0,
            last_exit_addr: 0x9999_9999,
            file_handle_size: 0x0,
            file_handle_addr: 0x9999_9999,
            prev_psp: 0x0,
            resv1: [0; 4],
            resv2: [0; 14],
            dos_ver: 2,
            far_call_dos: [0xFF; 3],
            resv3: [0; 9],
            fcb: [0; 16],
            fcb2: [0; 20],
            bytes_cmd: 0,
            cmd_tail: [0; 127],
        };
        let psp_addr = 0x0;
        let psp_bytes = unsafe { any_as_u8_slice(&psp) };
        unicorn
            .mem_write(psp_addr, psp_bytes)
            .expect("Failed to write psp");

        unicorn
            .mem_write(psp_size as u64, &buffer)
            .expect("Failed to write code segment");

        let ip = (LittleEndian::read_u16(&header.initial_ip) + psp_size as u16) as u64;
        unicorn
            .reg_write(RegisterX86::IP, ip)
            .expect("Failed to setup ip register");

        let cs = LittleEndian::read_u16(&header.initial_cs) as u64;
        info!("IP: {:X?} CS: {:X?} Loading: {:X?}", ip, cs, (cs << 4) + ip);
        unicorn
            .reg_write(RegisterX86::CS, cs)
            .expect("Failed to setup CS register");

        unicorn
            .reg_write(
                RegisterX86::SS,
                LittleEndian::read_u16(&header.initial_ss).into(),
            )
            .expect("Failed to setup SS register");
        unicorn
            .reg_write(
                RegisterX86::SP,
                LittleEndian::read_u16(&header.initial_sp).into(),
            )
            .expect("Failed to setup SP register");

        let psp_segment = psp_addr >> 4;
        unicorn
            .reg_write(RegisterX86::ES, psp_segment)
            .expect("Could't write psp segment to ES");
        unicorn
            .reg_write(RegisterX86::DS, psp_segment)
            .expect("Could't write psp segment to DS");

        unicorn
            .reg_write(RegisterX86::AL, 0)
            .expect("Could't write psp segment to AL");
        unicorn
            .reg_write(RegisterX86::AH, 0)
            .expect("Could't write psp segment to AH");

        debug!("ES: {:X?} DS: {:X?}", psp_segment, psp_segment);

        Self {
            header,
            data: buffer,
            alloc: alloc as u64,
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
}

#[repr(C)]
#[derive(Debug)]
pub struct Relocation {
    offset: [u8; 2],
    segment: [u8; 2],
}

// https://www.stanislavs.org/helppc/program_segment_prefix.html
#[repr(C)]
#[repr(packed)]
#[derive(Debug)]
pub struct PSP {
    /// Usually set to INT 0x20 (0xcd20) prog terminate
    exit: u16,
    /// "Segment of the first byte beyond the memory allocated to the program"
    /// Yeah that wording sucks. Basically the segment alloc ends
    /// So if we've alloc'd 0x0 -> 0x2000 it'd be 0x2001 /probably/
    alloc_end: u16,
    resv: u8,
    /// Far call instruction to MSDos function dispatcher
    call_disp: [u8; 5],
    /// .COM programs bytes available in segment (CP/M)
    // com_bytes: u32,
    /// Terminate address used by INT 22, we need to jump to this addr on exit
    /// This forces a child program to return to it's parent program
    term_addr: u32,
    /// The Ctrl-Break exit address, a location of a subroutine for us to run
    /// when we encounter a Ctrl-Break
    ctrl_break_addr: u32,
    /// Similar to the above. If we critically error, run the routine here
    crit_err_addr: u32,
    /// Parent process's segment address
    parent_addr: u16,
    /// File handle array for the process. It's completely undocumented for 2.x+
    /// /probably/ not in use for our case
    file_handle_array: [u8; 20],
    /// Segment address of the environment, or zero
    env_segment_addr: u16,
    /// SS:SP of the last program that called INT 0x21,0
    last_exit_addr: u32,
    /// File handle array size
    file_handle_size: u16,
    /// File handle array pointer
    file_handle_addr: u32,
    /// Pointer to previous PSP
    prev_psp: u32,
    resv1: [u8; 4],
    dos_ver: u16,
    resv2: [u8; 14],
    far_call_dos: [u8; 3],
    resv3: [u8; 9],
    fcb: [u8; 16],
    fcb2: [u8; 20],
    bytes_cmd: u8,
    cmd_tail: [u8; 127],
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
}
