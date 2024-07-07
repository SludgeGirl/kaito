mod msdos;

use std::{
    any::Any, borrow::BorrowMut, env, fs::File, io::Write, ops::DerefMut, path::Path, sync::Arc,
};

use log::{debug, error, info};
use unicorn_engine::{
    unicorn_const::{Arch, Mode, Permission, SECOND_SCALE},
    RegisterX86, Unicorn,
};
use yaxpeax_x86::real_mode::InstDecoder;

use crate::msdos::MSDosFile;

const MEM_SIZE: usize = 0x0020_0000;

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    info!("Loading file {}", args.get(1).expect(""));
    let path = Path::new(args.get(1).expect("No file provided"));

    let mut unicorn = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_16)
        .expect("failed to initialize Unicorn instance");
    let emu = unicorn.borrow_mut();

    add_standard_interrupts(emu);

    let file = MSDosFile::load_file(emu, path);

    emu.mem_map(0x0, MEM_SIZE, Permission::ALL)
        .expect("failed to map code page");

    emu.mem_write(0x0_u64, &file.data)
        .expect("Failed to write code segment");

    emu.add_code_hook(0x0, MEM_SIZE as u64, |unicorn, address, _size| {
        let mut buffer = [0; 4];
        let decoder = InstDecoder::default();
        unicorn
            .mem_read(address, &mut buffer)
            .expect("Failed to read code hook memory");

        info!("----------------------");
        info!(
            "Running code (address, buffer): {:X?} {:X?}",
            address, buffer
        );

        let instruction = decoder.decode_slice(&buffer);
        if instruction.is_err() {
            error!("Invalid instruction: {:X?}", buffer);
        } else {
            let instruction = instruction.unwrap();
            info!("{:X?}", instruction.to_string());

            let mut i = 0;
            while instruction.operand_present(i) {
                let register = match instruction.operand(i).to_string().as_str() {
                    "ax" => Ok(RegisterX86::AX),
                    "ah" => Ok(RegisterX86::AH),
                    "al" => Ok(RegisterX86::AL),

                    "bx" => Ok(RegisterX86::BX),
                    "bh" => Ok(RegisterX86::BH),
                    "bl" => Ok(RegisterX86::BL),

                    "si" => Ok(RegisterX86::SI),
                    "di" => Ok(RegisterX86::DI),
                    "bp" => Ok(RegisterX86::BP),
                    "sp" => Ok(RegisterX86::SP),

                    "ip" => Ok(RegisterX86::IP),

                    "cs" => Ok(RegisterX86::IP),
                    "ds" => Ok(RegisterX86::DS),
                    "es" => Ok(RegisterX86::ES),
                    "ss" => Ok(RegisterX86::SS),

                    _ => Err(()),
                };

                if register.is_ok() {
                    let register = register.unwrap();
                    info!(
                        "Register {}: {:X?}",
                        instruction.operand(i).to_string().as_str(),
                        unicorn.reg_read(register).unwrap(),
                    );
                }
                i += 1;
            }
        }
    })
    .expect("Failed to add code hook");

    mem_dump(emu, "mem_dump");

    let prog_start = (file.cs << 4) + file.ip;
    info!("Starting program at: {:X?}", prog_start);
    let result = emu.emu_start(prog_start, MEM_SIZE as u64, 30 * SECOND_SCALE, 0);
    let reg_value = emu.reg_read(RegisterX86::IP).unwrap();

    println!("Got result {:?} {}", result.unwrap(), reg_value);

    let mut buffer = [0; 20];
    emu.mem_read(0x126D2_u64, &mut buffer).expect("");
    info!("Program start {:X?} Until: {:X?}", buffer, MEM_SIZE);
}

fn add_standard_interrupts(unicorn: &mut Unicorn<'_, ()>) {
    unicorn
        .add_intr_hook(|u, i| {
            // Based off: https://stanislavs.org/helppc/int_21-4.html
            let ah = u.reg_read(RegisterX86::AH).unwrap();
            info!("INT: {:X?} AH: {:X?} PC: {}", i, ah, u.pc_read().unwrap());
            match i {
                0x21 => {
                    match ah {
                        0x30 => {
                            u.reg_write(RegisterX86::AL, 2).unwrap();
                            u.reg_write(RegisterX86::AH, 0).unwrap();
                        }
                        0x40 => {
                            let bx = u.reg_read(RegisterX86::BX).unwrap();
                            let cx = u.reg_read(RegisterX86::CX).unwrap();
                            info!(
                                "Interrupt 0x21 - 0x40 handle: {} byte count: {}",
                                bx,
                                u.reg_read(RegisterX86::CX).unwrap()
                            );

                            match bx {
                                2 | 3 => {
                                    let buffer = u
                                        .mem_read_as_vec(
                                            (u.reg_read(RegisterX86::DS).unwrap() << 4)
                                                + u.reg_read(RegisterX86::DX).unwrap(),
                                            cx as usize,
                                        )
                                        .expect("");
                                    let mut full_string = String::new();
                                    for c in buffer.iter() {
                                        full_string.push(*c as char);
                                    }
                                    println!("{}", full_string);
                                }
                                _ => {}
                            }

                            u.reg_write(RegisterX86::AX, cx)
                                .expect("Failed 0x21 - 0x40 call");
                            u.reg_write(
                                RegisterX86::FLAGS,
                                u.reg_read(RegisterX86::FLAGS).unwrap() & 0b0,
                            )
                            .expect("Failed to set register flags");
                            // u.emu_stop();
                        } // INT 21,4 - Auxiliary Output
                        0x4C => {
                            let exit_code = u.reg_read(RegisterX86::AL).unwrap();
                            error!(
                                "Exiting from interrupt 21 - 4C {:X?} {}",
                                exit_code, exit_code
                            );
                            std::process::exit(exit_code as i32);
                        }
                        _ => todo!("0x21 unmatched ah: {:X?}", ah),
                    };
                }
                0x33 => {
                    match ah {
                        // 0x0 => {
                        //     let num: i32 = -1;
                        //     u.reg_write(RegisterX86::AH, num as u64).unwrap();
                        //     u.reg_write(RegisterX86::BX, 3).unwrap();
                        // }
                        _ => todo!("0x21 unmatched ah: {:X?}", ah),
                    };
                }
                _ => todo!("unmatched interrupt: {}", i),
            };
        })
        .expect("failed to add interrupt hook");
}

fn mem_dump(unicorn: &mut Unicorn<'_, ()>, path: &str) {
    debug!("Dumping memory to {}", path);
    let mut fh = File::create(path).expect("Failed to open memdump file");
    let mut offset: u64 = 0;
    while offset < MEM_SIZE as u64 {
        let mut buffer: [u8; 128] = [0; 128];
        unicorn
            .mem_read(offset, &mut buffer)
            .expect("Failed to dump memory");
        fh.write_all(&buffer)
            .expect("Failed to dump memory to file");
        offset += 128;
    }
}
