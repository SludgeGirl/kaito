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

use crate::msdos::File as MSDosFile;

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

    mem_dump(emu, "mem_init", file.alloc);

    emu.add_code_hook(0x0, file.alloc as u64, |unicorn, address, size| {
        let decoder = InstDecoder::default();
        let machine_code = unicorn
            .mem_read_as_vec(address, size as usize)
            .expect("Failed to read code hook memory");

        info!("----------------------");

        let instruction = decoder.decode_slice(&machine_code);
        if instruction.is_err() {
            error!("Invalid instruction: {:X?}", machine_code);
        } else {
            let instruction = instruction.unwrap();
            info!(
                "Running code (address, buffer): {:X?} {:X?}",
                address, machine_code
            );
            info!("{} {:X?}", instruction.to_string(), instruction.opcode());

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

    let prog_start = (file.cs << 4) + file.ip;
    info!("Starting program at: {:X?}", prog_start);
    emu.reg_write(RegisterX86::IP, 0).unwrap();
    let result = emu.emu_start(prog_start, file.alloc, 30 * SECOND_SCALE, 0);
    let reg_value = emu.reg_read(RegisterX86::IP).unwrap();

    if result.is_err() {
        error!("Got result {:?} {:X?} {:X?}", result, reg_value, file.alloc);
        error!(
            "es {:X?} di {:X?} ds {:X?} si {:X?}",
            emu.reg_read(RegisterX86::ES).unwrap(),
            emu.reg_read(RegisterX86::DI).unwrap(),
            emu.reg_read(RegisterX86::DS).unwrap(),
            emu.reg_read(RegisterX86::SI).unwrap(),
        );
    } else {
        println!(
            "Got result {:?} {:X?} {:X?}",
            result.unwrap(),
            reg_value,
            file.alloc
        );
    }

    mem_dump(emu, "mem_dump", file.alloc);
    let mut buffer = [0; 20];
    emu.mem_read(prog_start, &mut buffer).expect("");
    info!("Program start {:X?} Until: {:X?}", buffer, file.alloc);
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

fn mem_dump(unicorn: &mut Unicorn<'_, ()>, path: &str, memory_size: u64) {
    debug!("Dumping memory to {}", path);
    let mut fh = File::create(path).expect("Failed to open memdump file");
    let mut offset: u64 = 0x0;
    while offset < memory_size as u64 {
        let mut buffer: [u8; 4096] = [0; 4096];
        unicorn
            .mem_read(offset, &mut buffer)
            .expect("Failed to dump memory");
        fh.write_all(&buffer)
            .expect("Failed to dump memory to file");
        offset += 4096;
    }
}
