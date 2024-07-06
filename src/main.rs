mod msdos;

use std::{
    any::Any, borrow::BorrowMut, env, fs::File, io::Write, ops::DerefMut, path::Path, sync::Arc,
};

use unicorn_engine::{
    unicorn_const::{Arch, Mode, Permission, SECOND_SCALE},
    RegisterX86, Unicorn,
};
use yaxpeax_x86::real_mode::InstDecoder;

use crate::msdos::MSDosFile;

const MEM_SIZE: usize = 0x0020_0000;

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("Loading file {}", args.get(1).expect(""));
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
        println!("");
        let mut buffer = [0; 4];
        let decoder = InstDecoder::default();
        unicorn
            .mem_read(address, &mut buffer)
            .expect("Failed to read code hook memory");

        println!(
            "Running code (address, buffer): {:X?} {:X?}",
            address, buffer
        );

        let instruction = decoder.decode_slice(&buffer);
        if instruction.is_err() {
            println!("Invalid instruction: {:X?}", buffer);
        } else {
            let instruction = instruction.unwrap();
            println!("{:X?}", instruction.to_string());

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
                    println!(
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
    println!("Starting program at: {:X?}", prog_start);
    let result = emu.emu_start(prog_start, MEM_SIZE as u64, 30 * SECOND_SCALE, 0);
    let reg_value = emu.reg_read(RegisterX86::IP).unwrap();

    println!("Got result {:?} {}", result.unwrap(), reg_value);

    let mut buffer = [0; 20];
    emu.mem_read(0x126D2_u64, &mut buffer).expect("");
    println!("Program start {:X?} Until: {:X?}", buffer, MEM_SIZE);
}

fn add_standard_interrupts(unicorn: &mut Unicorn<'_, ()>) {
    unicorn
        .add_intr_hook(|u, i| {
            // Based off: https://stanislavs.org/helppc/int_21-4.html
            let ah = u.reg_read(RegisterX86::AH).unwrap();
            println!("INT: {:X?} AH: {:X?} PC: {}", i, ah, u.pc_read().unwrap());
            match i {
                0x21 => {
                    match ah {
                        0x40 => {
                            let bx = u.reg_read(RegisterX86::BX).unwrap();
                            let cx = u.reg_read(RegisterX86::CX).unwrap();
                            println!(
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
                                        full_string.push_str(match c {
                                            0x20 => " ",
                                            0x50 => "P",
                                            0x61 => "a",
                                            0x62 => "b",
                                            0x63 => "c",
                                            0x64 => "d",
                                            0x65 => "e",
                                            0x66 => "f",
                                            0x67 => "g",
                                            0x68 => "h",
                                            0x69 => "i",
                                            0x6a => "j",
                                            0x6b => "k",
                                            0x6c => "l",
                                            0x6d => "m",
                                            0x6e => "n",
                                            0x6f => "o",
                                            0x70 => "p",
                                            0x71 => "q",
                                            0x72 => "r",
                                            0x73 => "s",
                                            0x74 => "t",
                                            0x75 => "u",
                                            0x76 => "v",
                                            0x77 => "w",
                                            0x78 => "x",
                                            0x79 => "y",
                                            0x7a => "z",
                                            _ => "`",
                                        });
                                    }
                                    // println!("{:X?}", buffer);
                                    println!("{:?}", full_string);
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
                            println!(
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
    println!("Dumping memory to {}", path);
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
