use kaito_backends::msdos::MSDos;
use kaito_interfaces::Backend;

fn main() {
    let mut unicorn = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_16)
        .expect("failed to initialize Unicorn instance");
    let emu = unicorn.borrow_mut();
    let msdos = MSDos{ driver: emu };

    msdos.add_code_hook(0, 0x8000, |arguments| {
        println!("{:?}", arguments);
    });

    msdos.add_code_hook(0, 0x9000, |arguments| {
        println!("{:?}", arguments);
    })
}
