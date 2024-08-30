use std::u64;

use kaito_interfaces::{Backend, CallbackArgs, GenericCallback};
use unicorn_engine::Unicorn;

pub struct MSDos<'a> {
    pub driver: Unicorn<'a, ()>,
}

impl<'a> Backend for MSDos<'a> {
    fn add_code_hook(&mut self, start: u64, end: u64, callback: fn(Box<dyn CallbackArgs>)) {
        self.driver
            .add_code_hook(start, end, |unicorn, address, size| {
                callback(Box::new(GenericCallback::<&mut Unicorn<'a, ()>> {
                    backend: unicorn,
                    address: address as usize,
                    size: size as usize,
                }));
            })
            .expect("");
    }

    fn add_interrupt_hook<T: CallbackArgs>(mut self, callback: fn(T)) {
        // self.driver.add_intr_hook(callback).expect("");
    }

    fn start(mut self, begin: u64, until: u64, timeout: u64, count: usize) {
        self.driver
            .emu_start(begin, until, timeout, count)
            .expect("");
    }
}
