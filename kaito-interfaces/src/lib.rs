pub trait Backend {
    fn add_code_hook(&mut self, start: u64, end: u64, callback: fn(Box<dyn CallbackArgs>));

    fn add_interrupt_hook<T: CallbackArgs>(self, callback: fn(T));

    fn start(self, begin: u64, until: u64, timeout: u64, count: usize);
}

pub trait CallbackArgs {

}

pub struct GenericCallback<T> {
    pub backend: T,
    pub address: usize,
    pub size: usize,
}

impl <T>CallbackArgs for GenericCallback<T> {}
