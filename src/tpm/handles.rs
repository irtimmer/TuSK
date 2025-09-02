use tss_esapi::Context;
use tss_esapi::handles::KeyHandle;

/// A small guard that ties a TPM key handle to a mutable borrow of a TPM `Context`.
///
/// This struct ensures the handle is released when no longer needed on drop.
/// It ties the lifetime of the `KeyHandle` to the lifetime of the `Context`.
pub(crate) struct HandleGuard<'a> {
    pub handle: KeyHandle,
    pub ctx: &'a mut Context,
}

impl<'a> Drop for HandleGuard<'a> {
    fn drop(&mut self) {
        // The result of flushing is ignored, which is common in drop implementations.
        // Panicking in drop is generally discouraged.
        let _ = self.ctx.flush_context(self.handle.into());
    }
}

impl<'a> HandleGuard<'a> {
    pub fn new(handle: KeyHandle, ctx: &'a mut Context) -> Self {
        HandleGuard { handle, ctx }
    }
}
