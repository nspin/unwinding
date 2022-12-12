use super::FDESearchResult;
use crate::util::*;

use gimli::{BaseAddresses, EhFrame, EhFrameHdr, NativeEndian, UnwindSection};

pub struct DeferredFinder(());

pub fn get_finder() -> &'static DeferredFinder {
    &DeferredFinder(())
}

extern "Rust" {
    fn __unwinding_get_text_base(pc: usize) -> Option<usize>;
    fn __unwinding_get_eh_frame_hdr() -> Option<usize>;
    fn __unwinding_get_eh_frame() -> Option<usize>;
}

mod defaults {
    #[no_mangle]
    #[linkage = "weak"]
    fn __unwinding_get_text_base(_pc: usize) -> Option<usize> {
        None
    }

    #[no_mangle]
    #[linkage = "weak"]
    fn __unwinding_get_eh_frame_hdr() -> Option<usize> {
        None
    }

    #[no_mangle]
    #[linkage = "weak"]
    fn __unwinding_get_eh_frame() -> Option<usize> {
        None
    }
}

impl super::FDEFinder for DeferredFinder {
    fn find_fde(&self, pc: usize) -> Option<FDESearchResult> {
        unsafe {
            let text = __unwinding_get_text_base(pc)?;
            __unwinding_get_eh_frame_hdr()
                .and_then(|eh_frame_hdr| find_fde_with_eh_frame_hdr(pc, text, eh_frame_hdr))
                .or_else(|| {
                    __unwinding_get_eh_frame()
                        .and_then(|eh_frame| find_fde_with_eh_frame(pc, text, eh_frame))
                })
        }
    }
}

fn find_fde_with_eh_frame_hdr(
    pc: usize,
    text: usize,
    eh_frame_hdr: usize,
) -> Option<FDESearchResult> {
    unsafe {
        let bases = BaseAddresses::default()
            .set_text(text as _)
            .set_eh_frame_hdr(eh_frame_hdr as _);
        let eh_frame_hdr = EhFrameHdr::new(
            get_unlimited_slice(eh_frame_hdr as usize as _),
            NativeEndian,
        )
        .parse(&bases, core::mem::size_of::<usize>() as _)
        .ok()?;
        let eh_frame = deref_pointer(eh_frame_hdr.eh_frame_ptr());
        let bases = bases.set_eh_frame(eh_frame as _);
        let eh_frame = EhFrame::new(get_unlimited_slice(eh_frame as _), NativeEndian);

        // Use binary search table for address if available.
        if let Some(table) = eh_frame_hdr.table() {
            if let Ok(fde) =
                table.fde_for_address(&eh_frame, &bases, pc as _, EhFrame::cie_from_offset)
            {
                return Some(FDESearchResult {
                    fde,
                    bases,
                    eh_frame,
                });
            }
        }

        // Otherwise do the linear search.
        if let Ok(fde) = eh_frame.fde_for_address(&bases, pc as _, EhFrame::cie_from_offset) {
            return Some(FDESearchResult {
                fde,
                bases,
                eh_frame,
            });
        }

        None
    }
}

fn find_fde_with_eh_frame(pc: usize, text: usize, eh_frame: usize) -> Option<FDESearchResult> {
    unsafe {
        let bases = BaseAddresses::default()
            .set_text(text as _)
            .set_eh_frame(eh_frame as _);
        let eh_frame = EhFrame::new(get_unlimited_slice(eh_frame as _), NativeEndian);

        if let Ok(fde) = eh_frame.fde_for_address(&bases, pc as _, EhFrame::cie_from_offset) {
            return Some(FDESearchResult {
                fde,
                bases,
                eh_frame,
            });
        }

        None
    }
}
