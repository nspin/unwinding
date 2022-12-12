use super::{FDEFinder, FDESearchResult};
use crate::util::{deref_pointer, get_unlimited_slice};

use core::sync::atomic::{AtomicBool, Ordering};
use gimli::{BaseAddresses, EhFrame, EhFrameHdr, NativeEndian, UnwindSection};

static mut CUSTOM_FDE_FINDER: Option<&(dyn FDEFinder + Sync)> = None;

static CUSTOM_FDE_FINDER_INIT_STARTED: AtomicBool = AtomicBool::new(false);
static CUSTOM_FDE_FINDER_INIT_COMPLETED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct SetCustomFDEFinderError(());

pub fn set_custom_fde_finder(
    fde_finder: &'static (dyn FDEFinder + Sync),
) -> Result<(), SetCustomFDEFinderError> {
    if CUSTOM_FDE_FINDER_INIT_STARTED.swap(true, Ordering::SeqCst) {
        Err(SetCustomFDEFinderError(()))
    } else {
        unsafe {
            CUSTOM_FDE_FINDER = Some(fde_finder);
        }
        CUSTOM_FDE_FINDER_INIT_COMPLETED.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn get_custom_fde_finder() -> Option<&'static dyn FDEFinder> {
    if CUSTOM_FDE_FINDER_INIT_COMPLETED.load(Ordering::SeqCst) {
        Some(unsafe { CUSTOM_FDE_FINDER.unwrap() })
    } else {
        None
    }
}

pub struct CustomFinder(());

pub fn get_finder() -> &'static CustomFinder {
    &CustomFinder(())
}

impl FDEFinder for CustomFinder {
    fn find_fde(&self, pc: usize) -> Option<FDESearchResult> {
        get_custom_fde_finder().and_then(|fde_finder| fde_finder.find_fde(pc))
    }
}

pub trait BaseAddressFinder {
    fn find_text_base(&self, _pc: usize) -> Option<usize>;

    fn find_eh_frame_hdr(&self) -> Option<usize> {
        None
    }

    fn find_eh_frame(&self) -> Option<usize> {
        None
    }
}

impl<T: BaseAddressFinder> FDEFinder for T {
    fn find_fde(&self, pc: usize) -> Option<FDESearchResult> {
        let text = self.find_text_base(pc)?;
        self.find_eh_frame_hdr()
            .and_then(|eh_frame_hdr| find_fde_with_eh_frame_hdr(pc, text, eh_frame_hdr))
            .or_else(|| {
                self.find_eh_frame()
                    .and_then(|eh_frame| find_fde_with_eh_frame(pc, text, eh_frame))
            })
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
