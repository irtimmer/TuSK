use std::fs;

use opensk::api::persist::{Persist, PersistIter};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};

use xdg::BaseDirectories;

pub struct TuskPersist {
    xdg: BaseDirectories
}

impl TuskPersist {
    pub fn new(xdg: BaseDirectories) -> Self {
        TuskPersist {
            xdg
        }
    }
}

/// Persist implementation for `TuskPersist`.
///
/// This implementation stores values as files under the configured XDG data
/// directory. Keys are mapped to filenames using the pattern "<key>.bin"
/// where <key> is the decimal representation of the `usize` key.
///
/// Note: All filesystem and XDG-related failures are coalesced into
/// `CTAP2_ERR_VENDOR_INTERNAL_ERROR` for write/remove operations; read
/// failures are treated as absence for `find`.
impl Persist for TuskPersist {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        Ok(match self.xdg.find_data_file(format!("{}.bin", key)) {
            Some(path) => fs::read(path).ok(),
            None => None,
        })
    }

    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        let path = self.xdg.place_data_file(format!("{}.bin", key))
            .map_err(|_| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;

        fs::write(path, value).map_err(|_| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }

    fn remove(&mut self, key: usize) -> CtapResult<()> {
        match self.xdg.find_data_file(format!("{}.bin", key)) {
            Some(path) => fs::remove_file(path)
                .map_err(|_| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
            None => Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
        }
    }

    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        let files = self.xdg.list_data_files("");
        Ok(Box::new(files
            .into_iter()
            .filter_map(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_suffix(".bin"))
                    .and_then(|num_str| num_str.parse::<usize>().ok())
            })
            .map(|num| Ok(num))
        ))
    }
}
