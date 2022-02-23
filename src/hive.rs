// Copyright 2019-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::byte_subrange;
use crate::key_node::KeyNode;
use core::convert::TryInto;
use core::ops::Range;
use core::{mem, u32};
use enumn::N;
use memoffset::offset_of;
use binread::{BinRead, BinReaderExt, PosValue};
use std::io;

#[derive(BinRead)]
#[repr(packed)]
struct CellHeader {
    size: PosValue<i32>,
}

/// Known hive minor versions.
///
/// You can use [`HiveMinorVersion::n`] on the value returned by [`Hive::minor_version`]
/// to find out whether a hive has a known version.
#[derive(Clone, Copy, Debug, Eq, N, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum HiveMinorVersion {
    WindowsNT3_1Beta = 0,
    WindowsNT3_1 = 1,
    WindowsNT3_5 = 2,
    WindowsNT4 = 3,
    WindowsXPBeta = 4,
    WindowsXP = 5,
    WindowsVista = 6,
}

#[allow(dead_code)]
#[repr(u32)]
enum HiveFileTypes {
    Primary = 0,
    Log = 1,
    External = 2,
}

#[repr(u32)]
enum HiveFileFormats {
    Memory = 1,
}

/// this data structure follows the documentation found at
/// <https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#format-of-primary-files>
#[allow(dead_code)]
#[derive(BinRead)]
#[br(magic = b"regf")]
struct HiveBaseBlock {
    primary_sequence_number: PosValue<u32>,
    secondary_sequence_number: PosValue<u32>,
    timestamp: PosValue<u64>,

    #[br(assert(major_version==1))]
    major_version: PosValue<u32>,

    #[br(assert(vec![3, 4, 5, 6].contains(&*minor_version)))]
    minor_version: PosValue<u32>,

    #[br(assert(*file_type==1 || *file_type==2))]
    file_type: PosValue<u32>,

    #[br(assert(*file_format==1))]
    file_format: PosValue<u32>,
    root_cell_offset: PosValue<u32>,

    #[br(assert(*data_size%4096 == 0))]
    data_size: PosValue<u32>,
    clustering_factor: PosValue<u32>,
    file_name: PosValue<[u16; 32]>,
    #[br(count=99)]
    padding_1: PosValue<Vec<u32>>,
    checksum: PosValue<u32>,
    #[br(count=0x37E)]
    padding_2: PosValue<Vec<u32>>,
    boot_type: PosValue<u32>,
    boot_recover: PosValue<u32>,
}


#[derive(BinRead)]
#[br(magic = b"hbin")]
struct HiveBin {
    offset: u32,

    #[br(assert(size%4096 == 0))]
    size: u32,
    reserved: u64,
    timestamp: u64,
    spare: u32
}

/// Root structure describing a registry hive.
pub struct Hive<B: BinReaderExt> {
    base_block: HiveBaseBlock,
    data_len: usize,
    pub(crate) data: B,
}

impl<B> Hive<B>
where
    B: BinReaderExt,
{
    /// Creates a new `Hive` from any byte slice.
    /// Performs basic validation and rejects any invalid hive.
    ///
    /// You may use [`Hive::without_validation`] if you want to accept hives that fail validation.
    pub fn new(bytes: B) -> Result<Self> {
        let hive = Self::without_validation(bytes)?;
        hive.validate()?;
        Ok(hive)
    }

    /// Creates a new `Hive` from any byte slice, without validating the header.
    ///
    /// You may later validate the header via [`Hive::validate`].
    /// This is a solution for accessing parts of hives that have not been fully flushed to disk
    /// (e.g. due to hibernation and mismatching sequence numbers).
    pub fn without_validation(bytes: B) -> Result<Self> {
        let data_len = bytes.seek(io::SeekFrom::End(0)).unwrap() as usize;
        bytes.seek(io::SeekFrom::Start(0)).unwrap();
        let base_block: HiveBaseBlock = bytes.read_le()?;

        let hive = Self { base_block, data: bytes, data_len };
        Ok(hive)
    }

    pub(crate) fn cell_range_from_data_offset(&self, data_offset: u32) -> Result<Range<usize>> {
        // Only valid data offsets are accepted here.
        assert!(data_offset != u32::MAX);

        // Accept only u32 data offsets, but convert them into usize right away for
        // slice range operations and fearless calculations.
        let data_offset = data_offset as usize;

        // After the check above, the following operation must succeed, so we can just `unwrap`.
        //
        // FIXME: remove the following line
        // let header = LayoutVerified::<&[u8], CellHeader>::new(&self.data[header_range]).unwrap();
        self.data.seek(io::SeekFrom::Start(data_offset as u64))?;
        let header: CellHeader = self.data.read_le()?;
        let cell_size = header.size;
        let cell_data_offset = self.data.seek(io::SeekFrom::Current(0))? as usize;

        // A cell with size > 0 is unallocated and shouldn't be processed any further by us.
        if *cell_size > 0 {
            return Err(NtHiveError::UnallocatedCell {
                offset: self.offset_of_data_offset(data_offset),
                size: *cell_size,
            });
        }
        let cell_size = cell_size.abs() as usize;

        // The cell size must be a multiple of 8 bytes
        let expected_alignment = 8;
        if cell_size % expected_alignment != 0 {
            return Err(NtHiveError::InvalidSizeFieldAlignment {
                offset: self.offset_of_field(&header.size),
                size: cell_size,
                expected_alignment,
            });
        }

        // Get the actual data range and verify that it's inside our hive data.
        let remaining_range = cell_data_offset..self.data_len;
        let cell_data_range = byte_subrange(&remaining_range, cell_size).ok_or_else(|| {
            NtHiveError::InvalidSizeField {
                offset: self.offset_of_field(&header.size),
                expected: cell_size,
                actual: remaining_range.len(),
            }
        })?;

        Ok(cell_data_range)
    }

    /// Calculate a field's offset from the very beginning of the hive bytes.
    ///
    /// Note that this function primarily exists to provide absolute hive file offsets when reporting errors.
    /// It cannot be used to index into the hive bytes, because they are initially split into `base_block`
    /// and `data`.
    pub(crate) fn offset_of_field<T>(&self, field: &PosValue<T>) -> usize {
        let field_address = field.pos as usize;
        /*
        let base_address = self.base_block.bytes().as_ptr() as usize;

        assert!(field_address > base_address);
        field_address - base_address
        */
        field_address
    }

    /// Calculate a data offset's offset from the very beginning of the hive bytes.
    pub(crate) fn offset_of_data_offset(&self, data_offset: usize) -> usize {
        data_offset + mem::size_of::<HiveBaseBlock>()
    }

    /// Returns the major version of this hive.
    ///
    /// The only known value is `1`.
    pub fn major_version(&self) -> u32 {
        *self.base_block.major_version
    }

    /// Returns the minor version of this hive.
    ///
    /// You can feed this value to [`HiveMinorVersion::n`] to find out whether this is a known version.
    pub fn minor_version(&self) -> u32 {
        *self.base_block.minor_version
    }

    /// Returns the root [`KeyNode`] of this hive.
    pub fn root_key_node(&self) -> Result<KeyNode<&Self, B>> {
        let root_cell_offset = self.base_block.root_cell_offset;
        let cell_range = self.cell_range_from_data_offset(*root_cell_offset)?;
        KeyNode::from_cell_range(self, cell_range)
    }

    /// Performs basic validations on the header of this hive.
    ///
    /// If you read the hive via [`Hive::new`], these validations have already been performed.
    /// This function is only relevant for hives opened via [`Hive::without_validation`].
    pub fn validate(&self) -> Result<()> {
        self.validate_sequence_numbers()?;
        self.validate_version()?;
        self.validate_file_type()?;
        self.validate_file_format()?;
        //self.validate_data_size()?;
        self.validate_clustering_factor()?;
        //self.validate_checksum()?;
        Ok(())
    }
/*
    fn validate_checksum(&self) -> Result<()> {
        let checksum_offset = offset_of!(HiveBaseBlock, checksum);

        // Calculate the XOR-32 checksum of all bytes preceding the checksum field.
        let mut calculated_checksum = 0;
        for dword_bytes in self.base_block.bytes()[..checksum_offset].chunks(mem::size_of::<u32>())
        {
            let dword = u32::from_le_bytes(dword_bytes.try_into().unwrap());
            calculated_checksum ^= dword;
        }

        if calculated_checksum == 0 {
            calculated_checksum += 1;
        } else if calculated_checksum == u32::MAX {
            calculated_checksum -= 1;
        }

        // Compare the calculated checksum with the stored one.
        let checksum = self.base_block.checksum;
        if checksum == calculated_checksum {
            Ok(())
        } else {
            Err(NtHiveError::InvalidChecksum {
                expected: checksum,
                actual: calculated_checksum,
            })
        }
    }
*/
    fn validate_clustering_factor(&self) -> Result<()> {
        let clustering_factor = self.base_block.clustering_factor;
        let expected_clustering_factor = 1;

        if clustering_factor == expected_clustering_factor {
            Ok(())
        } else {
            Err(NtHiveError::UnsupportedClusteringFactor {
                expected: expected_clustering_factor,
                actual: *clustering_factor,
            })
        }
    }
/*
    fn validate_data_size(&self) -> Result<()> {
        let data_size = self.base_block.data_size as usize;
        let expected_alignment = 4096;

        // The data size must be a multiple of 4096 bytes
        if data_size % expected_alignment != 0 {
            return Err(NtHiveError::InvalidSizeFieldAlignment {
                offset: self.offset_of_field(&self.base_block.data_size),
                size: data_size,
                expected_alignment,
            });
        }

        // Does the size go beyond our hive data?
        if data_size > self.data.len() {
            return Err(NtHiveError::InvalidSizeField {
                offset: self.offset_of_field(&self.base_block.data_size),
                expected: data_size,
                actual: self.data.len(),
            });
        }

        Ok(())
    }
*/
    fn validate_file_format(&self) -> Result<()> {
        let file_format = self.base_block.file_format;
        let expected_file_format = HiveFileFormats::Memory as u32;

        if file_format == expected_file_format {
            Ok(())
        } else {
            Err(NtHiveError::UnsupportedFileFormat {
                expected: expected_file_format,
                actual: *file_format,
            })
        }
    }

    fn validate_file_type(&self) -> Result<()> {
        let file_type = self.base_block.file_type;
        let expected_file_type = HiveFileTypes::Primary as u32;

        if file_type == expected_file_type {
            Ok(())
        } else {
            Err(NtHiveError::UnsupportedFileType {
                expected: expected_file_type,
                actual: *file_type,
            })
        }
    }

    fn validate_sequence_numbers(&self) -> Result<()> {
        let primary_sequence_number = self.base_block.primary_sequence_number;
        let secondary_sequence_number = self.base_block.secondary_sequence_number;

        if primary_sequence_number == *secondary_sequence_number {
            Ok(())
        } else {
            Err(NtHiveError::SequenceNumberMismatch {
                primary: *primary_sequence_number,
                secondary: *secondary_sequence_number,
            })
        }
    }

    fn validate_version(&self) -> Result<()> {
        let major = self.major_version();
        let minor = self.minor_version();

        if major == 1 && minor >= HiveMinorVersion::WindowsNT4 as u32 {
            Ok(())
        } else {
            Err(NtHiveError::UnsupportedVersion { major, minor })
        }
    }

    fn enum_subkeys(&self, f: fn (&KeyNode<&Hive<B>, B>) -> Result<()>) -> Result<()> {
        let root_key_node = self.root_key_node()?;
        f(&root_key_node)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::io;

    #[test]
    fn enum_subkeys() {
        let testhive = crate::helpers::tests::testhive_vec();
        let hive = Hive::new(io::Cursor::new(testhive)).unwrap();
        assert!(hive.enum_subkeys(|k| Ok(())).is_ok());
    }
}
