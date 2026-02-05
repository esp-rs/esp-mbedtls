//! Prints the alignment of various primitive types.

use log::info;

pub fn print_alignments() {
    use core::mem;

    info!("= TYPES ALIGNMENT ==========");
    info!("| Type         | Alignment |");
    info!("|--------------|-----------|");
    info!("| u8           | {:>9} |", mem::align_of::<u8>());
    info!("| u16          | {:>9} |", mem::align_of::<u16>());
    info!("| u32          | {:>9} |", mem::align_of::<u32>());
    info!("| u64          | {:>9} |", mem::align_of::<u64>());
    info!("| u128         | {:>9} |", mem::align_of::<u128>());
    info!("| usize        | {:>9} |", mem::align_of::<usize>());
    info!("| f32          | {:>9} |", mem::align_of::<f32>());
    info!("| f64          | {:>9} |", mem::align_of::<f64>());
    info!("| char         | {:>9} |", mem::align_of::<char>());
    info!("| bool         | {:>9} |", mem::align_of::<bool>());
    info!("| [u8; 16]     | {:>9} |", mem::align_of::<[u8; 16]>());
    info!("| [u16; 16]    | {:>9} |", mem::align_of::<[u16; 16]>());
    info!("| [u32; 16]    | {:>9} |", mem::align_of::<[u32; 16]>());
    info!("| [u64; 16]    | {:>9} |", mem::align_of::<[u64; 16]>());
    info!("| [u128; 16]   | {:>9} |", mem::align_of::<[u128; 16]>());
    info!("| [usize; 16]  | {:>9} |", mem::align_of::<[usize; 16]>());
    info!("| [f32; 16]    | {:>9} |", mem::align_of::<[f32; 16]>());
    info!("| [f64; 16]    | {:>9} |", mem::align_of::<[f64; 16]>());
    info!("| [char; 16]   | {:>9} |", mem::align_of::<[char; 16]>());
    info!("| [bool; 16]   | {:>9} |", mem::align_of::<[bool; 16]>());
    info!("============================");
}
