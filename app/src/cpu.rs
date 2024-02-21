use rayon::prelude::*;
use shared::collatz;
use std::{
    ops::Range,
    time::Instant,
};

pub fn rayon_parallel(src_range: Range<u32>) -> Vec<Option<u32>> {
    let now = Instant::now();
    let res = src_range.into_par_iter().map(collatz).collect::<Vec<_>>();
    eprintln!("Rayon Parallel: {:?}", now.elapsed());
    res
}

pub fn sequential(src_range: Range<u32>) -> Vec<Option<u32>> {
    let now = Instant::now();
    let res = src_range.into_iter().map(collatz).collect::<Vec<_>>();
    eprintln!("Sequential: {:?}", now.elapsed());
    res
}
