# Overview

A nice starting point for using rust-gpu to compile to spriv which is then loaded into wgpu.

## Build Requirements

- Use `rustup` to install nightly Rust and include the `llvm-tools-preview`,
  `rustc-dev` and `rust-src` components. These are necessary for the rust-gpu
  spir-v builder to function.

## Running

To run the project, use:

```
cargo run --release -p gpu-fuel-crypto-app
```

You should see something similar to the following output.

```
GPU Compute Shader: 3.382959ms
Rayon Parallel: 24.27075ms
Sequential: 196.673292ms
```

## Code Structure

There are 3 crates in this repo:

- `app` is the main application that builds the Rust shader
  via `SpirvBuilder` and sets up the WGPU pipeline.
- `shader` is the crate containing compute shader entrypoint (`main_cs`).
- `shared` contains code shared between both `app` and `shader`. It declares
  and implements most of the logic. By implementing
  most stuff in a shared crate, I could more easily debug certain functions on
  the CPU in the `app` if necessary.

Thanks to @mitchmindtree for the starting point of this repo structure.
