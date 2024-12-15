# Folded SHA-256 Circuit Benchmarking

This repository contains an implementation of a folded SHA-256 circuit using [Sonobe](https://github.com/privacy-scaling-explorations/sonobe), which performs recursive SHA-256 hashing. The circuit is benchmarked using different sizes of pre-images, and the proving time is measured and logged.

## Installation

To get started, you need to have Rust and Cargo installed. You can install Rust using [rustup](https://rustup.rs/).

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

To run the benchmark you will need to install `gnu-time`:

```sh
brew install gnu-time
```

## Usage

The input size is expressed into powers of 2 (2^input_size):

```sh
cargo run --release --example folded_sha256 -- <input_size>
```
