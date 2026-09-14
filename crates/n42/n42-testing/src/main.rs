// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The suite is tests only: `dev` and its helpers use items that exist under
// `cfg(test)`, so a plain build of this binary (`cargo clippy --workspace
// --bins`, the lint workflow) must not compile them.
#[cfg(test)]
mod dev;
#[cfg(test)]
mod snapshot_test_utils;
#[cfg(test)]
mod utils;

#[tokio::main]
async fn main() {
    println!("main starts");
}
