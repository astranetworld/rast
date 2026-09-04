# N42 Public Chain

[![Rust](https://img.shields.io/badge/rust-1.50%2B-orange.svg)](https://www.rust-lang.org)
[![GitHub Actions](https://github.com/n42blockchain/N42-rs/actions/workflows/devskim.yml/badge.svg)](https://github.com/n42blockchain/N42-rs/actions/workflows/devskim.yml)
[![License](https://img.shields.io/github/license/n42blockchain/N42-rs)](https://github.com/n42blockchain/N42-rs/blob/main/LICENSE)

## Introduction

N42 is a high-performance blockchain platform implemented in Rust, engineered to provide developers with unparalleled autonomy and interoperability across diverse digital ecosystems. Our architecture combines Rust's memory-safe programming paradigm, modular design principles, and innovative consensus mechanisms to establish a robust foundation for next-generation decentralized applications.

Leveraging Rust's security properties and our proprietary sharded domain architecture, N42 delivers enterprise-grade performance without compromising decentralization principles. The platform facilitates seamless cross-domain communication, concurrent transaction processing, and customizable execution environments—all secured by zero-knowledge proofs that ensure data integrity throughout the network.

Whether developing financial applications, interoperable dApps, or custom execution environments, N42 provides the infrastructure necessary to create secure, scalable, and interconnected blockchain solutions for the evolving digital landscape.

## Key Features

- **Decentralized Consensus:** Implements an energy-efficient Proof of Stake (PoS) mechanism that ensures network-wide security and transaction validation integrity.

- **WebAssembly Smart Contracts:** Supports smart contract development through WebAssembly (Wasm), enabling language-agnostic contract implementation with near-native performance.

- **Enterprise-Grade Performance:** Engineered for high transaction throughput with optimized data structures and processing algorithms to support demanding enterprise workloads.
  Measured on the all-Rust seven-node native fleet (2026-09-04): **305,556 transactions per second** in a 30 s window at a 0.526 s block cycle, every node executing every transaction (`docs/NATIVE_FLEET7.md`, "Where it stands today").

- **Cross-Chain Compatibility:** Integrates seamlessly with existing blockchain ecosystems through standardized interoperability protocols and cross-chain messaging.

- **Enhanced Security:** Built with Rust's memory safety guarantees, eliminating entire classes of vulnerabilities including buffer overflows, use-after-free errors, and memory leaks.

- **Developer-Friendly Integration:** Connect to the N42 network with lightweight client libraries and comprehensive SDKs that minimize implementation overhead.

- **Flexible Configuration:**
  - Multi-language development support with idiomatic bindings
  - Ultra-low transaction latency (≤1ms) through architectural optimizations
  - Configurable network bandwidth utilization for efficient resource allocation

- **Unlimited Scalability:** Horizontal scaling through dynamic node addition, complemented by concurrent transaction processing powered by our CRDT-based state model architecture.

## Architecture

### Domains

**Execution Environment:** Each domain functions as an autonomous computational unit hosting one or more applications. Users interact through a dedicated "vault" within each domain where their assets reside. While expenditures are contained within the associated domain, assets can be received from any domain in the network.

**Local Customization:** Domains can be optimized for specific use cases, implementing custom execution environments and smart contract engines (such as EVM or specialized VMs) without compromising the network's security model.

### Validator Network

**State Propagation & Verification:** Validators constitute a decentralized network responsible for propagating state updates, formalized as State Difference Lists (SDL), across domains. These updates are cryptographically verified using zero-knowledge proofs (SNARKs), ensuring compliance with both global protocol rules and domain-specific constraints.

**Consensus without Full Ordering:** Implementing a leaderless, partial-ordering consensus mechanism based on Byzantine Reliable Broadcast (BRB), N42 achieves exceptional throughput and robust Byzantine fault tolerance.

### State Model & Settlement

**CRDT-Based State Management:** The system employs Conflict-Free Replicated Data Types (CRDTs) to facilitate concurrent state updates without reconciliation conflicts, enabling deterministic and efficient merging of distributed state changes.

**Zero-Knowledge Settlement:** Domains generate cryptographic zero-knowledge proofs attesting to the correctness of state transitions. Validators verify these proofs to finalize settlements without accessing the underlying transaction data, preserving privacy while ensuring correctness.

### Digital Asset Ownership

**User Sovereignty:** N42 establishes comprehensive control of digital assets—from user-generated data to creative content—at the individual level. Assets are tokenized (e.g., via NFTs) and managed through smart contracts with cryptographic attestation of ownership.

**Forced Migration:** In cases of domain censorship or operational disruption, users can initiate secure migration of their vaults to alternative domains, preserving self-custody principles and ensuring continuous access to digital assets.

## Use Cases & Ecosystem

- **Decentralized Finance (DeFi):** By integrating traditional finance (TradFi) capabilities with decentralized finance (DeFi) innovations, N42 supports sophisticated financial applications enabling frictionless asset transfers, efficient market mechanisms, and novel value creation models.

- **Interoperable dApps:** The minimalist global state architecture enables atomic composability across domains, facilitating secure, trustless interactions between decentralized applications without reliance on third-party bridging infrastructure.

- **Custom Execution Environments:** Developers can leverage N42's extensible architecture to implement domain-specific execution environments tailored to particular business requirements while benefiting from the network's global security guarantees and interoperability framework.

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (v1.50 or later)
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)
- [Node.js](https://nodejs.org/en/) (optional, for front-end tooling)
- [Wasm-Pack](https://rustwasm.github.io/wasm-pack/installer/) (for smart contract compilation)

### Installation

Clone the repository:

```bash
git clone https://github.com/n42blockchain/N42-rs.git
cd N42-rs
```

Build the project:

```bash
cargo build --release
```

Run a local node:

```bash
cargo run --release -- --dev
```

### Running Tests

Execute the test suite with:

```bash
cargo test
```

## Documentation

N42 provides comprehensive documentation to facilitate developer onboarding and platform adoption:

### Official Documentation

- **Developer Hub**: Access our [official documentation portal](https://docs.n42.world) for in-depth technical guides, tutorials, and API references
- **SDK Documentation**: Explore language-specific SDK documentation for seamless integration with existing applications

### Local Documentation

Generate and access documentation locally:

```bash
# Generate comprehensive documentation with examples and all features
cargo doc --no-deps --all-features --document-private-items

# Open the generated documentation in your browser
cargo doc --open
```

### Learning Resources

- **Tutorials**: Progressive guides for domain creation and application deployment
- **Examples**: Browse our [examples repository](https://github.com/n42blockchain/examples) for reference implementations
- **Architecture Deep Dives**: Technical papers detailing N42's consensus mechanism, CRDT-based state model, and zero-knowledge settlement system

### API Reference

- **RPC API**: Comprehensive reference for programmatic interaction with the N42 network
- **WebSocket API**: Real-time data stream specifications and implementation guidelines
- **CLI Reference**: Detailed guide to command-line interface tools and automation capabilities

### Support Resources

- **Discord Community**: Join our active [Discord community](https://discord.com/invite/n42) for technical discussions and peer support
- **Developer Office Hours**: Scheduled sessions with the core development team for direct assistance
- **GitHub Discussions**: Participate in technical conversations and knowledge sharing
- **FAQ**: Structured answers to frequently asked implementation questions

Visit our [Developer Portal](https://developers.n42.world) for additional resources including sandbox environments, testing frameworks, and testnet token faucets.

## Usage

### Setting Up a Node

To deploy a full node, follow these steps:

1. **Install Rust and Cargo** according to the official documentation.
2. **Build the Project** following the compilation instructions above.
3. **Configure and Run the Node** with appropriate network parameters.

### Interacting with the Blockchain

Interact with the network via the command-line interface (CLI) or integrate programmatically through the JSON-RPC API.

### Deploying Smart Contracts

1. Develop your smart contract in Rust or any Wasm-compatible language.
2. Compile the contract to Wasm using `wasm-pack` or language-specific tooling.
3. Deploy the compiled Wasm binary to the blockchain using the provided deployment utilities.

## Contributing

Contributions are welcome! Please refer to our CONTRIBUTING.md for comprehensive guidelines on participation.

### Contribution Process

We welcome community contributions through the following process:

1. Fork the repository.
2. Create a feature or bugfix branch with descriptive naming.
3. Implement changes with appropriate test coverage.
4. Submit a pull request with detailed documentation of modifications.

Please ensure all contributions adhere to the project's coding standards and pass the continuous integration test suite.

## License

N42 is licensed under the MIT License. See the [LICENSE](LICENSE) file for complete terms.

## Contact

For inquiries or technical support, please contact us via email at [support@n42.world](mailto:support@n42.world) or join our [Discord community](https://discord.gg/n42).

## Acknowledgments

We extend our appreciation to the Rust community and all contributors whose expertise and dedication have advanced this project.
