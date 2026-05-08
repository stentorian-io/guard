# Sentinel

Free, open-source macOS supply-chain firewall. Default-deny outbound network
enforcement inside `sentinel <command>` subtrees. Defends developer
laptops against compromised npm / pip / cargo / etc. dependencies.

**Status:** pre-release; Phase 1 (foundations + hook hello-world).

## Quick start

```sh
cargo build --workspace --release
```

(Wrapped-command UX lands in plan 08; e2e smoke test in plan 09.)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

This project is licensed under **MIT OR Apache-2.0**.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
