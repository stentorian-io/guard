# Windows Support

Windows is not planned for Stentorian Guard.

## Status

| Area | Status |
| --- | --- |
| Runtime support | Not planned |
| Enforcement implementation | None |
| Hardware-backed signing support | Unsupported |

No Windows CPU architecture is supported.

## Enforcement Model

Stentorian Guard's current architecture depends on user-space process wrapping
and library injection. macOS has `DYLD_INSERT_LIBRARIES`; Linux has initial
`LD_PRELOAD` support for dynamically linked wrapped processes.

Windows does not provide an equivalent open, general-purpose mechanism that
matches this project's security and distribution constraints. Meaningful
network enforcement for arbitrary child processes would push the project toward
kernel-mode drivers, enterprise network filtering APIs, or privileged security
products.

Those approaches have different signing, distribution, testing, and operational
requirements from this project.

## Support Decisions

Windows support is not planned because a credible implementation would be a
different product architecture, not a small platform port.

The project avoids shipping a weak Windows mode that looks like enforcement but
can be bypassed by ordinary process behavior. A convenient fallback that weakens
default-deny enforcement would be misleading for users and inconsistent with the
security model.

## What Would Change Support

Windows support would need a separate design that explains the enforcement
boundary, driver or filtering requirements, signing and distribution model,
identity model, install and uninstall safety, and bypass behavior.

Until that design exists, Windows remains out of scope.
