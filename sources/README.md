
Project Name (HMAC- AEAD)

Overview:
This repository contains a reference implementation of a hash-based authenticated encryption construction designed for resource-constrained embedded systems.
The primary goal of this project is to explore and demonstrate an encryption and authentication approach that can be implemented on platforms with limited cryptographic hardware support (e.g., AES-128 only, no dedicated AEAD accelerator), while maintaining clear security boundaries and explicit misuse considerations.

This implementation is intended for research, evaluation, and review purposes.

Design Goals:
- Suitable for embedded and firmware environments
- Minimal external dependencies
- Clear separation between:
    --cryptographic core logic
    --platform-specific glue
    --test and validation code
    --Explicit key and IV separation
    --Simple and auditable control flow

Non-Goals:
This project does not aim to:
    - Replace standardized AEAD schemes such as AES-GCM or ChaCha20-Poly1305
    - Claim formal security proofs or standards compliance
    - Provide side-channel hardened implementations
    - Be production-ready without further review and hardening

Threat Model (High-Level):
The construction assumes
    - An attacker can observe ciphertexts, authentication tags, and associated data
    - An attacker may attempt message forgery or modification
    - Device secret keys are not directly readable by the attacker
    - Physical attacks and side-channel attacks are out of scope
    - Correct IV usage is assumed unless explicitly stated otherwise
    - Detailed threat modeling is documented in the design notes and comments within the code.

Cryptographic Notes:
This implementation is intentionally conservative and avoids relying on undefined behavior or platform-specific optimizations.

Repository Structure
.
├── src/            # Core cryptographic implementation
├── include/        # Public headers / API
├── tests/          # Unit tests and known-answer tests
├── README.md
└── LICENSE


Note: The src/ directory is designed to be portable and reusable in embedded firmware projects with minimal modification.


License

This project is released under the terms of the LICENSE file included in this repository.

Acknowledgements

This work is informed by established cryptographic standards and common embedded security practices, with an emphasis on clarity and auditability.