# TuSK: TPM2-backed virtual FIDO2 security key

TuSK is a virtual FIDO2 security key that is backed by a Trusted Platform Module (TPM2).
It provides a secure and convenient way to authenticate users and devices using WebAuthn/CTAP/FIDO2 standards.

> [!CAUTION]
> When using TuSK, ensure you have a secondary authentication method available, such as a backup security key or biometric authentication.

> [!WARNING]
> This project is in early development and may not be suitable for production use.
> Updates may introduce breaking changes and require re-enrollment of existing keys.

## Features

- TPM2-backed signing keys
- Virtual FIDO2 device emulation using `uhid`
- FIDO2 key implementation by [OpenSK](https://github.com/google/OpenSK)
- User presence verification using `pinentry` popup
- Resident keys support (saved on disk)

## Security

While TPM2 keys provide strong protection against key extraction and are bound to the device (cannot be transferred), they are not immune to all attacks.
Physical attacks on the device or side-channel attacks may still pose risks.

## Limitations

- Pin protection is currently implemented in software and not backed by the TPM.
- General counter is kept in software and not backed by the TPM.
- Attackers with access to the TPM (e.g. physical access or malware) can abuse the TPM for signing any number of webauthn requests.
- User verification is just a popup and therefore insecure.
- FIDO2 key attestation is not yet implemented.
- Resident keys can not be migrated to other devices.

> [!IMPORTANT]
> Updates may resolve some of the limitations mentioned above.
> However, that will also invalidate any existing keys and require re-enrollment.

## Installation

TuSK is written in Rust but uses the libtss library for connecting to the TPM2.
Therefore libclang and libtss needs to be installed for building TuSK.
To build TuSK from a source checkout, run the following command:

```bash
cargo build --release
```

Ensure your user has permission to access the TPM2 device.
Make sure to add your user to the `tss` group or adjust the device permissions accordingly.

To emulate a FIDO2 device, the user also needs permission for uhid.
For example by adding a udev rule like this (replace `USER_GROUP` with your user group):

```bash
echo 'KERNEL=="uhid", GROUP="USER_GROUP", MODE="0660"' > /etc/udev/rules.d/90-uhid.rules
```

## Configuration

TuSK can be configured using a configuration file. The default location for the configuration file is `$HOME/.config/tusk/tusk.cfg`.
The format of the configuration file is INI.
Default configuration options include:

```ini
tcti = device:/dev/tpmrm0
```

Data, like blobs and resident keys, are stored in `$HOME/.local/share/tusk`.

## Run

TuSK will show a confirmation dialog when user presence is required.
Therefore TuSK needs to be run within the user's session to display the dialog properly.
To run TuSK, use the following command:

```bash
cargo run
```

or start the TuSK binary directly:

```bash
./target/release/tusk
```

## Alternatives

- [tpm-fido](https://github.com/psanford/tpm-fido), written in Go
- [PassKeeZ](https://github.com/Zig-Sec/PassKeeZ), written in Zig but not backed by a TPM

## Copyright and License
Copyright 2025 Iwan Timmer.
Distributed under the GNU General Public License v3.0 or later.
For full terms see the [COPYING](COPYING) file
