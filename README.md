# MSecret #

MSecret is both an explicit mechanism for the derivation of keys from
a "master secret", and to the tools in this archive that implement it.

IMPORTANT: This project is currently experimental. You should not yet
rely on the stability of the key derivation mechniams because they are
still subject to change. You have been warned.

This project includes two tools:

*   `ecollect` - Entropy collection/compression program. This tool
    takes a file of a certain size and adds entropy to it from either
    another file (could be a stream like `/dev/random`) or `stdin`.
    This allows you to cherry-pick your entropy sources when
    constructing your master secret: you could take some from
    `/dev/random`, some from your microphone, and some from a
    dedicated hardware entropy source.
*   `msecret` - Tool for deriving various types of keys (both
    symmetric and asymmetric) from a master secret and a key
    identifier string (the key selector). Supports deriving symmetric
    keys, RSA keys, EC keys, and bitcoin keys.

The MSecret mechanism was designed with the following goals:

*   Well-defined, secure derivation of keys from a fixed set of data
    (the "master secret").
*   Allow for a arbitrary size of the master secret (without entropy
    bottlenecks) relying only on cryptographic functions which are
    commonly found in hardware (SHA256). This allows for smartcard
    implementations on existing hardware.

## Future Work ##

*   Derivation of master secret from a passphrase using a
    key-streching algorithm like [PBKDF2][] or [scrypt][].
*   Support for litecoin and Ethereum addresses.
*   Support for Ed25519 curves.
*   Support for generating PGP keys.

[PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
[scrypt]: https://en.wikipedia.org/wiki/Scrypt

## Usage Examples ##

### Generating a Master Secret ###

The following commands will generate a master secret in the file
`secret.bin` with a size of 512 bits (64 bytes):

    # Create master.bin with the appropriate length.
    dd if=/dev/zero of=secret.bin bs=1 count=64

    # Use dmesg for initial entropy.
    dmesg | ./ecollect secret.bin

    # Collect entropy from microphone. (Press CTRL-C to stop)
    arecord | ./ecollect secret.bin

    # Collect entropy from /dev/urandom. (Press CTRL-C to stop)
    ./ecollect secret.bin /dev/urandom

Note that `ecollect` usage is cumulative: it builds on the existing
state of the file and mixes additional entropy into it.

### Deriving Keys from a Master Secret ###

    # Derive the pseudorandom number between 0
    # and 1000 named "X" from the secret.
    ./msecret -i secret.bin -k "X" --format-dec --key-max 1000

    # Same thing, but with the name "Y".
    ./msecret -i secret.bin -k "Y" --format-dec --key-max 1000

	# Derive your strong etrade password. Since users are occasionally
	# required to change their passwords, the index is appended to the
	# key identifier.
    ./msecret -i secret.bin --format-b32 -l 15 -k "com.etrade.myusername.1"

    # Derive a bitcoin address named "Savings-1"
    ./msecret -i secret.bin --bitcoin -k "Savings-1"

    # Print out the private key for the above bitcoin address
    ./msecret -i secret.bin --bitcoin -k "Savings-1" --private

    # Derive a subsecret named "SubSecret-1" that is 64-bytes long,
    # and then use that subsecret to derive a bitcoin address
    # named "BTC-1".
    ./msecret -i secret.bin -o subsecret-1.bin --format-bin
    ./msecret -i subsecret-1.bin --bitcoin -k "BTC-1"

# Appendix #

## Protecting a master secret ##

Protecting the master secret requires special care because compromise
of the master secret leads to the compromise of all derived secrets.

Use of a secret-sharing protocol, like Shamir's scheme, is highly
recommended.

The idea is that we break up the master key into `n` slices, of which
`k` are required to be able to reconstruct the secret. These slices
may be stored on USB drives, smart cards, or even paper. It is
mathmatically proven that any individual with fewer than `k` slices
might as well have zero slices: they will not be able to make any
determination about the value of the secret.

[libgfshare][] is an excellent open-source tool for doing this.

[libgfshare]: http://www.digital-scurf.org/software/libgfshare

