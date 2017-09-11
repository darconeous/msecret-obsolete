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
    dd if=/dev/zero of=secret.bin bs=1 c=64

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

## Large Key Derivation Function (LKDF) ##

Most key derivation functions (KDFs) are not suitable for use with
large amounts of input keying material. HKDF, for example, creates a
entropy bottle-neck of the hash length between the "extract" and
"expand" stage. PBKDF2 isn't really suitable, either, as it was
designed for a different purpose: key streching.

For example, using HKDF with HMAC-SHA1 to generate a 521-bit ECC key
is not appropriate since the input keying material is compressed into
just 160 bits, even if the input keying material is much larger than
521 bits.

There are a few ways around this. The most obvious method is to use a
hash with a larger output size, like LKDF-SHA512. However, this still
imposes a (much larger) entropy bottleneck when the IKM is larger than
512 bits. More importantly, many smart-cards don't implement SHA512 in
hardware, making the operation prohibitively expensive.

Another alternative is to break up the IKM into `hlen` sized blocks
and apply the KDF multiple times, XORing the results into the final
key. This works, but it is somewhat inefficient. If we are going to go
down this road, we might as well design something that is more
efficient.

As such, I am proposing a new key derivation function specifically
designed for deriving keys when the IKM is larger than `hlen`: the
Large Key Derivation Function, or LKDF.

When the IKM is smaller than the hash length, LKDF is defined to in
terms of HKDF, according to the following:

     LKDF_Extract(salt, IKM, L) =
             HKDF_Expand(HKDF_Extract(salt, IKM), "", L)

When the IKM is larger than the hash length, an entirely different
mechanism is used.

This key derivation function has the following parameters:

*   `IKM` - Input keying material. Arbitrary length.
*   `Salt` - Salt/Nonce. Arbitrary length.
*   `HMAC` - The HMAC algorithm.

The output key material (OKM) is calculated as follows:

    N = ceil(L/HashLen)
    T = T(1) | T(2) | T(3) | ... | T(N)
    OKM = first L octets of T

where:

    T(0) = empty string (zero length)
    T(1) = BlockCalc(1, T(0), salt, IKM)
    T(2) = BlockCalc(2, T(1), salt, IKM)
    T(3) = BlockCalc(3, T(2), salt, IKM)
    ...
    T(n) = BlockCalc(n, T(n-1), salt, IKM)

    BlockCalc(n, prev, salt, IKM)
            = HMAC(salt, prev | n | IKM_Chunk(0) | 0x01)
            ^ HMAC(salt, prev | n | IKM_Chunk(1) | 0x02)
            ^ HMAC(salt, prev | n | IKM_Chunk(2) | 0x03)
            ...
            ^ HMAC(salt, prev | n | IKM_Chunk(m-1) | m)

    m = RoundUp(IKM_Length/HashLen);
