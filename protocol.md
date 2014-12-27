# Master Secret Protocol #

This document describes the protocol and procedures for safely using a
single master secret to securely derive additional secrets.

The master secret in this protocol can contain an arbitrary amount of
entropy. This should be no less than 4096 bits (512 bytes) of pure
entropy.

With such a large secret, we can't just use the normal key derivation
functions (like HKDF or PBKDF2) alone: using such procedures naively
will end up truncating the total entropy of the pool. We can use
established key derivation functions in the process of constructing
these keys, but we must do so carefully.

## Description ##

Master secret is 4096 bits (512 bytes) of entropy. This master secret
shall be compressed from no less than 10 megabits of entropy.

 *  MS (Master Secret) : 4096 (512 bytes) of entropy
 *  DSID (Derived Secret Identifier) : Arbitrary UTF8-encoded string
    identifying a derived secret.
 *  SK (Secret Key) : 256-bit (32-byte) key derived from the SID.

## Secret Extraction Procedure ##

The SK is derived from the SID using 100,000 rounds of
PBKDF2(HMAC-SHA256).

    SK = PBKDF2(
        HASH,
        0,
        100000
        256
    )

Secret Extraction:

    MS_EXTRACT(MS, DSID, MOD)

Where:

 *  `MS`: Master Secret
 *  `DSID`: Derived Secret Identifier
 *  `MOD`: Largest value (inclusive)

So, to extract a 31-bit key with the identifier "My Secret Key":

    MS_EXTRACT(MS, "My Secret Key", 0x7FFFFFFF)

The procedure works as follows.

Values:

 *  `MS`: Master Secret
 *  `DSID`: Derived Secret Identifier
 *  `MOD`: Largest value (inclusive)
 *  `HKDF()`: HKDF algorithm. (HMAC-SHA256 suggested)
 *  `hlen`: the hash-size of `HMAC()`.
 *  `BITS(x)`: Number of bits required to represent `x`
 *  `NONCE`: NONCE value (starts at zero)

    1.  Extract a secret `BITS(MOD)` large.
    2.  If the secret is larger than MOD or equal to zero, increment
        NONCE and start over. Otherwise, return derived key.

To extract the secret, we break up `MS` into `n` blocks, each `HS`
long. For each block, the following is calculated:

    SubKey(n) = HKDF(NONCE, BLK(MS, hlen, n), DSID, BITS(MOD))

The candidate key is calculated as the XOR "sum" of this function
applied to all blocks of MS:

    CandidateKey = SubKey(0) XOR SubKey(1) XOR ... SubKey(n)

This construction was selected to avoid reducing the effective
strength of the master key to that of `hlen/2`.

Is pseudocode:

    DerivedKey = 0;
    Nonce = 0;
    do {
        DerivedKey = 0;
        for(i = 0; i < n; i++) {
            DerivedKey = DerivedKey XOR SubKey(i, nonce);
        }
        Nonce = Nonce + 1;
    } while(DerivedKey > MOD);

For cases where `MOD` is equal to `2^n-1` where `n` is a multiple of 8,
a much more simplified version may be used:

    DerivedKey = 0;
    for(i = 0; i < n; i++) {
        DerivedKey = DerivedKey XOR SubKey(i, 0);
    }

## Protecting the master secret ##

Protecting the master secret requires special care because compromise
of the master secret leads to the compromise of all derived secrets.

Use of a secret-sharing protocol, like Shamir's scheme, is highly
recommended.

Here I will describe a mechanism that uses Shamir's scheme to protect
the master secret and uses secure elements to protect the master
secret and derived secrets at every stage.

The idea is that we break up the master key into `n` slices, of which
`k` are required to be able to reconstruct the secret. These slices
may be stored on USB drives, smart cards, or even paper.

However, care must be taken to ensure that the machine which is used
to combine the slices to generate new derived keys from the master
secret is not compromised.

Here, I describe a mechanism to secure the process by storing the
slices on secure elements. To derive a secret, you collect the secure
elements and pick one to be the "master". The master then communicates
with the other secure elements, mutually authenticates, and then
exchanges the secret slices. Once `k` slices have been obtained by the
master, it can then be used to derive new keys. Under no circumstances
does the master secret ever leave the secure element.

Mutual authentication is achieved using Blom's scheme, which is the
algorithm used by HDCP copy protection. This mechanism is secure to
use in this circumstance as long the value of `k_blom` is greater than
or equal to `k_shamir`. In practice, there is little reason for these
values to not be exactly equal.

This mechanism provides for both mutual authentication and encryption
between provisioned devices, without relying on asymmetric-key
cryptography.

The specific implementation of shamir secret sharing is identical to
that used for `libgfshare`, except that the polynomial coefficients
are calculated deterministically using DSID `internal:shamir?v=V`,
where `V` is the current "protection version" (described below).

If some shares are compromised, the remaining shares can be collected
and re-calculated to make the compromised shares useless. This is
done by incrementing the "protection version" and re-commissioning
all cards.

This is how the mechanism works.

The secure element has the following methods:

 *  Reconstruct\_Challenge(Data) - Returns Challenge
 *  Reconstruct\_Respond(Challenge) - Returns (EncryptedResponse)
 *  DeriveKey(DSID, MOD) - returns a random number identified by DSID
    that is less than or equal to MOD.
 *  GetStatus() - Returns (SlicesNeeded, SlicesObtained,
    SlicesContained, SliceIDsOfContainedSlices)
 *  Initialize(n, k, entropy) - Initialize a new master secret, mixing
    `entropy` with additional entropy generated by the internal TRNG;
    with a maximum of `n` issued shares, and `k` shares needed to
    reconstruct the key.
 *  Provision(n) - Generate provisioning info for a secure element
    with `n` shares.
 *  Inject(ProvisionData) - Initialize app with the given provisioning
    data.

`Reconstruct_Challenge()` is initially called with an empty parameter.
The resulting data is then passed to `Reconstruct_Respond()`. The
resulting data is then in turn passed back to
`Reconstruct_Challenge()`. This back-and-forth is continued until an
error is generated or the exchange has completed (indicated by a
successful return code).

Once enough slices are obtained, the master secret will become
unlocked and new secrets may be derived. Once the secure element is
reset, it will once again become locked.

IMPORTANT: Due to physical limitations in the design of some secure
elements, it may not be possible during reconstruction to store all of
the slices from other secure elements in non-volatile RAM. In such a
case, it is imperative that the application be reset and re-selected
before disconnecting the secure element. Failure to do so could render
the master secret recoverable by a dedicated adversary with physical
access to the secure element.

Any secure element in the group may be used to reconstruct the master
secret (with the help of other secure elements)

The matrix generated for Blom's scheme shall use secrets generated
from the master secret, using the following DSID `internal:blom?v=V;i=I;j=J`, where
`I` and `J` are decimal indexes of the matrix and `V` is the protection version. MOD is set to the same
`p` as NIST curve P-256: `2^256 - 2^224 + 2^192 + 2^96 - 1`. The
entire matrix need not be stored in memory, but may be used as needed.

Note that any DSID that is prefixed with `internal:` is only allowed
to be calculated internally within the secure element. Any attempts
to fetch the value associated with such a DSID from an external
interface MUST fail.

When a new card is being provisioned, a new public/private Blom
key-pair is generated, along with `n` slices. This data is optionally
asymmetrically encrypted for import into the card being provisioned.

The following information is included with each "slice":

 *  Slice number. 16-bit.
 *  Slice data. Size of master key.
 *  CRC or other hash, verifying that the key isn't corrupted.

When a card is regenerating the master secret, it performs mutual
authentication with each card before slice data is exchanged. This
process is stateful on both sides. The process looks like this:

We have two cards: "Master" and "Slave".

 *  Master generates the "initial challenge", which contains the
    public key and a randomly-generated `ChallengeM`.
 *  The Slave uses Master's public key to generate the shared key
    using Blom's scheme. This value is hashed using HMAC-SHA256 using
    the challenge as the key and the shared key as the message. This
    value is then used to encrypt `ChallengeM`. The "initial response"
    contains the public key of the slaveand the encrypted
    `ChallengeS`.
 *  The master






## Proposed parameters ##

* `n` (Number of shares) = 13
* `k` (Shares needed) = 5
* `p_blom` = `2^256 - 2^224 + 2^192 + 2^96 - 1` (256-bits)
* `mslen` = 4096 bits (512 bytes)
* `HMAC` = HMAC-SHA256
* `hlen` = 256

Shares are numbered 0 thru 31.

### Initial Share Distribution ###

Eight initial cards:

* Card 0: 3/5, 00 01 02 (~1600 bytes)
* Card 1: 2/5, 03 04 (~1100 bytes)
* Card 2: 2/5, 05 06 (~1100 bytes)
* Card 3: 2/5, 07 08 (~1100 bytes)
* Card 4: 1/5, 09 (~600 bytes)
* Card 5: 1/5, 10 (~600 bytes)
* Card 6: 1/5, 11 (~600 bytes)
* Card 7: 1/5, 12 (~600 bytes)









-----------------------


Most key derivation functions (KDFs) are not suitable for use with large
amounts of input keying material. HKDF, for example, creates a entropy
bottle-neck of the hash length between the "extract" and "expand" stage.
PBKDF2 isn't really suitable, either, as it was designed for a distinct
purpose.

For example, using HKDF with HMAC-SHA256 to generate a 521-bit ECC key
is not appropriate since the input keying material is compressed into
just 256 bits, even if the input keying material is much larger than 521 bits.

One alternative is to break up the IKM into `hlen` sized blocks and apply
the KDF multiple times, XORing the results into the final key. This approach
is particularly unsuited to devices with limited resources.

As such, I am proposing a new key derivation function specifically designed
for deriving keys when the IKM is larger than `hlen`.

This key derivation function has the following parameters:

* `IKM` - Input keying material. Arbitrary length.
* `Info` - Data identifying the key being derived. Arbitrary length.
* `Salt` - Salt/Nonce. Arbitrary length.
* `HMAC` - The HMAC algorithm.

The output OKM is calculated as follows:

    N = ceil(L/HashLen)
    T = T(1) | T(2) | T(3) | ... | T(N)
    OKM = first L octets of T

where:

    T(0) = empty string (zero length)
    T(1) = HMAC-Hash(Salt | info | 0x00000001,   T(0) | IKM)
    T(2) = HMAC-Hash(Salt | info | 0x00000002,   T(1) | IKM)
    T(3) = HMAC-Hash(Salt | info | 0x00000003,   T(2) | IKM)
    ...
    T(n) = HMAC-Hash(Salt | info |          n, T(n-1) | IKM)

Where n is represented with 4 octets, for a maximum generated key length of `hlen*(2^32-1)` bytes.
