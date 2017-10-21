# Large Key Derivation Function (LKDF) #

Most key derivation functions (KDFs) cannot achieve a strength larger
than 2^**hlen**, where **hlen** is the output length of the hash
function. HKDF, for example, creates a entropy bottle-neck of the hash
length between the "extract" and "expand" stage. PBKDF2 isn't really
suitable, either, as it was designed for a different purpose: key
streching.

Since computation will only become less expensive in the future, and
the security of the SHA family is also somewhat unclear over long (50+
years) periods of time, the use of a KDF that does not impose such a
strength limit seems desirable for certain applications.

The 2^**hlen** strength limitation was called out specifically as a
weakness of many KDFs in *Adams, et al*[2]. The HKDF paper
(*Krawczyk*[1]) responded to such criticism on page 21:

> While we agree with this fact, we do not agree with the criticism.
> If a work factor of 2^k is considered feasible (say 2^160) then one
> should simply use a stronger hash function. Counting on a 2^k-secure
> hash function to provide more than 2^k security, even on a
> high-entropy source, seems as unnecessary as unrealistic.

However, there are tangable benefits from avoiding the use of larger
hash functions like SHA-512: Specifically, it is not currently
supported by many secure elements, whereas most support SHA-256. In
such cases, the use of SHA-512 in software is prohibitively expensive.

Another alternative is to break up the IKM into `hlen` sized blocks
and apply the KDF multiple times, XORing the results into the final
key. This works, but it is somewhat inefficient. If we are going to go
down this road, we might as well design something that is more
efficient.

As such, I am proposing a new key derivation function specifically
designed for deriving keys when the IKM is larger than `hlen`: the
Large Key Derivation Function, or LKDF.

However, it is worth noting that if the use of SHA-512 is not ruled
out by your application and a strength of 2^512 is adequate for your
needs (seems like it should be) then you should go with HKDF based
on SHA-512, since its implementation is much easier to review and
implement.

## Implementation Details ##

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

### References ###

*   [1] Hugo Krawczyk, "Cryptographic Extraction and Key Derivation:
    The HKDF Scheme", Crypto’2010, LNCS 6223,
    <https://eprint.iacr.org/2010/264.pdf>
*   [2] Carlisle Adams, Guenther Kramer, Serge Mister and Robert
    Zuccherato, “On The Security of Key Derivation Functions”,
    ISC’2004, LNCS 3225, 134-145.
