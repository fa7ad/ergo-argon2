# ergo-argon2
Simple wrapper around the standard implementation of [*Argon2id*](https://github.com/P-H-C/phc-winner-argon2) to make hashing and verifying passwords easier.

## Motivation
According to OWASP, IETF, et al. Argon2 is currently (2023-04-14) the recommended way to hash and store passwords <sup>\[[1][1] [2][2]\]</sup>.
There is a standard implementation of Argon2 in the [crypto package](https://pkg.go.dev/golang.org/x/crypto/argon2#hdr-Argon2id).
But the functions exported from that package are (in my opinion) too low level for general usage, the `bcrypt` implementation in the same package has a much better interface.

This package aims to act as a simpler interface for using Argon2.


[1]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[2]: https://www.ietf.org/archive/id/draft-ietf-kitten-password-storage-07.html
