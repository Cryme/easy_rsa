WIP

TODO:
 - crate.io
 - badges
 - github ci
 - github deps bot

---

A simple wrapper around [RustCrypto] for easier usage, similar to how you would handle it in Node or Python.

Designed for common use cases, such as when you have keys from an external service, and want to use them without digging into RustCrypto.

#### Supported sign paddings:
- PSS
- PKCS#1 v1.5 _(default)_

#### Supported encryption paddings:
- AOEP
- PKCS#1 v1.5 _(default)_

#### Supported hashers:
 - SHA19
 - SHA256 _(default)_
 - Sha224
 - Sha512_224
 - Sha512_256
 - Sha384
 - Sha512

## Examples

### Sign/Decrypt
```rust
use easy_rsa::{RsaKey};

//Can be PKCS#1/8 PEM, DER Base64 encoded string or DER raw bytes.
let key = r#"-----BEGIN RSA PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAkbULQYDEI/JWm49R
jybBPLnTd2cKKo7NAUySMuA3poiM9L29JRfvJKD7jX+tCD3f9YjQKwNnl0Emaxnl
2mhQ8wIDAQABAkBOkq+wMg0TSWK03nNf28lGwvqrH/CWhI0+jxkjwE+iSJ42Wu09
tqEx4tDQzH6zb2+1iUNfpJO8a33ux2vkRv9ZAiEAx93S9f8vCEmdp7hJumzuPYnW
qPC05DwoLVbkyM2p3UcCIQC6oTo+jlfiItlLXEoJwhI4ojvoVM/RXuJlczwzQQIU
9QIhAIEfin9rEZOlG7mTke5jGbegKZKTkAoz4zEHhl9En41ZAiBFFRcdPs1zLJko
lyHk2Myr4Amy52oBw1CkYvJ+umqN3QIgTCu9ZyAqvm+hwKup8JCwCHwQL6FCt+MJ
/OS7WqqiDRc=
-----END RSA PRIVATE KEY-----"#;

let private_key = RsaKey::import(key).unwrap().into_private().unwrap();

let signed = private_key.sign("payload".as_bytes()).unwrap();
let decrypted = private_key.decrypt("encrypted msg".as_bytes()).unwrap();
```

### Verify/Encrypt
```rust
use easy_rsa::{RsaKey};

//Can be PKCS#1/8 PEM, DER Base64 encoded string or DER raw bytes.
let key = r#"-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJG1C0GAxCPyVpuPUY8mwTy503dnCiqO
zQFMkjLgN6aIjPS9vSUX7ySg+41/rQg93/WI0CsDZ5dBJmsZ5dpoUPMCAwEAAQ==
-----END PUBLIC KEY-----
"#;

let public_key = RsaKey::import(key).unwrap().into_public();
let sign_to_verify = "some_sign";

public_key.verify("payload".as_bytes(), sign_to_verify).unwrap();
let encrypted = public_key.encrypt("encrypted msg".as_bytes()).unwrap();
```
### Options
```rust
use easy_rsa::{RsaKey, Hasher, EncryptionPadding, SignPadding};

//Can be PKCS#1/8 PEM, DER Base64 encoded string or DER raw bytes.
let key = r#"-----BEGIN RSA PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAkbULQYDEI/JWm49R
jybBPLnTd2cKKo7NAUySMuA3poiM9L29JRfvJKD7jX+tCD3f9YjQKwNnl0Emaxnl
2mhQ8wIDAQABAkBOkq+wMg0TSWK03nNf28lGwvqrH/CWhI0+jxkjwE+iSJ42Wu09
tqEx4tDQzH6zb2+1iUNfpJO8a33ux2vkRv9ZAiEAx93S9f8vCEmdp7hJumzuPYnW
qPC05DwoLVbkyM2p3UcCIQC6oTo+jlfiItlLXEoJwhI4ojvoVM/RXuJlczwzQQIU
9QIhAIEfin9rEZOlG7mTke5jGbegKZKTkAoz4zEHhl9En41ZAiBFFRcdPs1zLJko
lyHk2Myr4Amy52oBw1CkYvJ+umqN3QIgTCu9ZyAqvm+hwKup8JCwCHwQL6FCt+MJ
/OS7WqqiDRc=
-----END RSA PRIVATE KEY-----"#;

let rsa_private_key = RsaKey::import(key).unwrap()
   .encryption_padding(EncryptionPadding::OAEP)
   .hasher(Hasher::Sha512)
   .sign_padding(SignPadding::PSS)
   .into_private().unwrap();

let rsa_public_key = rsa_private_key.into_public_key();
```
---
## License

Licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto/
