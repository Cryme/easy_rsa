WIP

TODO:
 - crate.io
 - badges

---

A simple wrapper around [RustCrypto] for easier usage, similar to how you would handle it in Node or Python.

Designed for common use cases, such as when you have keys from an external service, and want to use them without digging into RustCrypto.

#### Supported signing algorithms:
- PSS
- PKCS#1 v1.5 _(default)_

#### Supported encrypting algorithms:
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

let key_bytes = "MII...";
let private_key = RsaKey::import(key_bytes).unwrap().into_private().unwrap();

let signed = private_key.sign("payload".as_bytes()).unwrap();
let decrypted = private_key.decrypt("encrypted msg".as_bytes()).unwrap();
```

### Verify/Encrypt
```rust
use easy_rsa::{RsaKey};

let key_bytes = "MII...";
let public_key = RsaKey::import(key_bytes).unwrap().into_public();
let sign_to_verify = "some_sign";

public_key.verify("payload".as_bytes(), sign_to_verify).unwrap();
let encrypted = public_key.encrypt("encrypted msg".as_bytes()).unwrap();
```
### Options
```rust
use easy_rsa::{RsaKey, Hasher, EncryptionPadding, SignPadding};

let key_bytes = "MII...";
let public_key = RsaKey::import(key_bytes).unwrap().into_public();

let rsa_private_key = RsaKey::import(key_bytes).unwrap()
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