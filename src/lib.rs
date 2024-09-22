use anyhow::anyhow;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use rsa::{Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use std::fmt::Debug;
use strum::{Display, EnumIter};

/// RustCrypto Hashers
///
/// __Sha256__ is default
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, EnumIter, Display)]
pub enum Hasher {
    /**
    🚨 __Warning: Cryptographically Broken__ 🚨

    Use only if you need exactly [Sha1]
    */
    Sha1,

    #[default]
    ///[Sha256]
    Sha256,

    ///[Sha224]
    Sha224,

    ///[Sha512_224]
    Sha512_224,

    ///[Sha512_256]
    Sha512_256,

    ///[Sha384]
    Sha384,

    ///[Sha512]
    Sha512,
}

/// RustCrypto Sign paddings
///
/// __PKCS1v15__ is default
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, EnumIter, Display)]
pub enum SignPadding {
    #[default]
    PKCS1v15,
    PSS,
}

/// RustCrypto Encryption paddings
///
/// __PKCS1v15__ is default
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, EnumIter, Display)]
pub enum EncryptionPadding {
    OAEP,
    #[default]
    PKCS1v15,
}

#[derive(Debug, Copy, Clone, Default)]
enum KeyEncoding {
    /**
    PKCS#1:
    - __Focus__: PKCS#1 is specifically designed for __RSA keys__.
    - __Use__: It defines the standard for encoding __RSA public and private keys__.
    - __Format__: A PKCS#1 private key includes only the RSA-specific information (like modulus, public exponent, private exponent, prime factors, etc.).
    - __Private Key Encoding__: The format is simpler and designed specifically for RSA.
    - __Header__: `-----BEGIN RSA PRIVATE KEY-----`
    */
    Pkcs1,
    /**
    PKCS#8:
    - __Focus__: PKCS#8 is a more generic standard, supporting not only RSA but also other key types like __DSA, ECDSA, etc__.
    - __Use__: It defines a format for private keys that can be used for any public-key algorithm, not just RSA.
    - __Format__: PKCS#8 includes an algorithm identifier and the associated private key information. It can optionally include a cryptographic algorithm identifier (OID) so it can describe keys for various algorithms.
    - __Private Key Encoding__: The format is more versatile and can be applied to a variety of key types, making it more flexible than PKCS#1.
    - __Header__: `-----BEGIN PRIVATE KEY-----`
    */
    #[default]
    Pkcs8,
}

impl KeyEncoding {
    fn try_from_pem_header(value: &str) -> Option<Self> {
        if value.starts_with("-----BEGIN RSA ") {
            Some(Self::Pkcs1)
        } else if value.starts_with("-----BEGIN ") {
            Some(Self::Pkcs8)
        } else {
            None
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
enum RsaKeyType {
    Private,
    #[default]
    Public,
}

impl RsaKeyType {
    fn try_from_pem_header(value: &str) -> Option<Self> {
        if value.ends_with(" PRIVATE KEY-----") {
            Some(Self::Private)
        } else if value.ends_with(" PUBLIC KEY-----") {
            Some(Self::Public)
        } else {
            None
        }
    }
}

/**
Either a private or a public rsa key.
*/
#[derive(Debug, Clone, Eq, PartialEq)]
enum AbstractRsaKey {
    Private(RsaPrivateKey),
    Public(RsaPublicKey),
}

/// # Examples
///
/// ### Sign/Decrypt
///
///```
/// use easy_rsa::{RsaKey};
///
/// let key_bytes = "MII...";
/// let private_key = RsaKey::import(key_bytes).unwrap().into_private().unwrap();
///
/// let signed = private_key.sign("payload".as_bytes()).unwrap();
/// let decrypted = private_key.decrypt("encrypted msg".as_bytes()).unwrap();
///```
///
/// ### Verify/Encrypt
///
/// ```
/// use easy_rsa::{RsaKey};
///
/// let key_bytes = "MII...";
/// let public_key = RsaKey::import(key_bytes).unwrap().into_public();
/// let sign_to_verify = "some_sign";
///
/// public_key.verify("payload".as_bytes(), sign_to_verify).unwrap();
/// let encrypted = public_key.encrypt("encrypted msg".as_bytes()).unwrap();
///```
///
/// ### Options
///
///```
/// use easy_rsa::{RsaKey, Hasher, EncryptionPadding, SignPadding};
///
/// let key_bytes = "MII...";
/// let public_key = RsaKey::import(key_bytes).unwrap().into_public();
///
/// let rsa_private_key = RsaKey::import(key_bytes).unwrap()
///    .encryption_padding(EncryptionPadding::OAEP)
///    .hasher(Hasher::Sha512)
///    .sign_padding(SignPadding::PSS)
///    .into_private().unwrap();
///
/// let rsa_public_key = rsa_private_key.into_public_key();
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RsaKey<T: Clone + Debug + Eq + PartialEq> {
    hasher: Hasher,
    sign_padding: SignPadding,
    encryption_padding: EncryptionPadding,
    key: T,
}

/// Performs _sign_ and _decrypt_ operations.
///
/// Can be converted to public key using [RsaKey<RsaPrivateKey>::into_public_key] method
impl RsaKey<RsaPrivateKey> {
    /// Decrypt the given message using padding (and hash algorithm for OAEP), specified at build step (PKCS#1 v1.5 and SHA256 by default).
    pub fn decrypt(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.encryption_padding {
            EncryptionPadding::OAEP => Ok(self.key.decrypt(self.oaep_enc_schema(), msg)?),
            EncryptionPadding::PKCS1v15 => {
                Ok(self.key.decrypt(self.pkcs1v15_enc_schema(), msg)?)
            }
        }
    }

    /// Sign the given message using padding and hash algorithm, specified at build step _(PKCS#1 v1.5 and SHA256 by default)_.
    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<String> {
        let sign_bytes = match self.sign_padding {
            SignPadding::PKCS1v15 => {
                let (scheme, hash) = self.pkcs1v15_sign_schema_and_hash(msg);

                self.key.sign(scheme, &hash)?
            }
            SignPadding::PSS => {
                let (scheme, hash) = self.pss_sign_schema_and_hash(msg);

                let mut rng = rand::thread_rng();

                self.key.sign_with_rng(&mut rng, scheme, &hash)?
            }
        };

        Ok(BASE64_STANDARD.encode(&sign_bytes))
    }

    /// Converts private RSA key into a public key.
    pub fn into_public_key(self) -> RsaKey<RsaPublicKey> {
        RsaKey {
            hasher: self.hasher,
            sign_padding: self.sign_padding,
            encryption_padding: self.encryption_padding,
            key: self.key.to_public_key(),
        }
    }
}

impl RsaKey<RsaPublicKey> {
    /// Encrypt the given message using padding (and hash algorithm for OAEP), specified at build step (PKCS#1 v1.5 and SHA256 by default).
    pub fn encrypt(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut rng = rand::thread_rng();

        match self.encryption_padding {
            EncryptionPadding::OAEP => {
                Ok(self.key.encrypt(&mut rng, self.oaep_enc_schema(), msg)?)
            }
            EncryptionPadding::PKCS1v15 => {
                Ok(self
                    .key
                    .encrypt(&mut rng, self.pkcs1v15_enc_schema(), msg)?)
            }
        }
    }

    /// Verify the given message using padding and hash algorithm, specified at build step (PKCS#1 v1.5 and SHA256 by default).
    ///
    /// `msg` must be initial message without any modifications.
    ///
    /// If the message is valid `Ok(())` is returned, otherwise an `Err` indicating failure.
    pub fn verify(&self, msg: &[u8], signature: &str) -> anyhow::Result<()> {
        match self.sign_padding {
            SignPadding::PKCS1v15 => {
                let (scheme, hash) = self.pkcs1v15_sign_schema_and_hash(msg);

                Ok(self
                    .key
                    .verify(scheme, &hash, &BASE64_STANDARD.decode(signature)?)?)
            }
            SignPadding::PSS => {
                let (scheme, hash) = self.pss_sign_schema_and_hash(msg);

                Ok(self
                    .key
                    .verify(scheme, &hash, &BASE64_STANDARD.decode(signature)?)?)
            }
        }
    }
}

impl RsaKey<AbstractRsaKey> {
    pub fn import<T: AsRef<[u8]>>(data: T) -> anyhow::Result<RsaKeyBuilder> {
        let Some(k) = RsaKey::try_import(data) else {
            return Err(anyhow!("Unsupported or invalid key data!"));
        };

        Ok(RsaKeyBuilder { key: k })
    }
    fn try_import<T: AsRef<[u8]>>(data: T) -> Option<RsaKey<AbstractRsaKey>> {
        let key_data = data.as_ref();

        if key_data.is_empty() {
            return None;
        }

        if key_data.starts_with(b"----") {
            let Ok(str) = std::str::from_utf8(key_data) else {
                return None;
            };

            return try_from_pem(str);
        }

        if key_data[0] == b'M' {
            let Ok(str) = std::str::from_utf8(key_data) else {
                return try_from_der(key_data, RsaKeyType::default(), KeyEncoding::default());
            };

            return try_from_der_string(str, None, None);
        }

        try_from_der(key_data, RsaKeyType::default(), KeyEncoding::default())
    }

    fn into_private_key(self) -> anyhow::Result<RsaKey<RsaPrivateKey>> {
        let AbstractRsaKey::Private(key) = self.key else {
            return Err(anyhow!("Can't make private key from public key!"));
        };

        Ok(RsaKey {
            hasher: self.hasher,
            sign_padding: self.sign_padding,
            encryption_padding: self.encryption_padding,
            key,
        })
    }

    fn into_public_key(self) -> anyhow::Result<RsaKey<RsaPublicKey>> {
        match self.key {
            AbstractRsaKey::Private(key) => Ok(RsaKey {
                hasher: self.hasher,
                sign_padding: self.sign_padding,
                encryption_padding: self.encryption_padding,
                key: key.to_public_key(),
            }),

            AbstractRsaKey::Public(key) => Ok(RsaKey {
                hasher: self.hasher,
                sign_padding: self.sign_padding,
                encryption_padding: self.encryption_padding,
                key,
            }),
        }
    }
}

impl<T: Clone + Debug + Eq> RsaKey<T> {
    fn oaep_enc_schema(&self) -> Oaep {
        match self.hasher {
            Hasher::Sha1 => Oaep::new::<Sha1>(),
            Hasher::Sha256 => Oaep::new::<Sha256>(),
            Hasher::Sha224 => Oaep::new::<Sha224>(),
            Hasher::Sha512_224 => Oaep::new::<Sha512_224>(),
            Hasher::Sha512_256 => Oaep::new::<Sha512_256>(),
            Hasher::Sha384 => Oaep::new::<Sha384>(),
            Hasher::Sha512 => Oaep::new::<Sha512>(),
        }
    }

    fn pkcs1v15_enc_schema(&self) -> Pkcs1v15Encrypt {
        Pkcs1v15Encrypt
    }

    fn pkcs1v15_sign_schema_and_hash(&self, msg: &[u8]) -> (Pkcs1v15Sign, Vec<u8>) {
        match self.hasher {
            Hasher::Sha256 => {
                let scheme = Pkcs1v15Sign::new::<Sha256>();

                let mut hasher = Sha256::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha1 => {
                let scheme = Pkcs1v15Sign::new::<Sha1>();

                let mut hasher = Sha1::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha224 => {
                let scheme = Pkcs1v15Sign::new::<Sha224>();

                let mut hasher = Sha224::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha512_224 => {
                let scheme = Pkcs1v15Sign::new::<Sha512_224>();

                let mut hasher = Sha512_224::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha512_256 => {
                let scheme = Pkcs1v15Sign::new::<Sha512_256>();

                let mut hasher = Sha512_256::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha384 => {
                let scheme = Pkcs1v15Sign::new::<Sha384>();

                let mut hasher = Sha384::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha512 => {
                let scheme = Pkcs1v15Sign::new::<Sha512>();

                let mut hasher = Sha512::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
        }
    }

    fn pss_sign_schema_and_hash(&self, msg: &[u8]) -> (Pss, Vec<u8>) {
        match self.hasher {
            Hasher::Sha256 => {
                let scheme = Pss::new::<Sha256>();

                let mut hasher = Sha256::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha1 => {
                let scheme = Pss::new::<Sha1>();

                let mut hasher = Sha1::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha224 => {
                let scheme = Pss::new::<Sha224>();

                let mut hasher = Sha224::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha512_224 => {
                let scheme = Pss::new::<Sha512_224>();

                let mut hasher = Sha512_224::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha512_256 => {
                let scheme = Pss::new::<Sha512_256>();

                let mut hasher = Sha512_256::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha384 => {
                let scheme = Pss::new::<Sha384>();

                let mut hasher = Sha384::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
            Hasher::Sha512 => {
                let scheme = Pss::new::<Sha512>();

                let mut hasher = Sha512::new();

                hasher.update(msg);

                (scheme, hasher.finalize().to_vec())
            }
        }
    }
}

struct RsaKeyBuilder {
    key: RsaKey<AbstractRsaKey>,
}

impl RsaKeyBuilder {
    /// [Hasher]
    ///
    /// SHA256 is used by default.
    ///
    /// _(Hashing is not used for PKCS#1 v1.5 enc/dec)_
    pub fn hasher(mut self, v: Hasher) -> Self {
        self.key.hasher = v;

        self
    }

    /// [SignPadding]
    ///
    /// PKCS1v15 is used by default.
    pub fn sign_padding(mut self, v: SignPadding) -> Self {
        self.key.sign_padding = v;

        self
    }

    /// [EncryptionPadding]
    ///
    /// PKCS1v15 is used by default.
    pub fn encryption_padding(mut self, v: EncryptionPadding) -> Self {
        self.key.encryption_padding = v;

        self
    }

    /// Returns public key.
    ///
    /// Always succeed
    pub fn into_public(self) -> RsaKey<RsaPublicKey> {
        self.key.into_public_key().unwrap()
    }

    /// Returns private key or error, if imported key was public
    pub fn into_private(self) -> anyhow::Result<RsaKey<RsaPrivateKey>> {
        self.key.into_private_key()
    }
}

fn try_from_pem(key_data: &str) -> Option<RsaKey<AbstractRsaKey>> {
    let lines: Vec<_> = key_data.trim().lines().collect();

    if lines.len() < 3 {
        return None;
    }

    let header = lines[0].trim();
    let footer = lines.last()?.trim();

    if !header.starts_with("-----BEGIN ") || !footer.starts_with("-----END ") {
        return None;
    }

    let payload: String = lines[1..lines.len() - 1].iter().map(|v| v.trim()).collect();

    try_from_der_string(
        &payload,
        RsaKeyType::try_from_pem_header(header),
        KeyEncoding::try_from_pem_header(footer),
    )
}

fn try_from_der_string(
    der_string: &str,
    declared_key_type: Option<RsaKeyType>,
    declared_encoding: Option<KeyEncoding>,
) -> Option<RsaKey<AbstractRsaKey>> {
    let Ok(der) = BASE64_STANDARD.decode(der_string.as_bytes()) else {
        return None;
    };

    let declared_key_type = declared_key_type.unwrap_or_default();
    let declared_encoding = declared_encoding.unwrap_or_default();

    try_from_der(&der, declared_key_type, declared_encoding)
}

fn try_from_der(
    der: &[u8],
    declared_key_type: RsaKeyType,
    declared_encoding: KeyEncoding,
) -> Option<RsaKey<AbstractRsaKey>> {
    match declared_encoding {
        KeyEncoding::Pkcs1 => {
            if let Some(key) = try_from_der_pkcs1(der, declared_key_type) {
                Some(key)
            } else {
                try_from_der_pkcs8(der, declared_key_type)
            }
        }

        KeyEncoding::Pkcs8 => {
            if let Some(key) = try_from_der_pkcs8(der, declared_key_type) {
                Some(key)
            } else {
                try_from_der_pkcs1(der, declared_key_type)
            }
        }
    }
}

fn try_from_der_pkcs1(der: &[u8], declared_key_type: RsaKeyType) -> Option<RsaKey<AbstractRsaKey>> {
    match declared_key_type {
        RsaKeyType::Private => {
            if let Some(key) = try_private_from_der_pkcs1(der) {
                Some(key)
            } else {
                try_public_from_der_pkcs1(der)
            }
        }

        RsaKeyType::Public => {
            if let Some(key) = try_public_from_der_pkcs1(der) {
                Some(key)
            } else {
                try_private_from_der_pkcs1(der)
            }
        }
    }
}

fn try_public_from_der_pkcs1(der: &[u8]) -> Option<RsaKey<AbstractRsaKey>> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::RsaPublicKey;

    let Ok(key) = RsaPublicKey::from_pkcs1_der(der) else {
        return None;
    };

    Some(RsaKey {
        key: AbstractRsaKey::Public(key),
        sign_padding: SignPadding::default(),
        hasher: Hasher::default(),
        encryption_padding: EncryptionPadding::default(),
    })
}

fn try_private_from_der_pkcs1(der: &[u8]) -> Option<RsaKey<AbstractRsaKey>> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::RsaPrivateKey;

    let Ok(key) = RsaPrivateKey::from_pkcs1_der(der) else {
        return None;
    };

    Some(RsaKey {
        key: AbstractRsaKey::Private(key),
        sign_padding: SignPadding::default(),
        hasher: Hasher::default(),
        encryption_padding: EncryptionPadding::default(),
    })
}

fn try_from_der_pkcs8(der: &[u8], declared_key_type: RsaKeyType) -> Option<RsaKey<AbstractRsaKey>> {
    match declared_key_type {
        RsaKeyType::Private => {
            if let Some(key) = try_private_from_der_pkcs8(der) {
                Some(key)
            } else {
                try_public_from_der_pkcs8(der)
            }
        }

        RsaKeyType::Public => {
            if let Some(key) = try_public_from_der_pkcs8(der) {
                Some(key)
            } else {
                try_private_from_der_pkcs8(der)
            }
        }
    }
}

fn try_public_from_der_pkcs8(der: &[u8]) -> Option<RsaKey<AbstractRsaKey>> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::RsaPublicKey;

    let Ok(key) = RsaPublicKey::from_public_key_der(der) else {
        return None;
    };

    Some(RsaKey {
        key: AbstractRsaKey::Public(key),
        sign_padding: SignPadding::default(),
        hasher: Hasher::default(),
        encryption_padding: EncryptionPadding::default(),
    })
}

fn try_private_from_der_pkcs8(der: &[u8]) -> Option<RsaKey<AbstractRsaKey>> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;

    let Ok(key) = RsaPrivateKey::from_pkcs8_der(der) else {
        return None;
    };

    Some(RsaKey {
        key: AbstractRsaKey::Private(key),
        sign_padding: SignPadding::default(),
        hasher: Hasher::default(),
        encryption_padding: EncryptionPadding::default(),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn test_enc() {
        /// RSA-2048 PKCS#1 private key encoded as PEM
        const RSA_2048_PRIV_PEM: &str = include_str!("../test_examples/pkcs1/rsa2048-priv.pem");

        let mut priv_key = RsaKey::try_import(RSA_2048_PRIV_PEM)
            .unwrap()
            .into_private_key()
            .unwrap();
        let mut pub_key = priv_key.clone().into_public_key();

        for enc_pad in EncryptionPadding::iter() {
            for hasher in Hasher::iter() {
                priv_key.hasher = hasher;
                pub_key.hasher = hasher;

                priv_key.encryption_padding = enc_pad;
                pub_key.encryption_padding = enc_pad;

                let payload = "some random string 127";

                let encoded = pub_key.encrypt(payload.as_bytes()).unwrap();
                let decoded = priv_key.decrypt(&encoded).unwrap();

                assert_eq!(
                    payload.as_bytes(),
                    decoded,
                    "enc failed for pair {} {}",
                    enc_pad,
                    hasher
                );
            }
        }
    }

    #[test]
    fn test_sign() {
        /// RSA-2048 PKCS#1 private key encoded as PEM
        const RSA_2048_PRIV_PEM: &str = include_str!("../test_examples/pkcs1/rsa2048-priv.pem");

        let mut priv_key = RsaKey::try_import(RSA_2048_PRIV_PEM)
            .unwrap()
            .into_private_key()
            .unwrap();
        let mut pub_key = priv_key.clone().into_public_key();

        for sign_pad in SignPadding::iter() {
            for hasher in Hasher::iter() {
                priv_key.hasher = hasher;
                pub_key.hasher = hasher;

                priv_key.sign_padding = sign_pad;
                pub_key.sign_padding = sign_pad;

                let payload = "some random string 128";

                let sign = priv_key
                    .sign(payload.as_bytes())
                    .unwrap_or_else(|_| panic!("sign failed for pair {} {}", sign_pad, hasher));

                pub_key
                    .verify(payload.as_bytes(), &sign)
                    .unwrap_or_else(|_| panic!("verify failed for pair {} {}", sign_pad, hasher));
            }
        }
    }

    #[test]
    fn test_pkcs1_pem_load() {
        /// RSA-2048 PKCS#1 private key encoded as PEM
        const RSA_2048_PRIV_PEM: &str = include_str!("../test_examples/pkcs1/rsa2048-priv.pem");

        /// RSA-4096 PKCS#1 private key encoded as PEM
        const RSA_4096_PRIV_PEM: &str = include_str!("../test_examples/pkcs1/rsa4096-priv.pem");

        /// RSA-2048 PKCS#1 public key encoded as PEM
        const RSA_2048_PUB_PEM: &str = include_str!("../test_examples/pkcs1/rsa2048-pub.pem");

        /// RSA-4096 PKCS#1 public key encoded as PEM
        const RSA_4096_PUB_PEM: &str = include_str!("../test_examples/pkcs1/rsa4096-pub.pem");

        test_pem(RSA_2048_PRIV_PEM);
        test_pem(RSA_4096_PRIV_PEM);
        test_pem(RSA_2048_PUB_PEM);
        test_pem(RSA_4096_PUB_PEM);
    }

    #[test]
    fn test_pkcs1_der_load() {
        /// RSA-2048 PKCS#1 private key encoded as ASN.1 DER.
        ///
        /// Note: this key is extracted from the corresponding `rsa2048-priv.der`
        /// example key in the `pkcs8` crate.
        const RSA_2048_PRIV_DER: &[u8] = include_bytes!("../test_examples/pkcs1/rsa2048-priv.der");

        /// RSA-4096 PKCS#1 private key encoded as ASN.1 DER
        const RSA_4096_PRIV_DER: &[u8] = include_bytes!("../test_examples/pkcs1/rsa4096-priv.der");

        /// RSA-2048 PKCS#1 public key encoded as ASN.1 DER.
        ///
        /// Note: this key is extracted from the corresponding `rsa2048-priv.der`
        /// example key in the `pkcs8` crate.
        const RSA_2048_PUB_DER: &[u8] = include_bytes!("../test_examples/pkcs1/rsa2048-pub.der");

        /// RSA-4096 PKCS#1 public key encoded as ASN.1 DER
        const RSA_4096_PUB_DER: &[u8] = include_bytes!("../test_examples/pkcs1/rsa4096-pub.der");

        RsaKey::try_import(RSA_2048_PRIV_DER).unwrap();
        RsaKey::try_import(RSA_4096_PRIV_DER).unwrap();
        RsaKey::try_import(RSA_2048_PUB_DER).unwrap();
        RsaKey::try_import(RSA_4096_PUB_DER).unwrap();

        RsaKey::try_import(BASE64_STANDARD.encode(RSA_2048_PRIV_DER)).unwrap();
        RsaKey::try_import(BASE64_STANDARD.encode(RSA_4096_PRIV_DER)).unwrap();
        RsaKey::try_import(BASE64_STANDARD.encode(RSA_2048_PUB_DER)).unwrap();
        RsaKey::try_import(BASE64_STANDARD.encode(RSA_4096_PUB_DER)).unwrap();
    }

    #[test]
    fn test_pkcs8_pem_load() {
        /// RSA-2048 PKCS#1 private key encoded as PEM
        const RSA_2048_PRIV_PEM: &str = include_str!("../test_examples/pkcs1/rsa2048-priv.pem");

        /// RSA-4096 PKCS#1 private key encoded as PEM
        const RSA_4096_PRIV_PEM: &str = include_str!("../test_examples/pkcs1/rsa4096-priv.pem");

        /// RSA-2048 PKCS#1 public key encoded as PEM
        const RSA_2048_PUB_PEM: &str = include_str!("../test_examples/pkcs1/rsa2048-pub.pem");

        /// RSA-4096 PKCS#1 public key encoded as PEM
        const RSA_4096_PUB_PEM: &str = include_str!("../test_examples/pkcs1/rsa4096-pub.pem");

        test_pem(RSA_2048_PRIV_PEM);
        test_pem(RSA_4096_PRIV_PEM);
        test_pem(RSA_2048_PUB_PEM);
        test_pem(RSA_4096_PUB_PEM);
    }

    #[test]
    fn test_pkcs8_der_load() {
        /// RSA-2048 PKCS#1 private key encoded as ASN.1 DER.
        ///
        /// Note: this key is extracted from the corresponding `rsa2048-priv.der`
        /// example key in the `pkcs8` crate.
        const RSA_2048_PRIV_DER: &[u8] = include_bytes!("../test_examples/pkcs1/rsa2048-priv.der");

        /// RSA-4096 PKCS#1 private key encoded as ASN.1 DER
        const RSA_4096_PRIV_DER: &[u8] = include_bytes!("../test_examples/pkcs1/rsa4096-priv.der");

        /// RSA-2048 PKCS#1 public key encoded as ASN.1 DER.
        ///
        /// Note: this key is extracted from the corresponding `rsa2048-priv.der`
        /// example key in the `pkcs8` crate.
        const RSA_2048_PUB_DER: &[u8] = include_bytes!("../test_examples/pkcs1/rsa2048-pub.der");

        /// RSA-4096 PKCS#1 public key encoded as ASN.1 DER
        const RSA_4096_PUB_DER: &[u8] = include_bytes!("../test_examples/pkcs1/rsa4096-pub.der");

        RsaKey::try_import(RSA_2048_PRIV_DER).unwrap();
        RsaKey::try_import(RSA_4096_PRIV_DER).unwrap();
        RsaKey::try_import(RSA_2048_PUB_DER).unwrap();
        RsaKey::try_import(RSA_4096_PUB_DER).unwrap();

        RsaKey::try_import(BASE64_STANDARD.encode(RSA_2048_PRIV_DER)).unwrap();
        RsaKey::try_import(BASE64_STANDARD.encode(RSA_4096_PRIV_DER)).unwrap();
        RsaKey::try_import(BASE64_STANDARD.encode(RSA_2048_PUB_DER)).unwrap();
        RsaKey::try_import(BASE64_STANDARD.encode(RSA_4096_PUB_DER)).unwrap();
    }

    fn test_pem(pem: &str) {
        RsaKey::try_import(pem).unwrap();
        let (c1, c2, c3) = corrupt_pem_header(pem);
        RsaKey::try_import(c1).unwrap();
        RsaKey::try_import(c2).unwrap();
        RsaKey::try_import(c3).unwrap();
    }

    fn corrupt_pem_header(pem: &str) -> (String, String, String) {
        if pem.starts_with("-----BEGIN RSA PUBLIC KEY-----") {
            (
                pem.replace(
                    "-----BEGIN RSA PUBLIC KEY-----",
                    "-----BEGIN PRIVATE KEY-----",
                ),
                pem.replace(
                    "-----BEGIN RSA PUBLIC KEY-----",
                    "-----BEGIN RSA PRIVATE KEY-----",
                ),
                pem.replace(
                    "-----BEGIN RSA PUBLIC KEY-----",
                    "-----BEGIN PUBLIC KEY-----",
                ),
            )
        } else if pem.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
            (
                pem.replace(
                    "-----BEGIN RSA PRIVATE KEY-----",
                    "-----BEGIN PUBLIC KEY-----",
                ),
                pem.replace(
                    "-----BEGIN RSA PRIVATE KEY-----",
                    "-----BEGIN RSA PUBLIC KEY-----",
                ),
                pem.replace(
                    "-----BEGIN RSA PRIVATE KEY-----",
                    "-----BEGIN PRIVATE KEY-----",
                ),
            )
        } else if pem.starts_with("-----BEGIN PRIVATE KEY-----") {
            (
                pem.replace("-----BEGIN PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----"),
                pem.replace(
                    "-----BEGIN PRIVATE KEY-----",
                    "-----BEGIN RSA PUBLIC KEY-----",
                ),
                pem.replace(
                    "-----BEGIN PRIVATE KEY-----",
                    "-----BEGIN RSA PRIVATE KEY-----",
                ),
            )
        } else if pem.starts_with("-----BEGIN PUBLIC KEY-----") {
            (
                pem.replace("-----BEGIN PUBLIC KEY-----", "-----BEGIN PRIVATE KEY-----"),
                pem.replace(
                    "-----BEGIN PUBLIC KEY-----",
                    "-----BEGIN RSA PUBLIC KEY-----",
                ),
                pem.replace(
                    "-----BEGIN PUBLIC KEY-----",
                    "-----BEGIN RSA PRIVATE KEY-----",
                ),
            )
        } else {
            panic!("incorrect PEM file!")
        }
    }
}
