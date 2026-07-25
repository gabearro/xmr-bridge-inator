use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, SeqAccess, Visitor},
};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey as EncryptionPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::committee::{Committee, CommitteeError, PartyId, SessionId};

const ENVELOPE_VERSION: u16 = 1;
/// Global allocation bound applied before any signed-envelope payload is materialized.
///
/// Application protocols impose tighter limits after decoding. This outer cap prevents a
/// malicious postcard length prefix from reserving attacker-chosen memory first.
pub const MAX_SIGNED_ENVELOPE_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = MAX_SIGNED_ENVELOPE_PAYLOAD_BYTES + 16;

/// Long-lived transport identity. The key material is never serialized through Serde.
pub struct Identity {
    party: PartyId,
    encryption_epoch: u64,
    signing: SigningKey,
    encryption: StaticSecret,
}

/// Non-serializable authority to advertise one X25519 key after durable readback.
///
/// Generating an [`EpochEncryptionSecret`] or constructing an [`Identity`] is deliberately
/// insufficient to enter a key-rotation transcript. The storage layer creates this capability only
/// after atomically persisting and authenticating the exact secret again. Keeping the wrapper free
/// of `Serialize`/`Deserialize` prevents a wire message or restored reducer snapshot from
/// manufacturing possession.
pub struct PersistedKeyAdvertisementIdentity {
    identity: Identity,
    durable_record_digest: [u8; 32],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").field("party", &self.party).finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PersistedKeyAdvertisementIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PersistedKeyAdvertisementIdentity")
            .field("party", &self.identity.party)
            .field("epoch", &self.identity.encryption_epoch)
            .field("public_key", &self.identity.encryption_public_key())
            .field("durable_record_digest", &self.durable_record_digest)
            .finish_non_exhaustive()
    }
}

/// Decrypted X25519 key material prepared for authenticated persistence.
///
/// This is the only API by which an [`Identity`] exports its encryption secret. The secret bytes
/// are erased when the value is dropped and are deliberately omitted from `Debug`. The public
/// metadata lets durable storage bind the ciphertext to the exact party and epoch, and lets a
/// restart validate that the decrypted secret still derives the certified public key before it is
/// used.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct EpochEncryptionSecret {
    #[zeroize(skip)]
    party: PartyId,
    #[zeroize(skip)]
    epoch: u64,
    #[zeroize(skip)]
    public_key: [u8; 32],
    secret: [u8; 32],
}

impl EpochEncryptionSecret {
    /// Generate an independently random X25519 secret for one explicit epoch.
    ///
    /// The long-lived Ed25519 signing seed is intentionally not an input. Callers must persist this
    /// zeroizing value and authenticate the durable readback before constructing a
    /// [`PersistedKeyAdvertisementIdentity`].
    pub fn generate<R: RngCore + CryptoRng>(
        party: PartyId,
        epoch: u64,
        rng: &mut R,
    ) -> Result<Self, IdentityError> {
        let encryption = StaticSecret::random_from_rng(&mut *rng);
        let public_key = EncryptionPublicKey::from(&encryption).to_bytes();
        if public_key == [0_u8; 32] {
            return Err(IdentityError::InvalidGeneratedEncryptionKey);
        }
        Ok(Self { party, epoch, public_key, secret: encryption.to_bytes() })
    }

    /// Reconstruct a zeroizing persistence value from decrypted storage bytes.
    ///
    /// `secret` is accepted only in a zeroizing container so storage code cannot accidentally
    /// leave the plaintext key in an ordinary long-lived allocation. The advertised public key is
    /// checked against the X25519 public key derived from the secret.
    pub fn from_decrypted(
        party: PartyId,
        epoch: u64,
        expected_public_key: [u8; 32],
        secret: Zeroizing<[u8; 32]>,
    ) -> Result<Self, IdentityError> {
        let encryption = StaticSecret::from(*secret);
        let public_key = EncryptionPublicKey::from(&encryption).to_bytes();
        if public_key != expected_public_key {
            return Err(IdentityError::WrongEncryptionPublicKey);
        }
        Ok(Self { party, epoch, public_key, secret: *secret })
    }

    #[must_use]
    pub const fn party(&self) -> PartyId {
        self.party
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Borrow the raw key only for immediate authenticated encryption or identity reconstruction.
    /// Long-lived copies must themselves use a zeroizing container.
    #[must_use]
    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl std::fmt::Debug for EpochEncryptionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochEncryptionSecret")
            .field("party", &self.party)
            .field("epoch", &self.epoch)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// Ciphertext for an authenticated point-to-point protocol payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub nonce: [u8; 24],
    #[serde(deserialize_with = "deserialize_encrypted_payload_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Signed, replay-protected transport envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub version: u16,
    pub committee: [u8; 32],
    pub epoch: u64,
    pub session: SessionId,
    pub from: PartyId,
    /// `None` means a portable broadcast envelope. The QUIC relay still sends one authenticated
    /// point-to-point frame per peer.
    pub to: Option<PartyId>,
    pub sequence: u64,
    #[serde(deserialize_with = "deserialize_signed_envelope_payload")]
    pub payload: Vec<u8>,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct UnsignedEnvelope<'a> {
    version: u16,
    committee: [u8; 32],
    epoch: u64,
    session: SessionId,
    from: PartyId,
    to: Option<PartyId>,
    sequence: u64,
    payload: &'a [u8],
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IdentityError {
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("identity party does not match the sender")]
    WrongSender,
    #[error("envelope protocol version is unsupported")]
    UnsupportedVersion,
    #[error("envelope is for another epoch or committee")]
    WrongCommittee,
    #[error("envelope is addressed to another party")]
    WrongRecipient,
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid envelope signature")]
    InvalidSignature,
    #[error("X25519 produced the all-zero shared secret")]
    InvalidSharedSecret,
    #[error("payload encryption failed")]
    Encryption,
    #[error("payload authentication or decryption failed")]
    Decryption,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("message serialization failed")]
    Serialization,
    #[error("transport payload exceeds the allocation bound")]
    PayloadTooLarge,
    #[error("target encryption epoch must immediately follow the current epoch")]
    WrongSuccessorEpoch,
    #[error("persisted encryption secret belongs to another party")]
    WrongEncryptionParty,
    #[error("persisted encryption secret belongs to another epoch")]
    WrongEncryptionEpoch,
    #[error("stable signing seed does not derive the expected Ed25519 public key")]
    WrongSigningPublicKey,
    #[error("X25519 secret does not derive the expected public key")]
    WrongEncryptionPublicKey,
    #[error("fresh X25519 generation reproduced the current public key")]
    EncryptionKeyNotRotated,
    #[error("fresh X25519 generation produced an invalid public key")]
    InvalidGeneratedEncryptionKey,
    #[error("durable X25519 readback binding must be nonzero")]
    InvalidPersistenceBinding,
}

impl Identity {
    /// Derive only the stable Ed25519 public identity from its long-lived seed.
    ///
    /// There is intentionally no corresponding API which derives X25519 material from this seed.
    pub fn signing_public_key_from_seed(
        signing_seed: &[u8; 32],
    ) -> Result<[u8; 32], IdentityError> {
        Ok(derive_signing_key(signing_seed)?.verifying_key().to_bytes())
    }

    /// Construct deterministic unit-test material from explicitly separate Ed25519 and X25519
    /// inputs. This helper is absent from production builds and intentionally has no one-seed
    /// variant.
    #[cfg(test)]
    pub(crate) fn from_test_secrets(
        party: PartyId,
        epoch: u64,
        signing_seed: &[u8; 32],
        x25519_secret: [u8; 32],
    ) -> Result<Self, IdentityError> {
        let expected_encryption_public_key =
            EncryptionPublicKey::from(&StaticSecret::from(x25519_secret)).to_bytes();
        let persisted = EpochEncryptionSecret::from_decrypted(
            party,
            epoch,
            expected_encryption_public_key,
            Zeroizing::new(x25519_secret),
        )?;
        Self::from_encryption_secret(
            party,
            epoch,
            signing_seed,
            Self::signing_public_key_from_seed(signing_seed)?,
            expected_encryption_public_key,
            &persisted,
        )
    }

    /// Generate a fresh, unpersisted X25519 candidate for the immediate successor epoch.
    ///
    /// This method returns only a zeroizing secret object. It does not create an advertisable
    /// identity; durable persistence and authenticated readback remain mandatory.
    pub fn fresh_successor_secret<R: RngCore + CryptoRng>(
        &self,
        target_epoch: u64,
        rng: &mut R,
    ) -> Result<EpochEncryptionSecret, IdentityError> {
        self.validate_successor_epoch(target_epoch)?;
        let candidate = EpochEncryptionSecret::generate(self.party, target_epoch, rng)?;
        if candidate.public_key() == self.encryption_public_key() {
            return Err(IdentityError::EncryptionKeyNotRotated);
        }
        Ok(candidate)
    }

    /// Export the epoch encryption key in a redacted, zeroize-on-drop persistence value.
    #[must_use]
    pub fn export_encryption_secret(&self) -> EpochEncryptionSecret {
        let secret = Zeroizing::new(self.encryption.to_bytes());
        EpochEncryptionSecret {
            party: self.party,
            epoch: self.encryption_epoch,
            public_key: self.encryption_public_key(),
            secret: *secret,
        }
    }

    /// Reconstruct an identity from a stable signing seed and an authenticated persisted X25519
    /// key.
    ///
    /// Both public-key expectations must come from trusted configuration or a certified rotation.
    /// The method checks the party and epoch metadata, re-derives the stable signing public key,
    /// and re-derives the X25519 public key from the stored secret before accepting it.
    #[allow(clippy::too_many_arguments)]
    pub fn from_encryption_secret(
        party: PartyId,
        expected_epoch: u64,
        signing_seed: &[u8; 32],
        expected_signing_public_key: [u8; 32],
        expected_encryption_public_key: [u8; 32],
        persisted: &EpochEncryptionSecret,
    ) -> Result<Self, IdentityError> {
        if persisted.party != party {
            return Err(IdentityError::WrongEncryptionParty);
        }
        if persisted.epoch != expected_epoch {
            return Err(IdentityError::WrongEncryptionEpoch);
        }
        if persisted.public_key != expected_encryption_public_key {
            return Err(IdentityError::WrongEncryptionPublicKey);
        }

        let signing = derive_signing_key(signing_seed)?;
        if signing.verifying_key().to_bytes() != expected_signing_public_key {
            return Err(IdentityError::WrongSigningPublicKey);
        }
        let secret = Zeroizing::new(*persisted.secret_bytes());
        let encryption = StaticSecret::from(*secret);
        if EncryptionPublicKey::from(&encryption).to_bytes() != expected_encryption_public_key {
            return Err(IdentityError::WrongEncryptionPublicKey);
        }
        Ok(Self { party, encryption_epoch: expected_epoch, signing, encryption })
    }

    /// Bind an identity reconstructed from an authenticated storage readback to the capability
    /// required by key-advertisement signing.
    ///
    /// `durable_record_digest` is the storage-domain digest of the exact authenticated record, not
    /// the public key or a caller-chosen request identifier.
    pub(crate) fn after_durable_encryption_readback(
        self,
        durable_record_digest: [u8; 32],
    ) -> Result<PersistedKeyAdvertisementIdentity, IdentityError> {
        if durable_record_digest == [0_u8; 32] {
            return Err(IdentityError::InvalidPersistenceBinding);
        }
        Ok(PersistedKeyAdvertisementIdentity { identity: self, durable_record_digest })
    }

    fn validate_successor_epoch(&self, target_epoch: u64) -> Result<(), IdentityError> {
        if self.encryption_epoch.checked_add(1) != Some(target_epoch) {
            return Err(IdentityError::WrongSuccessorEpoch);
        }
        Ok(())
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn encryption_epoch(&self) -> u64 {
        self.encryption_epoch
    }

    pub fn signing_public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn encryption_public_key(&self) -> [u8; 32] {
        EncryptionPublicKey::from(&self.encryption).to_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_envelope(
        &self,
        committee: &Committee,
        session: SessionId,
        to: Option<PartyId>,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<SignedEnvelope, IdentityError> {
        committee.validate()?;
        if payload.len() > MAX_SIGNED_ENVELOPE_PAYLOAD_BYTES {
            return Err(IdentityError::PayloadTooLarge);
        }
        if committee.member(self.party)?.signing_key != self.signing_public_key() {
            return Err(IdentityError::WrongSender);
        }
        if let Some(recipient) = to {
            committee.member(recipient)?;
        }
        let unsigned = UnsignedEnvelope {
            version: ENVELOPE_VERSION,
            committee: committee.digest(),
            epoch: committee.epoch,
            session,
            from: self.party,
            to,
            sequence,
            payload: &payload,
        };
        let bytes = postcard::to_allocvec(&unsigned).map_err(|_| IdentityError::Serialization)?;
        let signature = self.signing.sign(&bytes).to_bytes();
        Ok(SignedEnvelope {
            version: ENVELOPE_VERSION,
            committee: committee.digest(),
            epoch: committee.epoch,
            session,
            from: self.party,
            to,
            sequence,
            payload,
            signature,
        })
    }

    pub fn verify_envelope(
        committee: &Committee,
        local_party: PartyId,
        envelope: &SignedEnvelope,
    ) -> Result<(), IdentityError> {
        committee.validate()?;
        if envelope.payload.len() > MAX_SIGNED_ENVELOPE_PAYLOAD_BYTES {
            return Err(IdentityError::PayloadTooLarge);
        }
        if envelope.version != ENVELOPE_VERSION {
            return Err(IdentityError::UnsupportedVersion);
        }
        if envelope.epoch != committee.epoch || envelope.committee != committee.digest() {
            return Err(IdentityError::WrongCommittee);
        }
        if envelope.to.is_some_and(|recipient| recipient != local_party) {
            return Err(IdentityError::WrongRecipient);
        }
        let member = committee.member(envelope.from)?;
        let key = VerifyingKey::from_bytes(&member.signing_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let unsigned = UnsignedEnvelope {
            version: envelope.version,
            committee: envelope.committee,
            epoch: envelope.epoch,
            session: envelope.session,
            from: envelope.from,
            to: envelope.to,
            sequence: envelope.sequence,
            payload: &envelope.payload,
        };
        let bytes = postcard::to_allocvec(&unsigned).map_err(|_| IdentityError::Serialization)?;
        key.verify(&bytes, &Signature::from_bytes(&envelope.signature))
            .map_err(|_| IdentityError::InvalidSignature)
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        committee: &Committee,
        session: SessionId,
        recipient: PartyId,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<EncryptedPayload, IdentityError> {
        self.encrypt_bound(committee, session, recipient, b"", plaintext, rng)
    }

    /// Encrypt with an application binding (protocol kind, dealer slot, round, and logical slot).
    /// The same binding must be supplied when decrypting.
    pub fn encrypt_bound<R: RngCore + CryptoRng>(
        &self,
        committee: &Committee,
        session: SessionId,
        recipient: PartyId,
        binding: &[u8],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<EncryptedPayload, IdentityError> {
        if plaintext
            .len()
            .checked_add(16)
            .is_none_or(|ciphertext_len| ciphertext_len > MAX_ENCRYPTED_PAYLOAD_BYTES)
        {
            return Err(IdentityError::PayloadTooLarge);
        }
        let member = committee.member(recipient)?;
        let peer = EncryptionPublicKey::from(member.encryption_key);
        let shared = self.encryption.diffie_hellman(&peer);
        if bool::from(shared.as_bytes().ct_eq(&[0_u8; 32])) {
            return Err(IdentityError::InvalidSharedSecret);
        }
        let aad = encryption_aad(committee, session, self.party, recipient, binding);
        let key = derive_aead_key(shared.as_bytes(), &aad)?;
        let mut nonce = [0_u8; 24];
        rng.fill_bytes(&mut nonce);
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| IdentityError::Encryption)?;
        Ok(EncryptedPayload { nonce, ciphertext })
    }

    pub fn decrypt(
        &self,
        committee: &Committee,
        session: SessionId,
        sender: PartyId,
        encrypted: &EncryptedPayload,
    ) -> Result<Vec<u8>, IdentityError> {
        self.decrypt_bound(committee, session, sender, b"", encrypted)
    }

    pub fn decrypt_bound(
        &self,
        committee: &Committee,
        session: SessionId,
        sender: PartyId,
        binding: &[u8],
        encrypted: &EncryptedPayload,
    ) -> Result<Vec<u8>, IdentityError> {
        let sender_key = committee.member(sender)?.encryption_key;
        self.decrypt_from_key_bound(committee, session, sender, sender_key, binding, encrypted)
    }

    /// Decrypt a transition message from an old-only dealer whose key is authenticated by the old
    /// committee while this ciphertext is bound to the new committee.
    pub fn decrypt_from_key_bound(
        &self,
        committee: &Committee,
        session: SessionId,
        sender: PartyId,
        sender_encryption_key: [u8; 32],
        binding: &[u8],
        encrypted: &EncryptedPayload,
    ) -> Result<Vec<u8>, IdentityError> {
        if encrypted.ciphertext.len() > MAX_ENCRYPTED_PAYLOAD_BYTES {
            return Err(IdentityError::PayloadTooLarge);
        }
        let peer = EncryptionPublicKey::from(sender_encryption_key);
        let shared = self.encryption.diffie_hellman(&peer);
        if bool::from(shared.as_bytes().ct_eq(&[0_u8; 32])) {
            return Err(IdentityError::InvalidSharedSecret);
        }
        let aad = encryption_aad(committee, session, sender, self.party, binding);
        let key = derive_aead_key(shared.as_bytes(), &aad)?;
        XChaCha20Poly1305::new(Key::from_slice(&key))
            .decrypt(
                XNonce::from_slice(&encrypted.nonce),
                Payload { msg: &encrypted.ciphertext, aad: &aad },
            )
            .map_err(|_| IdentityError::Decryption)
    }
}

impl PersistedKeyAdvertisementIdentity {
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Consume the advertisement authority and retain the exact durably read-back identity for
    /// local protocol use.
    ///
    /// This deliberately prevents callers from keeping a second reusable advertisement
    /// capability after installing the receiver key in the epoch identity registry.
    #[must_use]
    pub(crate) fn into_identity(self) -> Identity {
        self.identity
    }

    #[must_use]
    pub const fn durable_record_digest(&self) -> [u8; 32] {
        self.durable_record_digest
    }
}

fn deserialize_signed_envelope_payload<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes(
        deserializer,
        MAX_SIGNED_ENVELOPE_PAYLOAD_BYTES,
        "signed-envelope payload exceeds the allocation bound",
    )
}

fn deserialize_encrypted_payload_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes(
        deserializer,
        MAX_ENCRYPTED_PAYLOAD_BYTES,
        "encrypted payload exceeds the allocation bound",
    )
}

fn deserialize_bounded_bytes<'de, D>(
    deserializer: D,
    maximum: usize,
    expectation: &'static str,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedBytesVisitor {
        maximum: usize,
        expectation: &'static str,
    }

    impl<'de> Visitor<'de> for BoundedBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(self.expectation)
        }

        fn visit_bytes<E: DeError>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            if bytes.len() > self.maximum {
                return Err(E::custom(self.expectation));
            }
            Ok(bytes.to_vec())
        }

        fn visit_byte_buf<E: DeError>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            if bytes.len() > self.maximum {
                return Err(E::custom(self.expectation));
            }
            Ok(bytes)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > self.maximum) {
                return Err(A::Error::custom(self.expectation));
            }
            let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == self.maximum {
                    return Err(A::Error::custom(self.expectation));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_byte_buf(BoundedBytesVisitor { maximum, expectation })
}

fn derive_signing_key(stable_seed: &[u8; 32]) -> Result<SigningKey, IdentityError> {
    let hk = Hkdf::<Sha256>::new(Some(b"threshold-monero/identity/v1"), stable_seed);
    let mut expanded_seed = Zeroizing::new([0_u8; 32]);
    hk.expand(b"ed25519-signing", expanded_seed.as_mut())
        .map_err(|_| IdentityError::KeyDerivation)?;
    Ok(SigningKey::from_bytes(&expanded_seed))
}

fn encryption_aad(
    committee: &Committee,
    session: SessionId,
    sender: PartyId,
    recipient: PartyId,
    binding: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 32 + 8 + 4);
    aad.extend_from_slice(b"threshold-monero/share/v1");
    aad.extend_from_slice(&committee.digest());
    aad.extend_from_slice(&committee.epoch.to_le_bytes());
    aad.extend_from_slice(&session.0);
    aad.extend_from_slice(&sender.0.to_le_bytes());
    aad.extend_from_slice(&recipient.0.to_le_bytes());
    aad.extend_from_slice(&(binding.len() as u64).to_le_bytes());
    aad.extend_from_slice(binding);
    aad
}

fn derive_aead_key(shared: &[u8; 32], aad: &[u8]) -> Result<[u8; 32], IdentityError> {
    let hk = Hkdf::<Sha256>::new(Some(aad), shared);
    let mut key = [0_u8; 32];
    hk.expand(b"xchacha20poly1305", &mut key).map_err(|_| IdentityError::KeyDerivation)?;
    Ok(key)
}

mod signature_bytes {
    use serde::{
        Deserializer, Serializer,
        de::{Error, SeqAccess, Visitor},
    };

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        struct SignatureVisitor;

        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("exactly 64 signature bytes")
            }

            fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                bytes.try_into().map_err(|_| E::custom("signature must contain 64 bytes"))
            }

            fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&bytes)
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                // `size_hint` is advisory and absent in self-describing formats (serde_json
                // returns `None`); exactness is enforced below by reading precisely 64 elements
                // and rejecting any trailing element.
                let mut signature = [0_u8; 64];
                for byte in &mut signature {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| A::Error::custom("signature must contain 64 bytes"))?;
                }
                if sequence.next_element::<u8>()?.is_some() {
                    return Err(A::Error::custom("signature must contain 64 bytes"));
                }
                Ok(signature)
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use serde::{Deserialize, Deserializer};

    use super::*;
    use crate::committee::Member;

    fn deserialize_four_bytes<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        deserialize_bounded_bytes(deserializer, 4, "at most four bytes")
    }

    #[derive(Deserialize)]
    struct FourBytes(#[serde(deserialize_with = "deserialize_four_bytes")] Vec<u8>);

    fn explicit_identity(
        party: PartyId,
        epoch: u64,
        signing_seed: &[u8; 32],
        encryption_secret: [u8; 32],
    ) -> Identity {
        let public_key =
            EncryptionPublicKey::from(&StaticSecret::from(encryption_secret)).to_bytes();
        let persisted = EpochEncryptionSecret::from_decrypted(
            party,
            epoch,
            public_key,
            Zeroizing::new(encryption_secret),
        )
        .unwrap();
        Identity::from_encryption_secret(
            party,
            epoch,
            signing_seed,
            Identity::signing_public_key_from_seed(signing_seed).unwrap(),
            public_key,
            &persisted,
        )
        .unwrap()
    }

    fn fixtures() -> (Committee, Identity, Identity) {
        let one = explicit_identity(PartyId(1), 4, &[1; 32], [0xA1; 32]);
        let two = explicit_identity(PartyId(2), 4, &[2; 32], [0xA2; 32]);
        let committee = Committee {
            epoch: 4,
            threshold: 2,
            members: vec![
                Member {
                    id: PartyId(1),
                    signing_key: one.signing_public_key(),
                    encryption_key: one.encryption_public_key(),
                },
                Member {
                    id: PartyId(2),
                    signing_key: two.signing_public_key(),
                    encryption_key: two.encryption_public_key(),
                },
            ],
        };
        (committee, one, two)
    }

    #[test]
    fn signatures_bind_every_field() {
        let (committee, one, _) = fixtures();
        let session = SessionId([9; 32]);
        let envelope = one
            .sign_envelope(&committee, session, Some(PartyId(2)), 7, b"message".to_vec())
            .unwrap();
        Identity::verify_envelope(&committee, PartyId(2), &envelope).unwrap();

        let mut tampered = envelope;
        tampered.sequence += 1;
        assert_eq!(
            Identity::verify_envelope(&committee, PartyId(2), &tampered),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn byte_deserialization_rejects_declared_oversize_before_materialization() {
        let encoded = postcard::to_allocvec(&vec![0xA5_u8; 5]).unwrap();
        assert!(postcard::from_bytes::<FourBytes>(&encoded).is_err());
        let encoded = postcard::to_allocvec(&vec![0xA5_u8; 4]).unwrap();
        assert_eq!(postcard::from_bytes::<FourBytes>(&encoded).unwrap().0.len(), 4);
    }

    #[test]
    fn pairwise_encryption_round_trips_and_binds_session() {
        let (committee, one, two) = fixtures();
        let session = SessionId([3; 32]);
        let encrypted =
            one.encrypt(&committee, session, PartyId(2), b"secret share", &mut OsRng).unwrap();
        assert_eq!(
            two.decrypt(&committee, session, PartyId(1), &encrypted).unwrap(),
            b"secret share"
        );
        assert_eq!(
            two.decrypt(&committee, SessionId([4; 32]), PartyId(1), &encrypted),
            Err(IdentityError::Decryption)
        );
    }

    #[test]
    fn encryption_rejects_payloads_which_cannot_be_decoded_under_the_transport_cap() {
        let (committee, one, _) = fixtures();
        let plaintext = vec![0_u8; MAX_SIGNED_ENVELOPE_PAYLOAD_BYTES + 1];
        assert_eq!(
            one.encrypt(&committee, SessionId([3; 32]), PartyId(2), &plaintext, &mut OsRng,),
            Err(IdentityError::PayloadTooLarge)
        );
    }

    #[test]
    fn fresh_successor_requires_durable_readback_before_it_can_advertise() {
        let signing_seed = [0x41; 32];
        let current = explicit_identity(PartyId(1), 4, &signing_seed, [0xB1; 32]);
        let successor_secret = current.fresh_successor_secret(5, &mut OsRng).unwrap();
        assert_eq!(successor_secret.party(), current.party());
        assert_eq!(successor_secret.epoch(), 5);
        assert_ne!(successor_secret.public_key(), current.encryption_public_key());

        // A raw generated secret is not an advertisement capability. Reconstructing the identity
        // and binding it to an authenticated durable-record digest is an explicit second step.
        let restored = Identity::from_encryption_secret(
            current.party(),
            5,
            &signing_seed,
            current.signing_public_key(),
            successor_secret.public_key(),
            &successor_secret,
        )
        .unwrap();
        assert_eq!(
            restored.after_durable_encryption_readback([0_u8; 32]).unwrap_err(),
            IdentityError::InvalidPersistenceBinding
        );
        let restored = Identity::from_encryption_secret(
            current.party(),
            5,
            &signing_seed,
            current.signing_public_key(),
            successor_secret.public_key(),
            &successor_secret,
        )
        .unwrap();
        let advertisable = restored.after_durable_encryption_readback([0xD5; 32]).unwrap();
        assert_eq!(advertisable.identity().encryption_epoch(), 5);
        assert_eq!(advertisable.identity().signing_public_key(), current.signing_public_key());
        assert_eq!(advertisable.durable_record_digest(), [0xD5; 32]);
        assert_eq!(
            current.fresh_successor_secret(6, &mut OsRng).unwrap_err(),
            IdentityError::WrongSuccessorEpoch
        );
    }

    #[test]
    fn persisted_encryption_secret_round_trips_with_public_expectations() {
        let party = PartyId(7);
        let signing_seed = [0x57; 32];
        let current = explicit_identity(party, 8, &signing_seed, [0xC7; 32]);
        let persisted = current.fresh_successor_secret(9, &mut OsRng).unwrap();

        let restored = Identity::from_encryption_secret(
            party,
            9,
            &signing_seed,
            current.signing_public_key(),
            persisted.public_key(),
            &persisted,
        )
        .unwrap();
        assert_eq!(restored.party(), party);
        assert_eq!(restored.encryption_epoch(), 9);
        assert_eq!(restored.signing_public_key(), current.signing_public_key());
        assert_eq!(restored.encryption_public_key(), persisted.public_key());

        assert_eq!(
            Identity::from_encryption_secret(
                party,
                10,
                &signing_seed,
                current.signing_public_key(),
                persisted.public_key(),
                &persisted,
            )
            .unwrap_err(),
            IdentityError::WrongEncryptionEpoch
        );
        assert_eq!(
            Identity::from_encryption_secret(
                party,
                9,
                &signing_seed,
                current.signing_public_key(),
                [0xA5; 32],
                &persisted,
            )
            .unwrap_err(),
            IdentityError::WrongEncryptionPublicKey
        );
        assert_eq!(
            Identity::from_encryption_secret(
                party,
                9,
                &signing_seed,
                [0xB6; 32],
                persisted.public_key(),
                &persisted,
            )
            .unwrap_err(),
            IdentityError::WrongSigningPublicKey
        );
    }

    #[test]
    fn decrypted_persistence_checks_public_key_and_zeroizes() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<EpochEncryptionSecret>();

        let identity = explicit_identity(PartyId(3), 12, &[0x93; 32], [0xD3; 32]);
        let mut persisted = identity.export_encryption_secret();
        assert_eq!(persisted.party(), PartyId(3));
        assert_eq!(persisted.epoch(), 12);
        assert_eq!(persisted.public_key(), identity.encryption_public_key());
        assert!(!format!("{persisted:?}").contains("secret"));

        let decrypted = Zeroizing::new(*persisted.secret_bytes());
        assert_eq!(
            EpochEncryptionSecret::from_decrypted(PartyId(3), 12, [0xA5; 32], decrypted)
                .unwrap_err(),
            IdentityError::WrongEncryptionPublicKey
        );

        persisted.zeroize();
        assert_eq!(persisted.secret_bytes(), &[0_u8; 32]);
    }

    #[test]
    fn signing_seed_neither_determines_nor_recovers_epoch_encryption_secrets() {
        let party = PartyId(9);
        let signing_seed = [0x99; 32];
        let epoch_four = explicit_identity(party, 4, &signing_seed, [0x34; 32]);
        let epoch_five = explicit_identity(party, 5, &signing_seed, [0x35; 32]);
        assert_eq!(epoch_four.signing_public_key(), epoch_five.signing_public_key());
        assert_ne!(epoch_four.encryption_public_key(), epoch_five.encryption_public_key());

        let old_public = epoch_four.encryption_public_key();
        let mut erased = epoch_four.export_encryption_secret();
        erased.zeroize();
        assert_eq!(
            EpochEncryptionSecret::from_decrypted(
                party,
                4,
                old_public,
                Zeroizing::new(*erased.secret_bytes()),
            )
            .unwrap_err(),
            IdentityError::WrongEncryptionPublicKey
        );
        assert_eq!(
            Identity::signing_public_key_from_seed(&signing_seed).unwrap(),
            epoch_five.signing_public_key()
        );
    }
}
