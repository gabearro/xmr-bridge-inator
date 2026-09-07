use core::ops::Deref as _;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};
use zeroize::{Zeroize as _, Zeroizing};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_POINT,
  edwards::CompressedEdwardsY,
  traits::{Identity as _, IsIdentity as _},
  Scalar, EdwardsPoint,
};

use transcript::{Transcript as _, RecommendedTranscript};
use frost::{
  curve::Ed25519,
  Participant, FrostError, ThresholdKeys,
  sign::{
    Writable, Preprocess, CachedPreprocess, SignatureShare, PreprocessMachine, SignMachine,
    SignatureMachine, AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
};

use monero_oxide::{
  ed25519::CompressedPoint,
  ringct::{
    clsag::{ClsagContext, ClsagMultisigMaskSender, ClsagAddendum, ClsagMultisig},
    RctPrunable, RctProofs,
  },
  transaction::Transaction,
};
use crate::send::{SendError, SignableTransaction, key_image_sort};

/// Initial FROST machine to produce a signed transaction.
pub struct TransactionMachine {
  signable: SignableTransaction,

  keys: ThresholdKeys<Ed25519>,

  key_image_proof_context: [u8; 32],

  // The key image generator, and the (scalar, offset) linear combination from the spend key
  key_image_generators_and_lincombs: Vec<(EdwardsPoint, (Scalar, Scalar))>,
  clsags: Vec<(ClsagMultisigMaskSender, AlgorithmMachine<Ed25519, ClsagMultisig>)>,
}

/// Second FROST machine to produce a signed transaction.
///
/// The generic [`SignMachine::sign`] entry point intentionally fails closed. Callers must first
/// consume this machine with [`Self::bind`], certify the resulting transaction, and only then call
/// [`TransactionBoundSignMachine::release_signature_share`]. `cache` and `from_cache` remain
/// unsupported.
///
/// This MUST only be passed preprocesses obtained via calling `read_preprocess` with this very
/// machine. Other machines representing distinct executions of the protocol will almost certainly
/// be incompatible.
pub struct TransactionSignMachine {
  signable: SignableTransaction,

  keys: ThresholdKeys<Ed25519>,

  key_image_proof_context: [u8; 32],

  key_image_generators_and_lincombs: Vec<(EdwardsPoint, (Scalar, Scalar))>,
  clsags: Vec<(ClsagMultisigMaskSender, AlgorithmSignMachine<Ed25519, ClsagMultisig>)>,

  our_preprocess: TransactionPreprocess,
}

/// A FROST machine whose exact preprocess set and unsigned Monero transaction have been bound.
///
/// Creating this machine does not calculate or expose a signature share. The caller can inspect
/// and certify [`Self::transaction`] before explicitly consuming the machine with
/// [`Self::release_signature_share`]. The same immutable preprocess set is used for both the
/// previewed transaction and the eventual signature share, preventing a time-of-check/time-of-use
/// substitution.
pub struct TransactionBoundSignMachine {
  machine: TransactionSignMachine,
  commitments: HashMap<Participant, TransactionPreprocess>,
  key_images: Vec<CompressedPoint>,
  transaction: Transaction,
  preprocess_set_digest: [u8; 32],
}

/// Final FROST machine to produce a signed transaction.
///
/// This MUST only be passed shares obtained via calling `read_share` with this very machine.
/// Shares from other machines, representing distinct executions of the signing protocol, will be
/// incompatible.
pub struct TransactionSignatureMachine {
  tx: Transaction,
  clsags: Vec<AlgorithmSignatureMachine<Ed25519, ClsagMultisig>>,
}

impl SignableTransaction {
  /// Create a FROST signing machine whose key-image-share proofs are bound to `context`.
  ///
  /// The context should commit to the complete application protocol session, including the
  /// committee, signer set, network, and transaction intent. It is incorporated into the
  /// Chaum-Pedersen proof attached to every input's round-one key-image share. This lets callers
  /// safely inspect the aggregate key images before releasing any signature share.
  ///
  /// This function runs in time variable to the validity of the arguments and the public data.
  pub fn multisig_with_context(
    self,
    keys: ThresholdKeys<Ed25519>,
    context: [u8; 32],
  ) -> Result<TransactionMachine, SendError> {
    if context == [0; 32] {
      return Err(SendError::MissingMultisigContext);
    }

    let mut clsags = vec![];

    let mut key_image_generators_and_lincombs = vec![];
    for input in &self.inputs {
      // Check this is the right set of keys
      let key_scalar = Scalar::ONE;
      let key_offset = input.key_offset();

      let offset = keys
        .clone()
        .scale(key_scalar)
        .expect("non-zero scalar (1) was zero")
        .offset(key_offset.into());
      if offset.group_key().0 != input.key().into() {
        Err(SendError::WrongPrivateKey)?;
      }

      let context = ClsagContext::new(input.decoys().clone(), input.commitment().clone())
        .map_err(SendError::ClsagError)?;
      let (clsag, clsag_mask_send) = ClsagMultisig::new(
        RecommendedTranscript::new(b"Monero Multisignature Transaction"),
        context,
      );
      key_image_generators_and_lincombs
        .push((clsag.key_image_generator(), (offset.current_scalar(), offset.current_offset())));
      clsags.push((clsag_mask_send, AlgorithmMachine::new(clsag, offset)));
    }

    Ok(TransactionMachine {
      signable: self,
      keys,
      key_image_proof_context: context,
      key_image_generators_and_lincombs,
      clsags,
    })
  }
}

/// The preprocess for a transaction.
// Opaque wrapper around the CLSAG preprocesses, forcing users to use `read_preprocess` to obtain
// this.
#[derive(Clone, PartialEq, Eq)]
struct KeyImageShareProof {
  commitment_g: EdwardsPoint,
  commitment_h: EdwardsPoint,
  response: Scalar,
}

impl KeyImageShareProof {
  #[allow(clippy::too_many_arguments)]
  fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    context: &[u8; 32],
    participant: Participant,
    input_index: usize,
    input: &[u8],
    secret_share: &Scalar,
    verification_share: EdwardsPoint,
    key_image_generator: EdwardsPoint,
    key_image_share: EdwardsPoint,
  ) -> Self {
    // This is an independent draw after the FROST/CLSAG nonce generation. It is never retained
    // as part of either signing nonce and is used solely by this proof.
    let nonce = Zeroizing::new(loop {
      let mut wide = [0; 64];
      rng.fill_bytes(&mut wide);
      let nonce = Scalar::from_bytes_mod_order_wide(&wide);
      wide.zeroize();
      if nonce != Scalar::ZERO {
        break nonce;
      }
    });
    let commitment_g = ED25519_BASEPOINT_POINT * *nonce;
    let commitment_h = key_image_generator * *nonce;
    let challenge = key_image_share_challenge(
      context,
      participant,
      input_index,
      input,
      verification_share,
      key_image_generator,
      key_image_share,
      commitment_g,
      commitment_h,
    );
    let response = *nonce + (challenge * secret_share);
    Self { commitment_g, commitment_h, response }
  }

  #[allow(clippy::too_many_arguments)]
  fn verify(
    &self,
    context: &[u8; 32],
    participant: Participant,
    input_index: usize,
    input: &[u8],
    verification_share: EdwardsPoint,
    key_image_generator: EdwardsPoint,
    key_image_share: EdwardsPoint,
  ) -> bool {
    if self.commitment_g.is_identity() || self.commitment_h.is_identity() {
      return false;
    }
    let challenge = key_image_share_challenge(
      context,
      participant,
      input_index,
      input,
      verification_share,
      key_image_generator,
      key_image_share,
      self.commitment_g,
      self.commitment_h,
    );
    ((ED25519_BASEPOINT_POINT * self.response)
      == (self.commitment_g + (verification_share * challenge)))
      && ((key_image_generator * self.response)
        == (self.commitment_h + (key_image_share * challenge)))
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.commitment_g.compress().to_bytes())?;
    writer.write_all(&self.commitment_h.compress().to_bytes())?;
    writer.write_all(&self.response.to_bytes())
  }

  fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    fn read_point<R: Read>(reader: &mut R) -> io::Result<EdwardsPoint> {
      let mut bytes = [0; 32];
      reader.read_exact(&mut bytes)?;
      let point = CompressedEdwardsY(bytes)
        .decompress()
        .filter(|point| point.is_torsion_free() && (point.compress().to_bytes() == bytes))
        .ok_or_else(|| io::Error::other("invalid key-image-share proof point"))?;
      Ok(point)
    }

    let commitment_g = read_point(reader)?;
    let commitment_h = read_point(reader)?;
    let mut response = [0; 32];
    reader.read_exact(&mut response)?;
    let response = Option::<Scalar>::from(Scalar::from_canonical_bytes(response))
      .ok_or_else(|| io::Error::other("invalid key-image-share proof response"))?;
    Ok(Self { commitment_g, commitment_h, response })
  }
}

#[allow(clippy::too_many_arguments)]
fn key_image_share_challenge(
  context: &[u8; 32],
  participant: Participant,
  input_index: usize,
  input: &[u8],
  verification_share: EdwardsPoint,
  key_image_generator: EdwardsPoint,
  key_image_share: EdwardsPoint,
  commitment_g: EdwardsPoint,
  commitment_h: EdwardsPoint,
) -> Scalar {
  let mut transcript = RecommendedTranscript::new(b"Monero FROSTLASS key-image-share proof");
  transcript.domain_separate(b"v1");
  transcript.append_message(b"application_context", context);
  transcript.append_message(b"participant", participant.to_bytes());
  transcript.append_message(
    b"input_index",
    u64::try_from(input_index).expect("input quantity fits within u64").to_le_bytes(),
  );
  transcript.append_message(b"input", input);
  transcript.append_message(b"G", ED25519_BASEPOINT_POINT.compress().to_bytes());
  transcript.append_message(b"xG", verification_share.compress().to_bytes());
  transcript.append_message(b"H", key_image_generator.compress().to_bytes());
  transcript.append_message(b"xH", key_image_share.compress().to_bytes());
  transcript.append_message(b"rG", commitment_g.compress().to_bytes());
  transcript.append_message(b"rH", commitment_h.compress().to_bytes());
  let challenge = transcript.challenge(b"challenge");
  let mut wide = [0; 64];
  wide.copy_from_slice(challenge.as_ref());
  let challenge = Scalar::from_bytes_mod_order_wide(&wide);
  wide.zeroize();
  challenge
}

#[derive(Clone, PartialEq)]
pub struct TransactionPreprocess {
  clsags: Vec<Preprocess<Ed25519, ClsagAddendum>>,
  key_image_share_proofs: Vec<KeyImageShareProof>,
}
impl Writable for TransactionPreprocess {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    debug_assert_eq!(self.clsags.len(), self.key_image_share_proofs.len());
    for (preprocess, proof) in self.clsags.iter().zip(&self.key_image_share_proofs) {
      preprocess.write(writer)?;
      proof.write(writer)?;
    }
    Ok(())
  }
}

impl PreprocessMachine for TransactionMachine {
  type Preprocess = TransactionPreprocess;
  type Signature = Transaction;
  type SignMachine = TransactionSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
  ) -> (TransactionSignMachine, Self::Preprocess) {
    // Iterate over each CLSAG calling preprocess
    let mut preprocesses = Vec::with_capacity(self.clsags.len());
    let clsags = self
      .clsags
      .drain(..)
      .map(|(clsag_mask_send, clsag)| {
        let (clsag, preprocess) = clsag.preprocess(rng);
        preprocesses.push(preprocess);
        (clsag_mask_send, clsag)
      })
      .collect();
    let participant = self.keys.params().i();
    let secret_share: &Scalar = self.keys.original_secret_share().deref();
    let verification_share = self.keys.original_verification_share(participant).0;
    let key_image_share_proofs = preprocesses
      .iter()
      .enumerate()
      .map(|(input_index, preprocess)| {
        KeyImageShareProof::prove(
          rng,
          &self.key_image_proof_context,
          participant,
          input_index,
          &self.signable.inputs[input_index].serialize(),
          secret_share,
          verification_share,
          self.key_image_generators_and_lincombs[input_index].0,
          preprocess.addendum.key_image_share().0,
        )
      })
      .collect();
    let preprocess = TransactionPreprocess { clsags: preprocesses, key_image_share_proofs };
    let our_preprocess = preprocess.clone();

    (
      TransactionSignMachine {
        signable: self.signable,

        keys: self.keys,

        key_image_proof_context: self.key_image_proof_context,

        key_image_generators_and_lincombs: self.key_image_generators_and_lincombs,
        clsags,

        our_preprocess,
      },
      preprocess,
    )
  }
}

/// The signature share for a transaction.
// Opaque wrapper around the CLSAG signature shares, forcing users to use `read_share` to
// obtain this.
#[derive(Clone, PartialEq)]
pub struct TransactionSignatureShare(Vec<SignatureShare<Ed25519>>);
impl Writable for TransactionSignatureShare {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    for share in &self.0 {
      share.write(writer)?;
    }
    Ok(())
  }
}

impl TransactionSignMachine {
  fn validate_key_image_share_proofs(
    &self,
    commitments: &HashMap<Participant, TransactionPreprocess>,
  ) -> Result<Vec<Participant>, FrostError> {
    let input_quantity = self.clsags.len();
    if (self.our_preprocess.clsags.len() != input_quantity)
      || (self.our_preprocess.key_image_share_proofs.len() != input_quantity)
    {
      Err(FrostError::InternalError("local preprocess has an invalid input quantity"))?;
    }
    #[expect(clippy::iter_over_hash_type)]
    for preprocess in commitments.values() {
      if (preprocess.clsags.len() != input_quantity)
        || (preprocess.key_image_share_proofs.len() != input_quantity)
      {
        Err(FrostError::InternalError(
          "preprocesses from another instance of the signing protocol were passed in",
        ))?;
      }
    }

    let local = self.keys.params().i();
    let mut included =
      commitments.keys().filter(|participant| **participant != local).copied().collect::<Vec<_>>();
    included.push(local);
    included.sort_unstable();

    // Validate the signing set before indexing its verification shares. This rejects out-of-range
    // participant identifiers without allowing original_verification_share to panic.
    self.keys.view(included.clone()).map_err(|_| {
      FrostError::InvalidSigningSet("couldn't form an interpolated view of the key")
    })?;

    // Verify every proof, including ours, before aggregating even one key-image share. The proof
    // binds xG and xH to the exact session, participant, original input position, and decoy ring.
    for participant in &included {
      let preprocess = if *participant == local {
        &self.our_preprocess
      } else {
        commitments.get(participant).ok_or(FrostError::MissingParticipant(*participant))?
      };
      let verification_share = self.keys.original_verification_share(*participant).0;
      for input_index in 0..input_quantity {
        let key_image_share = preprocess.clsags[input_index].addendum.key_image_share().0;
        if !preprocess.key_image_share_proofs[input_index].verify(
          &self.key_image_proof_context,
          *participant,
          input_index,
          &self.signable.inputs[input_index].serialize(),
          verification_share,
          self.key_image_generators_and_lincombs[input_index].0,
          key_image_share,
        ) {
          Err(FrostError::InvalidPreprocess(*participant))?;
        }
      }
    }
    Ok(included)
  }

  /// Bind the exact preprocess set and calculate the unsigned transaction it commits to.
  ///
  /// No signature share is calculated by this method. Dropping the returned machine aborts this
  /// signing attempt and its one-time nonces. An application implementing consensus over the
  /// aggregate key images should certify [`TransactionBoundSignMachine::transaction`] before it
  /// calls [`TransactionBoundSignMachine::release_signature_share`].
  pub fn bind(
    self,
    commitments: HashMap<Participant, TransactionPreprocess>,
  ) -> Result<TransactionBoundSignMachine, FrostError> {
    let (key_images, transaction) = self.transaction_for_commitments(&commitments)?;
    let preprocess_set_digest = self.preprocess_set_digest(&commitments);
    Ok(TransactionBoundSignMachine {
      machine: self,
      commitments,
      key_images,
      transaction,
      preprocess_set_digest,
    })
  }

  fn preprocess_set_digest(
    &self,
    commitments: &HashMap<Participant, TransactionPreprocess>,
  ) -> [u8; 32] {
    let local = self.keys.params().i();
    let mut included =
      commitments.keys().filter(|participant| **participant != local).copied().collect::<Vec<_>>();
    included.push(local);
    included.sort_unstable();

    let mut transcript =
      RecommendedTranscript::new(b"Monero FROSTLASS proof-bearing preprocess set");
    transcript.domain_separate(b"v1");
    transcript.append_message(b"proof_context", self.key_image_proof_context);
    transcript.append_message(
      b"participant_quantity",
      u64::try_from(included.len()).expect("participant quantity fits within u64").to_le_bytes(),
    );
    for participant in included {
      let preprocess = if participant == local {
        &self.our_preprocess
      } else {
        commitments
          .get(&participant)
          .expect("validated participant was absent from the preprocess map")
      };
      transcript.append_message(b"participant", participant.to_bytes());
      transcript.append_message(b"preprocess", preprocess.serialize());
    }
    transcript.rng_seed(b"digest")
  }

  fn transaction_for_commitments(
    &self,
    commitments: &HashMap<Participant, TransactionPreprocess>,
  ) -> Result<(Vec<CompressedPoint>, Transaction), FrostError> {
    let local = self.keys.params().i();
    let included = self.validate_key_image_share_proofs(commitments)?;
    let view = self.keys.view(included.clone()).map_err(|_| {
      FrostError::InvalidSigningSet("couldn't form an interpolated view of the key")
    })?;
    let mut key_images = vec![EdwardsPoint::identity(); self.clsags.len()];
    for (clsag, key_image) in key_images.iter_mut().enumerate() {
      for participant in &included {
        let preprocess = if *participant == local {
          &self.our_preprocess.clsags[clsag]
        } else {
          &commitments.get(participant).ok_or(FrostError::MissingParticipant(*participant))?.clsags
            [clsag]
        };
        *key_image += preprocess.addendum.key_image_share().0
          * view.interpolation_factor(*participant).ok_or(FrostError::InternalError(
            "view successfully formed with participant without an interpolation factor",
          ))?;
      }
    }

    // Preserve this original signable-input order. Monero sorts the actual transaction inputs by
    // descending key image, but an application certifying a prepared spend must first pair every
    // image with its original output/ring.
    let key_images: Vec<CompressedPoint> = key_images
      .into_iter()
      .zip(&self.key_image_generators_and_lincombs)
      .map(|(mut key_image, (generator, (scalar, offset)))| {
        key_image *= scalar;
        key_image += generator * offset;
        CompressedPoint::from(key_image.compress().to_bytes())
      })
      .collect();
    let transaction = self
      .signable
      .clone()
      .unsigned_transaction(key_images.clone())
      .ok_or(FrostError::InternalError("key image count changed while binding transaction"))?;
    Ok((key_images, transaction))
  }

  // This is deliberately private and is only reachable from the transaction-bound state. The
  // public generic SignMachine entry point below fails closed so an application cannot release a
  // share without first inspecting and authorizing the exact transaction.
  fn sign_bound_transaction(
    self,
    mut commitments: HashMap<Participant, TransactionPreprocess>,
  ) -> Result<(TransactionSignatureMachine, TransactionSignatureShare), FrostError> {
    let included = self.validate_key_image_share_proofs(&commitments)?;

    // We do not need to be included here, yet this set of signers has yet to be validated
    // We explicitly remove ourselves to ensure we aren't included twice, if we were redundantly
    // included
    commitments.remove(&self.keys.params().i());

    // Start calculating the key images, as needed on the TX level
    let mut key_images = vec![EdwardsPoint::identity(); self.clsags.len()];

    // Convert the serialized nonces commitments to a parallelized Vec
    let view = self.keys.view(included.clone()).map_err(|_| {
      FrostError::InvalidSigningSet("couldn't form an interpolated view of the key")
    })?;
    let mut commitments = (0..self.clsags.len())
      .map(|c| {
        included
          .iter()
          .map(|l| {
            let preprocess = if *l == self.keys.params().i() {
              self.our_preprocess.clsags[c].clone()
            } else {
              commitments.get_mut(l).ok_or(FrostError::MissingParticipant(*l))?.clsags[c].clone()
            };

            // While here, calculate the key image as needed to call sign
            // The CLSAG algorithm will independently calculate the key image/verify these shares
            key_images[c] += preprocess.addendum.key_image_share().0
              * view.interpolation_factor(*l).ok_or(FrostError::InternalError(
                "view successfully formed with participant without an interpolation factor",
              ))?;

            Ok((*l, preprocess))
          })
          .collect::<Result<HashMap<_, _>, _>>()
      })
      .collect::<Result<Vec<_>, _>>()?;

    let key_images: Vec<_> = key_images
      .into_iter()
      .zip(&self.key_image_generators_and_lincombs)
      .map(|(mut key_image, (generator, (scalar, offset)))| {
        key_image *= scalar;
        key_image += generator * offset;
        CompressedPoint::from(key_image.compress().to_bytes())
      })
      .collect();

    // The above inserted our own preprocess into these maps (which is unnecessary)
    // Remove it now
    for map in &mut commitments {
      map.remove(&self.keys.params().i());
    }

    // The actual TX will have sorted its inputs by key image
    // We apply the same sort now to our CLSAG machines
    let mut clsags = Vec::with_capacity(self.clsags.len());
    for ((key_image, clsag), commitments) in key_images.iter().zip(self.clsags).zip(commitments) {
      clsags.push((key_image, clsag, commitments));
    }
    clsags.sort_by(|x, y| key_image_sort(x.0, y.0));
    let clsags =
      clsags.into_iter().map(|(_, clsag, commitments)| (clsag, commitments)).collect::<Vec<_>>();

    // Specify the TX's key images
    let tx = self.signable.with_key_images(key_images);

    // We now need to decide the masks for each CLSAG
    let clsag_len = clsags.len();
    let output_masks = tx.intent.sum_output_masks(&tx.key_images);
    let mut rng = tx.intent.seeded_rng(b"multisig_pseudo_out_masks");
    let mut sum_pseudo_outs = Scalar::ZERO;
    let mut to_sign = Vec::with_capacity(clsag_len);
    for (i, ((clsag_mask_send, clsag), commitments)) in clsags.into_iter().enumerate() {
      let mut mask = monero_oxide::ed25519::Scalar::random(&mut rng).into();
      if i == (clsag_len - 1) {
        mask = output_masks.into() - sum_pseudo_outs;
      } else {
        sum_pseudo_outs += mask;
      }
      clsag_mask_send.send(mask);
      to_sign.push((clsag, commitments));
    }

    let tx = tx.transaction_without_signatures();
    let msg = tx.signature_hash().expect("signing a transaction which isn't signed?");

    // Iterate over each CLSAG calling sign
    let mut shares = Vec::with_capacity(to_sign.len());
    let clsags = to_sign
      .drain(..)
      .map(|(clsag, commitments)| {
        let (clsag, share) = clsag.sign(commitments, &msg)?;
        shares.push(share);
        Ok(clsag)
      })
      .collect::<Result<_, _>>()?;

    Ok((TransactionSignatureMachine { tx, clsags }, TransactionSignatureShare(shares)))
  }
}

impl TransactionBoundSignMachine {
  /// Aggregate key images in the original [`SignableTransaction`] input order.
  ///
  /// The transaction returned by [`Self::transaction`] sorts its inputs by descending key image,
  /// as required by Monero. Callers should use this accessor to bind each image to the original
  /// prepared output and decoy ring before applying that sort.
  pub fn key_images(&self) -> &[CompressedPoint] {
    &self.key_images
  }

  /// The exact unsigned Monero transaction committed to by the preprocess set.
  pub fn transaction(&self) -> &Transaction {
    &self.transaction
  }

  /// A domain-separated digest of the canonical, participant-sorted proof-bearing preprocess set.
  ///
  /// This commits to the application proof context and every local/peer preprocess used to derive
  /// [`Self::transaction`]. It is only available after all key-image-share proofs verify.
  pub fn preprocess_set_digest(&self) -> [u8; 32] {
    self.preprocess_set_digest
  }

  /// Produce this party's signature share after the application certifies the bound transaction.
  pub fn release_signature_share(
    self,
  ) -> Result<(TransactionSignatureMachine, TransactionSignatureShare), FrostError> {
    let (machine, share) = self.machine.sign_bound_transaction(self.commitments)?;
    if machine.tx != self.transaction {
      Err(FrostError::InternalError(
        "bound transaction changed while releasing the signature share",
      ))?;
    }
    Ok((machine, share))
  }
}

impl SignMachine<Transaction> for TransactionSignMachine {
  type Params = ();
  type Keys = ThresholdKeys<Ed25519>;
  type Preprocess = TransactionPreprocess;
  type SignatureShare = TransactionSignatureShare;
  type SignatureMachine = TransactionSignatureMachine;

  fn cache(self) -> CachedPreprocess {
    unimplemented!(
      "Monero transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn from_cache(
    (): (),
    _: ThresholdKeys<Ed25519>,
    _: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    unimplemented!(
      "Monero transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    let mut clsags = Vec::with_capacity(self.clsags.len());
    let mut key_image_share_proofs = Vec::with_capacity(self.clsags.len());
    for clsag in &self.clsags {
      clsags.push(clsag.1.read_preprocess(reader)?);
      key_image_share_proofs.push(KeyImageShareProof::read(reader)?);
    }
    Ok(TransactionPreprocess { clsags, key_image_share_proofs })
  }

  fn sign(
    self,
    _: HashMap<Participant, Self::Preprocess>,
    _: &[u8],
  ) -> Result<(TransactionSignatureMachine, Self::SignatureShare), FrostError> {
    Err(FrostError::InternalError(
      "direct TransactionSignMachine::sign is disabled; bind the transaction before releasing a signature share",
    ))
  }
}

impl SignatureMachine<Transaction> for TransactionSignatureMachine {
  type SignatureShare = TransactionSignatureShare;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    Ok(TransactionSignatureShare(
      self.clsags.iter().map(|clsag| clsag.read_share(reader)).collect::<Result<_, _>>()?,
    ))
  }

  fn complete(
    mut self,
    shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    #[expect(clippy::iter_over_hash_type)]
    for share in shares.values() {
      if share.0.len() != self.clsags.len() {
        Err(FrostError::InternalError(
          "signature shares from another instance of the signing protocol were passed in",
        ))?;
      }
    }

    let mut tx = self.tx;
    #[expect(clippy::wildcard_enum_match_arm)]
    match tx {
      Transaction::V2 {
        proofs:
          Some(RctProofs {
            prunable: RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. },
            ..
          }),
        ..
      } => {
        for (c, clsag) in self.clsags.drain(..).enumerate() {
          let (clsag, pseudo_out) = clsag.complete(
            shares.iter().map(|(l, shares)| (*l, shares.0[c].clone())).collect::<HashMap<_, _>>(),
          )?;
          clsags.push(clsag);
          pseudo_outs.push(CompressedPoint::from(pseudo_out.compress().to_bytes()));
        }
      }
      _ => unreachable!("attempted to sign a multisig TX which wasn't CLSAG"),
    }
    Ok(tx)
  }
}
