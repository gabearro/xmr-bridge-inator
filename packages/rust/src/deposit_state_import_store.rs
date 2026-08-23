//! Crash-safe target acknowledgement collection for one deposit-state handoff.
//!
//! A target member must not let an acknowledgement escape before the exact acknowledgement is
//! durable. This journal stores the local acknowledgement and every distinct verified target
//! acknowledgement in one encrypted [`WalletSnapshotStore`] record. Replaying the same completed
//! import returns the original canonical acknowledgement bytes. Presenting another statement for
//! the same target slot is a permanent equivocation error, including after restart.
//!
//! Durable bytes are evidence, never protocol authority. Pre-final reads and mutations require a
//! freshly reconstructed [`VerifiedDepositStateImport`]; post-final reducers require the exact
//! installed certificate reverified against fresh source, handoff, target-registry, and target
//! authority. Current reducers additionally require the full epoch identity; historical
//! certificate-only availability uses target membership plus the stable signing/storage seed and
//! never exposes ACK or install methods. Stored artifacts never mint either capability.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, io,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex, OnceLock, Weak},
};

use rand_core::OsRng;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, MapAccess, SeqAccess, Visitor},
};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    committee::{MAX_COMMITTEE_MEMBERS, PartyId},
    compact_epoch_registry::{CompactEpochRegistry, RegistryHandoffCertificate},
    deposit_state_import::{
        DepositStateImportError, DepositStateImportedAck, DepositStateImportedCertificate,
        DepositStateImportedStatement, MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES,
        MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_BYTES, MAX_DEPOSIT_STATE_IMPORTED_STATEMENT_BYTES,
        VerifiedDepositStateImport, VerifiedStateImportedCertificate,
    },
    deposit_state_transfer_wire::{
        DepositStateImportedAckDelivery, DepositStateImportedAckReceipt,
        DepositStateImportedCertificateDelivery, DepositStateImportedCertificateDisposition,
        DepositStateImportedCertificateReceipt, DepositStateTransferWireError,
    },
    deposit_wallet::DepositWalletId,
    identity::Identity,
    key_rotation::VerifiedRegistryHandoffTarget,
    storage::{StoreError, WalletId, WalletSnapshotStore},
};

const DEPOSIT_STATE_IMPORT_STORE_VERSION: u16 = 2;
const DEPOSIT_STATE_IMPORT_STORE_DOMAIN: [u8; 16] = *b"tm-import-store2";
const DEPOSIT_STATE_IMPORT_SLOT_DOMAIN: &str =
    "threshold-monero/deposit-state-import-store/target-slot/v2";
const DEPOSIT_STATE_IMPORT_WORK_LOCATOR_DOMAIN: &str =
    "threshold-monero/deposit-state-import-store/work-locator/v2";
const MAX_DEPOSIT_STATE_IMPORT_CERTIFICATE_RECIPIENTS: usize = MAX_COMMITTEE_MEMBERS * 2;
const MAX_DEPOSIT_STATE_IMPORT_STORE_BYTES: usize = MAX_DEPOSIT_STATE_IMPORTED_STATEMENT_BYTES
    + (MAX_COMMITTEE_MEMBERS + 1) * MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES
    + 2 * MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_BYTES
    + 64 * 1024;

static SLOT_MUTATIONS: OnceLock<StdMutex<BTreeMap<WalletId, Weak<Mutex<()>>>>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct StatementBytes(Vec<u8>);

impl<'de> Deserialize<'de> for StatementBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_bounded_bytes(
            deserializer,
            MAX_DEPOSIT_STATE_IMPORTED_STATEMENT_BYTES,
            "deposit state-import statement",
        )
        .map(Self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct AckBytes(Vec<u8>);

impl<'de> Deserialize<'de> for AckBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_bounded_bytes(
            deserializer,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES,
            "deposit state-import acknowledgement",
        )
        .map(Self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct CertificateBytes(Vec<u8>);

impl<'de> Deserialize<'de> for CertificateBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_bounded_bytes(
            deserializer,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_BYTES,
            "deposit state-import certificate",
        )
        .map(Self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DurableInstalledCertificate {
    Canonical,
    Distinct(CertificateBytes),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableImportedAckRecipient {
    recipient: PartyId,
    acknowledgement_digest: [u8; 32],
    delivery_digest: [u8; 32],
    receipt: Option<DepositStateImportedAckReceipt>,
}

impl DurableImportedAckRecipient {
    fn new(
        statement: &DepositStateImportedStatement,
        acknowledgement: &DepositStateImportedAck,
        recipient: PartyId,
    ) -> Result<Self, DepositStateImportStoreError> {
        let delivery = DepositStateImportedAckDelivery::new(statement, acknowledgement, recipient)?;
        let durable = Self {
            recipient,
            acknowledgement_digest: delivery.acknowledgement_digest(),
            delivery_digest: delivery.digest(),
            receipt: None,
        };
        durable.validate_static()?;
        Ok(durable)
    }

    fn validate_static(&self) -> Result<(), DepositStateImportStoreError> {
        if self.recipient == PartyId(0)
            || self.acknowledgement_digest == [0; 32]
            || self.delivery_digest == [0; 32]
        {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn delivery(
        &self,
        statement: &DepositStateImportedStatement,
        acknowledgement: &DepositStateImportedAck,
    ) -> Result<DepositStateImportedAckDelivery, DepositStateImportStoreError> {
        self.validate_static()?;
        let delivery =
            DepositStateImportedAckDelivery::new(statement, acknowledgement, self.recipient)?;
        if delivery.acknowledgement_digest() != self.acknowledgement_digest
            || delivery.digest() != self.delivery_digest
        {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }
        if let Some(receipt) = self.receipt {
            receipt.to_bytes(&delivery, statement)?;
        }
        Ok(delivery)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableImportedCertificateRecipient {
    recipient: PartyId,
    certificate_digest: [u8; 32],
    delivery_digest: [u8; 32],
    receipt: Option<DepositStateImportedCertificateReceipt>,
}

impl DurableImportedCertificateRecipient {
    fn new(
        certificate: &DepositStateImportedCertificate,
        sender: PartyId,
        recipient: PartyId,
    ) -> Result<Self, DepositStateImportStoreError> {
        let delivery =
            DepositStateImportedCertificateDelivery::new(certificate.clone(), sender, recipient)?;
        let durable = Self {
            recipient,
            certificate_digest: delivery.certificate_digest(),
            delivery_digest: delivery.digest(),
            receipt: None,
        };
        durable.validate_static()?;
        Ok(durable)
    }

    fn validate_static(&self) -> Result<(), DepositStateImportStoreError> {
        if self.recipient == PartyId(0)
            || self.certificate_digest == [0; 32]
            || self.delivery_digest == [0; 32]
        {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn delivery(
        &self,
        certificate: &DepositStateImportedCertificate,
        sender: PartyId,
    ) -> Result<DepositStateImportedCertificateDelivery, DepositStateImportStoreError> {
        self.validate_static()?;
        let delivery = DepositStateImportedCertificateDelivery::new(
            certificate.clone(),
            sender,
            self.recipient,
        )?;
        if delivery.certificate_digest() != self.certificate_digest
            || delivery.digest() != self.delivery_digest
        {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }
        if let Some(receipt) = self.receipt {
            receipt.to_bytes(&delivery)?;
            if receipt.disposition() == DepositStateImportedCertificateDisposition::Deferred {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
        }
        Ok(delivery)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableDepositStateImport {
    version: u16,
    domain: [u8; 16],
    revision: u64,
    network: [u8; 32],
    wallet: DepositWalletId,
    local_party: PartyId,
    target_epoch: u64,
    target_committee: [u8; 32],
    target_fault_bound: u16,
    target_key_id: [u8; 32],
    target_group_key: [u8; 32],
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
    statement: StatementBytes,
    statement_digest: [u8; 32],
    semantic_transition: [u8; 32],
    local_ack: Option<AckBytes>,
    #[serde(deserialize_with = "deserialize_acknowledgements")]
    acknowledgements: BTreeMap<PartyId, AckBytes>,
    certificate: Option<CertificateBytes>,
    installed_certificate: Option<DurableInstalledCertificate>,
    #[serde(deserialize_with = "deserialize_imported_ack_recipients")]
    ack_recipients: Vec<DurableImportedAckRecipient>,
    #[serde(deserialize_with = "deserialize_imported_certificate_recipients")]
    certificate_recipients: Vec<DurableImportedCertificateRecipient>,
    installed_and_reclaimed: bool,
    terminal: bool,
}

impl DurableDepositStateImport {
    fn new(
        context: &DepositStateImportStoreContext,
        completed: &VerifiedDepositStateImport,
    ) -> Result<Self, DepositStateImportStoreError> {
        Self::new_from_statement(context, completed.statement())
    }

    fn new_from_statement(
        context: &DepositStateImportStoreContext,
        statement: &DepositStateImportedStatement,
    ) -> Result<Self, DepositStateImportStoreError> {
        let statement_bytes = statement.to_bytes()?;
        Ok(Self {
            version: DEPOSIT_STATE_IMPORT_STORE_VERSION,
            domain: DEPOSIT_STATE_IMPORT_STORE_DOMAIN,
            revision: 0,
            network: context.network,
            wallet: context.wallet,
            local_party: context.local_party,
            target_epoch: context.target_epoch,
            target_committee: context.target_committee,
            target_fault_bound: context.target_fault_bound,
            target_key_id: context.target_key_id,
            target_group_key: context.target_group_key,
            target_activation: context.target_activation,
            target_certified_activation_root: context.target_certified_activation_root,
            statement: StatementBytes(statement_bytes),
            statement_digest: statement.digest(),
            semantic_transition: statement.semantic_transition_digest(),
            local_ack: None,
            acknowledgements: BTreeMap::new(),
            certificate: None,
            installed_certificate: None,
            ack_recipients: Vec::new(),
            certificate_recipients: Vec::new(),
            installed_and_reclaimed: false,
            terminal: false,
        })
    }

    fn statement(&self) -> Result<DepositStateImportedStatement, DepositStateImportStoreError> {
        Ok(DepositStateImportedStatement::from_bytes(&self.statement.0)?)
    }

    fn validate_durable(
        &self,
        context: &DepositStateImportStoreContext,
    ) -> Result<DepositStateImportedStatement, DepositStateImportStoreError> {
        if self.version != DEPOSIT_STATE_IMPORT_STORE_VERSION
            || self.domain != DEPOSIT_STATE_IMPORT_STORE_DOMAIN
            || self.network != context.network
            || self.wallet != context.wallet
            || self.local_party != context.local_party
            || self.target_epoch != context.target_epoch
            || self.target_committee != context.target_committee
            || self.target_fault_bound != context.target_fault_bound
            || self.target_key_id != context.target_key_id
            || self.target_group_key != context.target_group_key
            || self.target_activation != context.target_activation
            || self.target_certified_activation_root != context.target_certified_activation_root
            || self.statement_digest == [0; 32]
            || self.semantic_transition == [0; 32]
            || self.acknowledgements.len() > MAX_COMMITTEE_MEMBERS
            || self.ack_recipients.len() > MAX_COMMITTEE_MEMBERS.saturating_sub(1)
            || self.certificate_recipients.len() > MAX_DEPOSIT_STATE_IMPORT_CERTIFICATE_RECIPIENTS
            || self.installed_and_reclaimed != self.installed_certificate.is_some()
            || self.installed_certificate.is_some() && self.certificate.is_none()
            || self.installed_and_reclaimed && self.local_ack.is_none()
            || self.installed_and_reclaimed && !self.ack_recipients.is_empty()
            || !self.ack_recipients.is_empty() && self.local_ack.is_none()
            || !self.certificate_recipients.is_empty() && self.certificate.is_none()
            || self.terminal
                && (!self.installed_and_reclaimed
                    || self.certificate.is_none()
                    || self.ack_recipients.iter().any(|recipient| recipient.receipt.is_none())
                    || self
                        .certificate_recipients
                        .iter()
                        .any(|recipient| recipient.receipt.is_none()))
        {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }

        let statement = self.statement()?;
        if statement.network() != context.network
            || statement.wallet() != context.wallet
            || statement.target_epoch() != context.target_epoch
            || statement.target_committee().digest() != context.target_committee
            || statement.target_activation() != context.target_activation
            || statement.target_certified_activation_root()
                != context.target_certified_activation_root
            || statement.digest() != self.statement_digest
            || statement.semantic_transition_digest() != self.semantic_transition
        {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }

        for (party, bytes) in &self.acknowledgements {
            let ack = DepositStateImportedAck::from_bytes(&statement, &bytes.0)?;
            if ack.signer() != *party {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
        }
        if let Some(bytes) = &self.local_ack {
            let ack = DepositStateImportedAck::from_bytes(&statement, &bytes.0)?;
            if ack.signer() != context.local_party {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
            if !self.terminal && self.acknowledgements.get(&context.local_party) != Some(bytes) {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
        }
        if let Some(bytes) = &self.certificate
            && self.terminal
        {
            let certificate = DepositStateImportedCertificate::from_bytes(&bytes.0)?;
            if certificate.statement() != &statement {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
        } else if let Some(bytes) = &self.certificate {
            validate_embedded_certificate(bytes, &statement, &self.acknowledgements)?;
        }
        if let Some(DurableInstalledCertificate::Distinct(bytes)) = &self.installed_certificate {
            if self.terminal {
                let certificate = DepositStateImportedCertificate::from_bytes(&bytes.0)?;
                if certificate.statement() != &statement {
                    return Err(DepositStateImportStoreError::InvalidDurableState);
                }
            } else {
                validate_embedded_certificate(bytes, &statement, &self.acknowledgements)?;
            }
        }

        let mut previous_ack_recipient = None;
        for recipient in &self.ack_recipients {
            recipient.validate_static()?;
            if recipient.recipient == context.local_party
                || previous_ack_recipient.is_some_and(|previous| previous >= recipient.recipient)
            {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
            previous_ack_recipient = Some(recipient.recipient);
        }
        let mut previous_certificate_recipient = None;
        for recipient in &self.certificate_recipients {
            recipient.validate_static()?;
            if previous_certificate_recipient
                .is_some_and(|previous| previous >= recipient.recipient)
            {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
            previous_certificate_recipient = Some(recipient.recipient);
        }
        Ok(statement)
    }

    fn validate_for(
        &self,
        context: &DepositStateImportStoreContext,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateImportStoreError> {
        let durable_statement = self.validate_durable(context)?;
        let requested = completed.statement();
        if &durable_statement != requested {
            return Err(DepositStateImportStoreError::Equivocation {
                durable_statement: durable_statement.digest(),
                requested_statement: requested.digest(),
            });
        }
        validate_completed_target(context, completed, target)?;

        let required = required_acknowledgements(target)?;
        match &self.certificate {
            Some(_) => {
                let _ = reconstruct_certificate(self, completed, target)?;
            }
            None if self.acknowledgements.len() >= required => {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
            None => {}
        }
        if self.local_ack.is_some() && !self.installed_and_reclaimed {
            let acknowledgement = local_ack(self, completed.statement())?;
            let expected = expected_ack_recipients(context, completed.statement(), target, self)?;
            validate_exact_ack_recipients(&self.ack_recipients, &expected)?;
            for recipient in &self.ack_recipients {
                recipient.delivery(completed.statement(), &acknowledgement)?;
            }
        }
        if !self.certificate_recipients.is_empty() {
            let certificate = reconstruct_installed_certificate(self, completed, target)?
                .ok_or(DepositStateImportStoreError::InvalidDurableState)?;
            for recipient in &self.certificate_recipients {
                recipient.delivery(&certificate, context.local_party)?;
            }
        }
        Ok(())
    }

    fn next_revision(&self) -> Result<u64, DepositStateImportStoreError> {
        self.revision.checked_add(1).ok_or(DepositStateImportStoreError::RevisionExhausted)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DepositStateImportStoreContext {
    network: [u8; 32],
    wallet: DepositWalletId,
    local_party: PartyId,
    target_epoch: u64,
    target_committee: [u8; 32],
    target_fault_bound: u16,
    target_key_id: [u8; 32],
    target_group_key: [u8; 32],
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
}

impl DepositStateImportStoreContext {
    fn for_target_member(
        network: [u8; 32],
        wallet: DepositWalletId,
        target: &VerifiedRegistryHandoffTarget,
        local_party: PartyId,
    ) -> Result<Self, DepositStateImportStoreError> {
        target.committee().validate_async_security_with_faults(target.fault_bound())?;
        target.committee().member(local_party)?;
        if network == [0; 32] || wallet.0 == [0; 32] || target.wallet() != wallet {
            return Err(DepositStateImportStoreError::WrongAuthority);
        }
        Ok(Self {
            network,
            wallet,
            local_party,
            target_epoch: target.committee().epoch,
            target_committee: target.committee().digest(),
            target_fault_bound: target.fault_bound(),
            target_key_id: target.key_id(),
            target_group_key: target.group_key(),
            target_activation: target.activation(),
            target_certified_activation_root: target.certified_activation_root(),
        })
    }

    fn new(
        network: [u8; 32],
        wallet: DepositWalletId,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<Self, DepositStateImportStoreError> {
        let context = Self::for_target_member(network, wallet, target, identity.party())?;
        let member = target.committee().member(identity.party())?;
        if identity.encryption_epoch() != target.committee().epoch
            || member.signing_key != identity.signing_public_key()
            || member.encryption_key != identity.encryption_public_key()
        {
            return Err(DepositStateImportStoreError::WrongAuthority);
        }
        Ok(context)
    }

    fn validate_current(
        &self,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<(), DepositStateImportStoreError> {
        let current = Self::new(self.network, self.wallet, target, identity)?;
        if current != *self {
            return Err(DepositStateImportStoreError::WrongAuthority);
        }
        Ok(())
    }

    fn validate_target_member(
        &self,
        target: &VerifiedRegistryHandoffTarget,
        local_party: PartyId,
    ) -> Result<(), DepositStateImportStoreError> {
        let current = Self::for_target_member(self.network, self.wallet, target, local_party)?;
        if current != *self {
            return Err(DepositStateImportStoreError::WrongAuthority);
        }
        Ok(())
    }
}

/// Stable progress of the local target-member journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepositStateImportStorePhase {
    Empty,
    Collecting,
    Certified,
    InstalledAndReclaimed,
    Terminal,
}

/// Stable, non-authorizing route for one exact target-availability transmission.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct DepositStateImportWorkLocator {
    kind: DepositStateImportWorkKind,
    slot: WalletId,
    network: [u8; 32],
    wallet: DepositWalletId,
    sender: PartyId,
    recipient: PartyId,
    target_epoch: u64,
    transition_binding: [u8; 32],
    statement: [u8; 32],
    primary: [u8; 32],
    delivery: [u8; 32],
    binding: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum DepositStateImportWorkKind {
    AcknowledgementDelivery,
    CertificateDelivery,
}

impl DepositStateImportWorkKind {
    const fn tag(self) -> u8 {
        match self {
            Self::AcknowledgementDelivery => 1,
            Self::CertificateDelivery => 2,
        }
    }
}

impl DepositStateImportWorkLocator {
    fn new(
        context: &DepositStateImportStoreContext,
        kind: DepositStateImportWorkKind,
        recipient: PartyId,
        transition_binding: [u8; 32],
        statement: [u8; 32],
        primary: [u8; 32],
        delivery: [u8; 32],
    ) -> Result<Self, DepositStateImportStoreError> {
        let mut locator = Self {
            kind,
            slot: target_slot(context),
            network: context.network,
            wallet: context.wallet,
            sender: context.local_party,
            recipient,
            target_epoch: context.target_epoch,
            transition_binding,
            statement,
            primary,
            delivery,
            binding: [0; 32],
        };
        locator.validate_shape()?;
        locator.binding = locator.expected_binding();
        if locator.binding == [0; 32] {
            return Err(DepositStateImportStoreError::KeyDerivation);
        }
        Ok(locator)
    }

    fn expected_binding(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DEPOSIT_STATE_IMPORT_WORK_LOCATOR_DOMAIN);
        hasher.update(&[self.kind.tag()]);
        hasher.update(&self.slot.0);
        hasher.update(&self.network);
        hasher.update(&self.wallet.0);
        hasher.update(&self.sender.0.to_le_bytes());
        hasher.update(&self.recipient.0.to_le_bytes());
        hasher.update(&self.target_epoch.to_le_bytes());
        hasher.update(&self.transition_binding);
        hasher.update(&self.statement);
        hasher.update(&self.primary);
        hasher.update(&self.delivery);
        *hasher.finalize().as_bytes()
    }

    fn validate_shape(&self) -> Result<(), DepositStateImportStoreError> {
        if self.slot.0 == [0; 32]
            || self.network == [0; 32]
            || self.wallet.0 == [0; 32]
            || self.sender == PartyId(0)
            || self.recipient == PartyId(0)
            || self.target_epoch == 0
            || self.transition_binding == [0; 32]
            || self.statement == [0; 32]
            || self.primary == [0; 32]
            || self.delivery == [0; 32]
            || self.kind == DepositStateImportWorkKind::AcknowledgementDelivery
                && self.sender == self.recipient
        {
            return Err(DepositStateImportStoreError::InvalidWorkLocator);
        }
        Ok(())
    }

    fn validate(
        &self,
        store: &DepositStateImportStore,
        statement: &DepositStateImportedStatement,
    ) -> Result<(), DepositStateImportStoreError> {
        self.validate_shape()?;
        if self.binding == [0; 32]
            || self.binding != self.expected_binding()
            || self.slot != store.slot
            || self.network != store.context.network
            || self.wallet != store.context.wallet
            || self.sender != store.context.local_party
            || self.target_epoch != store.context.target_epoch
            || self.transition_binding != statement.transition_binding()
            || self.statement != statement.digest()
        {
            return Err(DepositStateImportStoreError::InvalidWorkLocator);
        }
        Ok(())
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> DepositStateImportWorkKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn network(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub(crate) const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub(crate) const fn sender(&self) -> PartyId {
        self.sender
    }

    #[must_use]
    pub(crate) const fn recipient(&self) -> PartyId {
        self.recipient
    }

    #[must_use]
    pub(crate) const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    #[must_use]
    pub(crate) const fn transition_binding(&self) -> [u8; 32] {
        self.transition_binding
    }

    #[must_use]
    pub(crate) const fn statement_digest(&self) -> [u8; 32] {
        self.statement
    }

    #[must_use]
    pub(crate) const fn primary_digest(&self) -> [u8; 32] {
        self.primary
    }

    #[must_use]
    pub(crate) const fn delivery_digest(&self) -> [u8; 32] {
        self.delivery
    }
}

/// Whether an authenticated acknowledgement changed durable collection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepositStateImportAckRecord {
    Recorded(DepositStateImportStoreStatus),
    AlreadyRecorded(DepositStateImportStoreStatus),
}

impl DepositStateImportAckRecord {
    #[must_use]
    pub const fn status(self) -> DepositStateImportStoreStatus {
        match self {
            Self::Recorded(status) | Self::AlreadyRecorded(status) => status,
        }
    }

    #[must_use]
    pub const fn was_recorded(self) -> bool {
        matches!(self, Self::Recorded(_))
    }
}

/// Whether the service's exact durable install/reclaim was newly journaled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepositStateImportInstallRecord {
    Installed(DepositStateImportStoreStatus),
    AlreadyInstalled(DepositStateImportStoreStatus),
}

impl DepositStateImportInstallRecord {
    #[must_use]
    pub const fn status(self) -> DepositStateImportStoreStatus {
        match self {
            Self::Installed(status) | Self::AlreadyInstalled(status) => status,
        }
    }

    #[must_use]
    pub const fn was_installed(self) -> bool {
        matches!(self, Self::Installed(_))
    }

    #[cfg(test)]
    pub(crate) const fn installed_for_test(certificate_digest: [u8; 32]) -> Self {
        Self::Installed(DepositStateImportStoreStatus {
            phase: DepositStateImportStorePhase::InstalledAndReclaimed,
            acknowledgements: 3,
            required_acknowledgements: 3,
            has_local_acknowledgement: true,
            certificate_digest: Some(certificate_digest),
            installed_certificate_digest: Some(certificate_digest),
        })
    }
}

/// Authority-checked summary of one target slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositStateImportStoreStatus {
    phase: DepositStateImportStorePhase,
    acknowledgements: usize,
    required_acknowledgements: usize,
    has_local_acknowledgement: bool,
    /// Digest of the first locally frozen exact `n-f` certificate.
    certificate_digest: Option<[u8; 32]>,
    /// Digest of the first exact certificate used by the durable install/reclaim effect.
    installed_certificate_digest: Option<[u8; 32]>,
}

impl DepositStateImportStoreStatus {
    #[must_use]
    pub const fn phase(&self) -> DepositStateImportStorePhase {
        self.phase
    }

    #[must_use]
    pub const fn acknowledgements(&self) -> usize {
        self.acknowledgements
    }

    #[must_use]
    pub const fn required_acknowledgements(&self) -> usize {
        self.required_acknowledgements
    }

    #[must_use]
    pub const fn has_local_acknowledgement(&self) -> bool {
        self.has_local_acknowledgement
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> Option<[u8; 32]> {
        self.certificate_digest
    }

    #[must_use]
    pub const fn installed_certificate_digest(&self) -> Option<[u8; 32]> {
        self.installed_certificate_digest
    }
}

/// Fully re-authenticated restart view of one target slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositStateImportStoreRecovery {
    status: DepositStateImportStoreStatus,
    local_acknowledgement: Option<DepositStateImportedAck>,
    acknowledgements: Vec<DepositStateImportedAck>,
    certificate: Option<DepositStateImportedCertificate>,
    installed_certificate: Option<DepositStateImportedCertificate>,
}

impl DepositStateImportStoreRecovery {
    #[must_use]
    pub const fn status(&self) -> DepositStateImportStoreStatus {
        self.status
    }

    #[must_use]
    pub const fn local_acknowledgement(&self) -> Option<&DepositStateImportedAck> {
        self.local_acknowledgement.as_ref()
    }

    #[must_use]
    pub fn acknowledgements(&self) -> &[DepositStateImportedAck] {
        &self.acknowledgements
    }

    #[must_use]
    pub const fn certificate(&self) -> Option<&DepositStateImportedCertificate> {
        self.certificate.as_ref()
    }

    #[must_use]
    pub const fn installed_certificate(&self) -> Option<&DepositStateImportedCertificate> {
        self.installed_certificate.as_ref()
    }
}

/// One encrypted, exact-CAS target-import journal.
pub struct DepositStateImportStore {
    snapshots: WalletSnapshotStore,
    slot: WalletId,
    context: DepositStateImportStoreContext,
    mutation: Arc<Mutex<()>>,
}

/// Certificate-only view of an already-installed target import journal.
///
/// This wrapper is intentionally unable to sign or record ACKs, install a certificate, or mutate
/// any pre-final state. It is reopened from stable party identity plus the exact authenticated
/// historical target after the retired epoch's full [`Identity`] has been erased.
pub(crate) struct InstalledDepositStateImportStore {
    store: DepositStateImportStore,
}

impl fmt::Debug for DepositStateImportStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DepositStateImportStore")
            .field("wallet", &self.context.wallet)
            .field("local_party", &self.context.local_party)
            .field("target_epoch", &self.context.target_epoch)
            .finish_non_exhaustive()
    }
}

impl DepositStateImportStore {
    fn from_context(
        directory: impl Into<PathBuf>,
        context: DepositStateImportStoreContext,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DepositStateImportStoreError> {
        let slot = target_slot(&context);
        let mutation = slot_mutation(slot)?;
        Ok(Self {
            snapshots: WalletSnapshotStore::new(directory, context.local_party, identity_seed)?,
            slot,
            context,
            mutation,
        })
    }

    /// Open the one restart-derivable journal slot for the current target.
    ///
    /// # Errors
    ///
    /// Returns an error if the network/wallet is invalid, the target is malformed, the supplied
    /// identity is not the target member's current full identity, or storage key derivation fails.
    pub fn open(
        directory: impl Into<PathBuf>,
        network: [u8; 32],
        wallet: DepositWalletId,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DepositStateImportStoreError> {
        let context = DepositStateImportStoreContext::new(network, wallet, target, identity)?;
        Self::from_context(directory, context, identity_seed)
    }

    /// Persist the exact local ACK before returning it, or replay its original canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale authority, a conflicting statement in this target slot,
    /// malformed durable state, signing failure, or a failed exact-CAS/readback.
    pub async fn sign_or_replay_ack(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<DepositStateImportedAck, DepositStateImportStoreError> {
        self.validate_authority(completed, target, identity)?;
        let _guard = self.mutation.lock().await;
        let mut state = match self.load().await? {
            Some(state) => {
                state.validate_for(&self.context, completed, target)?;
                state
            }
            None => DurableDepositStateImport::new(&self.context, completed)?,
        };

        if let Some(bytes) = &state.local_ack {
            return Ok(DepositStateImportedAck::from_bytes(completed.statement(), &bytes.0)?);
        }
        if state.terminal {
            return Err(DepositStateImportStoreError::WorkAlreadyComplete);
        }

        let acknowledgement = DepositStateImportedAck::sign(completed, identity)?;
        let bytes = AckBytes(acknowledgement.to_bytes(completed.statement())?);
        state.local_ack = Some(bytes.clone());
        match state.acknowledgements.get(&identity.party()) {
            Some(existing) if existing != &bytes => {
                return Err(DepositStateImportStoreError::ConflictingAcknowledgement(
                    identity.party(),
                ));
            }
            Some(_) => {}
            None => {
                state.acknowledgements.insert(identity.party(), bytes);
            }
        }
        self.initialize_ack_recipients(&mut state, completed, target)?;
        self.seal_certificate_if_ready(&mut state, completed, target)?;
        let state = self.persist_successor(state).await?;
        let bytes =
            state.local_ack.as_ref().ok_or(DepositStateImportStoreError::InvalidDurableState)?;
        Ok(DepositStateImportedAck::from_bytes(completed.statement(), &bytes.0)?)
    }

    /// Verify and persist one distinct target ACK, sealing an exact `n-f` certificate atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale authority, an invalid or conflicting acknowledgement, a
    /// conflicting target-slot statement, malformed durable state, or storage failure.
    pub async fn record_ack(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
        authenticated_signer: PartyId,
        acknowledgement: &DepositStateImportedAck,
    ) -> Result<DepositStateImportAckRecord, DepositStateImportStoreError> {
        self.validate_authority(completed, target, identity)?;
        let canonical = AckBytes(acknowledgement.to_bytes(completed.statement())?);
        let signer = acknowledgement.signer();
        if authenticated_signer != signer {
            return Err(DepositStateImportStoreError::WrongAuthenticatedSigner {
                authenticated: authenticated_signer,
                acknowledgement: signer,
            });
        }
        let _guard = self.mutation.lock().await;
        let mut state = match self.load().await? {
            Some(state) => state,
            None => DurableDepositStateImport::new(&self.context, completed)?,
        };
        state.validate_for(&self.context, completed, target)?;
        if durable_ack_is_exact(&state, completed.statement(), signer, &canonical)? {
            let status = self.status_for_state(Some(&state), completed, target)?;
            return Ok(DepositStateImportAckRecord::AlreadyRecorded(status));
        }

        let mut changed = false;
        if signer == self.context.local_party {
            match &state.local_ack {
                Some(existing) if existing == &canonical => {}
                Some(_) => {
                    return Err(DepositStateImportStoreError::ConflictingAcknowledgement(signer));
                }
                None => return Err(DepositStateImportStoreError::UnjournaledLocalAcknowledgement),
            }
        }
        match state.acknowledgements.get(&signer) {
            Some(existing) if existing != &canonical => {
                return Err(DepositStateImportStoreError::ConflictingAcknowledgement(signer));
            }
            Some(_) => {}
            None => {
                state.acknowledgements.insert(signer, canonical.clone());
                changed = true;
            }
        }
        changed |= self.seal_certificate_if_ready(&mut state, completed, target)?;
        if changed {
            state = self.persist_successor(state).await?;
        }
        let status = self.status_for_state(Some(&state), completed, target)?;
        Ok(if changed {
            DepositStateImportAckRecord::Recorded(status)
        } else {
            DepositStateImportAckRecord::AlreadyRecorded(status)
        })
    }

    /// Reconstruct and reverify the durable canonical certificate, if one has been sealed.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale authority, conflicting statement, malformed durable
    /// acknowledgement/certificate bytes, or storage failure.
    pub async fn certificate(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<Option<DepositStateImportedCertificate>, DepositStateImportStoreError> {
        self.validate_authority(completed, target, identity)?;
        let _guard = self.mutation.lock().await;
        let Some(state) = self.load().await? else {
            return Ok(None);
        };
        state.validate_for(&self.context, completed, target)?;
        reconstruct_certificate(&state, completed, target)
    }

    /// Enumerate this member's unacknowledged target-to-target ACK deliveries.
    pub(crate) async fn pending_ack_deliveries(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        identity: &Identity,
    ) -> Result<Vec<DepositStateImportWorkLocator>, DepositStateImportStoreError> {
        self.validate_outbound_authority(completed, target, source, handoff, identity)?;
        let _guard = self.mutation.lock().await;
        let state = self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        state.validate_for(&self.context, completed, target)?;
        if state.installed_and_reclaimed {
            return Ok(Vec::new());
        }
        let expected =
            expected_ack_recipients(&self.context, completed.statement(), target, &state)?;
        validate_exact_ack_recipients(&state.ack_recipients, &expected)?;
        pending_ack_locators(&self.context, completed.statement(), &state.ack_recipients)
    }

    /// Reconstruct one exact ACK delivery from its non-authorizing locator.
    pub(crate) async fn ack_delivery_for_locator(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        identity: &Identity,
        locator: DepositStateImportWorkLocator,
    ) -> Result<DepositStateImportedAckDelivery, DepositStateImportStoreError> {
        self.validate_outbound_authority(completed, target, source, handoff, identity)?;
        locator.validate(self, completed.statement())?;
        if locator.kind != DepositStateImportWorkKind::AcknowledgementDelivery {
            return Err(DepositStateImportStoreError::InvalidWorkLocator);
        }
        let _guard = self.mutation.lock().await;
        let state = self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        state.validate_for(&self.context, completed, target)?;
        if state.installed_and_reclaimed {
            return Err(DepositStateImportStoreError::WorkAlreadyComplete);
        }
        let expected =
            expected_ack_recipients(&self.context, completed.statement(), target, &state)?;
        validate_exact_ack_recipients(&state.ack_recipients, &expected)?;
        let recipient = find_ack_recipient(&state, locator.recipient)?;
        if recipient.receipt.is_some() {
            return Err(DepositStateImportStoreError::WorkAlreadyComplete);
        }
        if ack_locator(&self.context, completed.statement(), recipient)? != locator {
            return Err(DepositStateImportStoreError::InvalidWorkLocator);
        }
        let acknowledgement = local_ack(&state, completed.statement())?;
        recipient.delivery(completed.statement(), &acknowledgement)
    }

    /// Persist one authenticated recipient's exact ACK-delivery receipt tombstone.
    pub(crate) async fn acknowledge_ack_delivery(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        identity: &Identity,
        authenticated_recipient: PartyId,
        locator: DepositStateImportWorkLocator,
        receipt: DepositStateImportedAckReceipt,
    ) -> Result<(), DepositStateImportStoreError> {
        self.validate_outbound_authority(completed, target, source, handoff, identity)?;
        locator.validate(self, completed.statement())?;
        if locator.kind != DepositStateImportWorkKind::AcknowledgementDelivery
            || authenticated_recipient != locator.recipient
        {
            return Err(DepositStateImportStoreError::WrongReceiptPeer);
        }
        let _guard = self.mutation.lock().await;
        let mut state =
            self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        state.validate_for(&self.context, completed, target)?;
        if state.installed_and_reclaimed {
            return Err(DepositStateImportStoreError::WorkAlreadyComplete);
        }
        let expected =
            expected_ack_recipients(&self.context, completed.statement(), target, &state)?;
        validate_exact_ack_recipients(&state.ack_recipients, &expected)?;
        let index = state
            .ack_recipients
            .binary_search_by_key(&locator.recipient, |recipient| recipient.recipient)
            .map_err(|_| DepositStateImportStoreError::InvalidWorkLocator)?;
        let recipient = state.ack_recipients[index];
        if ack_locator(&self.context, completed.statement(), &recipient)? != locator {
            return Err(DepositStateImportStoreError::InvalidWorkLocator);
        }
        let acknowledgement = local_ack(&state, completed.statement())?;
        let delivery = recipient.delivery(completed.statement(), &acknowledgement)?;
        receipt.to_bytes(&delivery, completed.statement())?;
        match recipient.receipt {
            Some(existing) if existing == receipt => return Ok(()),
            Some(_) => return Err(DepositStateImportStoreError::ConflictingReceipt),
            None => {}
        }
        state.ack_recipients[index].receipt = Some(receipt);
        self.persist_successor(state).await?;
        Ok(())
    }

    /// Initialize exact old∪target certificate fanout after the installed certificate is durable.
    pub(crate) async fn prepare_certificate_fanout(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<Vec<DepositStateImportWorkLocator>, DepositStateImportStoreError> {
        let certificate = self.validate_terminal_authority(
            installed,
            source,
            handoff,
            target_registry,
            target,
            identity,
        )?;
        self.prepare_certificate_fanout_authorized(certificate, source, target).await
    }

    async fn prepare_certificate_fanout_authorized(
        &self,
        certificate: DepositStateImportedCertificate,
        source: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Vec<DepositStateImportWorkLocator>, DepositStateImportStoreError> {
        let _guard = self.mutation.lock().await;
        let mut state =
            self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        validate_terminal_state(&state, &self.context, &certificate)?;
        let expected =
            expected_certificate_recipients(&self.context, &certificate, source, target)?;
        if state.terminal {
            validate_exact_certificate_recipients(&state.certificate_recipients, &expected)?;
            return Ok(Vec::new());
        }
        if state.certificate_recipients.is_empty() {
            state.certificate_recipients = expected;
            state = self.persist_successor(state).await?;
        } else {
            validate_exact_certificate_recipients(&state.certificate_recipients, &expected)?;
        }
        pending_certificate_locators(
            &self.context,
            certificate.statement(),
            &state.certificate_recipients,
        )
    }

    /// Re-enumerate unacknowledged exact certificate deliveries after restart.
    pub(crate) async fn pending_certificate_deliveries(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<Vec<DepositStateImportWorkLocator>, DepositStateImportStoreError> {
        let certificate = self.validate_terminal_authority(
            installed,
            source,
            handoff,
            target_registry,
            target,
            identity,
        )?;
        self.pending_certificate_deliveries_authorized(certificate, source, target).await
    }

    async fn pending_certificate_deliveries_authorized(
        &self,
        certificate: DepositStateImportedCertificate,
        source: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Vec<DepositStateImportWorkLocator>, DepositStateImportStoreError> {
        let _guard = self.mutation.lock().await;
        let state = self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        validate_terminal_state(&state, &self.context, &certificate)?;
        let expected =
            expected_certificate_recipients(&self.context, &certificate, source, target)?;
        if state.terminal {
            validate_exact_certificate_recipients(&state.certificate_recipients, &expected)?;
            return Ok(Vec::new());
        }
        if state.certificate_recipients.is_empty() {
            return Err(DepositStateImportStoreError::FanoutNotPrepared);
        }
        validate_exact_certificate_recipients(&state.certificate_recipients, &expected)?;
        pending_certificate_locators(
            &self.context,
            certificate.statement(),
            &state.certificate_recipients,
        )
    }

    /// Reconstruct one exact old∪target certificate delivery.
    pub(crate) async fn certificate_delivery_for_locator(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
        locator: DepositStateImportWorkLocator,
    ) -> Result<DepositStateImportedCertificateDelivery, DepositStateImportStoreError> {
        let certificate = self.validate_terminal_authority(
            installed,
            source,
            handoff,
            target_registry,
            target,
            identity,
        )?;
        self.certificate_delivery_for_locator_authorized(certificate, source, target, locator).await
    }

    async fn certificate_delivery_for_locator_authorized(
        &self,
        certificate: DepositStateImportedCertificate,
        source: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        locator: DepositStateImportWorkLocator,
    ) -> Result<DepositStateImportedCertificateDelivery, DepositStateImportStoreError> {
        locator.validate(self, certificate.statement())?;
        if locator.kind != DepositStateImportWorkKind::CertificateDelivery {
            return Err(DepositStateImportStoreError::InvalidWorkLocator);
        }
        let _guard = self.mutation.lock().await;
        let state = self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        validate_terminal_state(&state, &self.context, &certificate)?;
        let expected =
            expected_certificate_recipients(&self.context, &certificate, source, target)?;
        validate_exact_certificate_recipients(&state.certificate_recipients, &expected)?;
        let recipient = find_certificate_recipient(&state, locator.recipient)?;
        if recipient.receipt.is_some() {
            return Err(DepositStateImportStoreError::WorkAlreadyComplete);
        }
        if certificate_locator(&self.context, certificate.statement(), recipient)? != locator {
            return Err(DepositStateImportStoreError::InvalidWorkLocator);
        }
        recipient.delivery(&certificate, self.context.local_party)
    }

    /// Persist one authenticated old/target recipient's exact certificate receipt tombstone.
    pub(crate) async fn acknowledge_certificate_delivery(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
        authenticated_recipient: PartyId,
        locator: DepositStateImportWorkLocator,
        receipt: DepositStateImportedCertificateReceipt,
    ) -> Result<(), DepositStateImportStoreError> {
        let certificate = self.validate_terminal_authority(
            installed,
            source,
            handoff,
            target_registry,
            target,
            identity,
        )?;
        self.acknowledge_certificate_delivery_authorized(
            certificate,
            source,
            target,
            authenticated_recipient,
            locator,
            receipt,
        )
        .await
    }

    async fn acknowledge_certificate_delivery_authorized(
        &self,
        certificate: DepositStateImportedCertificate,
        source: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        authenticated_recipient: PartyId,
        locator: DepositStateImportWorkLocator,
        receipt: DepositStateImportedCertificateReceipt,
    ) -> Result<(), DepositStateImportStoreError> {
        locator.validate(self, certificate.statement())?;
        if locator.kind != DepositStateImportWorkKind::CertificateDelivery
            || authenticated_recipient != locator.recipient
        {
            return Err(DepositStateImportStoreError::WrongReceiptPeer);
        }
        let _guard = self.mutation.lock().await;
        let mut state =
            self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        validate_terminal_state(&state, &self.context, &certificate)?;
        if authenticated_recipient == self.context.local_party && !state.installed_and_reclaimed {
            return Err(DepositStateImportStoreError::LocalInstallIncomplete);
        }
        let expected =
            expected_certificate_recipients(&self.context, &certificate, source, target)?;
        validate_exact_certificate_recipients(&state.certificate_recipients, &expected)?;
        let index = state
            .certificate_recipients
            .binary_search_by_key(&locator.recipient, |recipient| recipient.recipient)
            .map_err(|_| DepositStateImportStoreError::InvalidWorkLocator)?;
        let recipient = state.certificate_recipients[index];
        if certificate_locator(&self.context, certificate.statement(), &recipient)? != locator {
            return Err(DepositStateImportStoreError::InvalidWorkLocator);
        }
        let delivery = recipient.delivery(&certificate, self.context.local_party)?;
        receipt.to_bytes(&delivery)?;
        if receipt.disposition() == DepositStateImportedCertificateDisposition::Deferred {
            // Only the transport attempt completed. Never persist a deferral as an install ACK,
            // even after restart or through the historical certificate-only store wrapper.
            return Ok(());
        }
        match recipient.receipt {
            Some(existing) if existing == receipt => return Ok(()),
            Some(_) => return Err(DepositStateImportStoreError::ConflictingReceipt),
            None => {}
        }
        state.certificate_recipients[index].receipt = Some(receipt);
        self.persist_successor(state).await?;
        Ok(())
    }

    /// Compact a fully disseminated installed-certificate slot to exact durable evidence.
    pub(crate) async fn terminalize_availability(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<bool, DepositStateImportStoreError> {
        let certificate = self.validate_terminal_authority(
            installed,
            source,
            handoff,
            target_registry,
            target,
            identity,
        )?;
        self.terminalize_availability_authorized(certificate, source, target).await
    }

    async fn terminalize_availability_authorized(
        &self,
        certificate: DepositStateImportedCertificate,
        source: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<bool, DepositStateImportStoreError> {
        let _guard = self.mutation.lock().await;
        let mut state =
            self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        validate_terminal_state(&state, &self.context, &certificate)?;
        if state.terminal {
            return Ok(false);
        }
        let expected =
            expected_certificate_recipients(&self.context, &certificate, source, target)?;
        validate_exact_certificate_recipients(&state.certificate_recipients, &expected)?;
        if state.certificate_recipients.iter().any(|recipient| recipient.receipt.is_none()) {
            return Err(DepositStateImportStoreError::FanoutIncomplete);
        }
        state.acknowledgements.clear();
        state.terminal = true;
        self.persist_successor(state).await?;
        Ok(true)
    }

    /// Journal completion only after the fenced wallet certificate intent and retention reclaim.
    ///
    /// The service must commit this record before its final wallet CAS clears pending markers and
    /// opens readiness. Post-final wallet bytes are never authority to synthesize this marker.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied certificate does not verify for the completed import, it
    /// exposes an unjournaled local ACK, authority is stale, or the final exact-CAS/readback fails.
    pub async fn mark_installed(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
        installed: &VerifiedStateImportedCertificate,
    ) -> Result<DepositStateImportInstallRecord, DepositStateImportStoreError> {
        self.validate_authority(completed, target, identity)?;
        let supplied = DepositStateImportedCertificate::from_bytes(installed.certificate_bytes())?;
        let supplied_verified = supplied.verify_completed_import(completed, target)?;
        if supplied_verified.certificate_bytes() != installed.certificate_bytes()
            || supplied_verified.certificate_digest() != installed.certificate_digest()
        {
            return Err(DepositStateImportStoreError::WrongCertificate);
        }
        let _guard = self.mutation.lock().await;
        let mut state = match self.load().await? {
            Some(state) => state,
            None => DurableDepositStateImport::new(&self.context, completed)?,
        };
        state.validate_for(&self.context, completed, target)?;
        if state.local_ack.is_none() {
            return Err(DepositStateImportStoreError::UnjournaledLocalAcknowledgement);
        }
        if state.installed_and_reclaimed {
            let durable = reconstruct_installed_certificate(&state, completed, target)?
                .ok_or(DepositStateImportStoreError::InvalidDurableState)?;
            if durable.to_bytes()? != supplied.to_bytes()? {
                return Err(DepositStateImportStoreError::ConflictingCertificate);
            }
            let status = self.status_for_state(Some(&state), completed, target)?;
            return Ok(DepositStateImportInstallRecord::AlreadyInstalled(status));
        }

        for acknowledgement in supplied.acknowledgements() {
            let signer = acknowledgement.signer();
            let bytes = AckBytes(acknowledgement.to_bytes(completed.statement())?);
            if signer == self.context.local_party {
                match &state.local_ack {
                    Some(local) if local == &bytes => {}
                    Some(_) => {
                        return Err(DepositStateImportStoreError::ConflictingAcknowledgement(
                            signer,
                        ));
                    }
                    None => {
                        return Err(DepositStateImportStoreError::UnjournaledLocalAcknowledgement);
                    }
                }
            }
            match state.acknowledgements.get(&signer) {
                Some(existing) if existing != &bytes => {
                    return Err(DepositStateImportStoreError::ConflictingAcknowledgement(signer));
                }
                Some(_) => {}
                None => {
                    state.acknowledgements.insert(signer, bytes);
                }
            }
        }
        let supplied_bytes = CertificateBytes(supplied.to_bytes()?);
        let installed_certificate = match state.certificate.as_ref() {
            Some(existing) if existing == &supplied_bytes => DurableInstalledCertificate::Canonical,
            Some(_) => DurableInstalledCertificate::Distinct(supplied_bytes),
            None => {
                state.certificate = Some(supplied_bytes);
                DurableInstalledCertificate::Canonical
            }
        };
        state.installed_certificate = Some(installed_certificate);
        state.installed_and_reclaimed = true;
        // The exact installed certificate supersedes target-to-target ACK availability. Drop that
        // transport-only outbox atomically with the local install marker so finalization never
        // depends on a completed-import capability which the wallet final CAS erases.
        state.ack_recipients.clear();
        state = self.persist_successor(state).await?;
        state.validate_for(&self.context, completed, target)?;
        let status = self.status_for_state(Some(&state), completed, target)?;
        Ok(DepositStateImportInstallRecord::Installed(status))
    }

    /// Reverify and recover post-final semantic certificate authority without a completed-import
    /// token.
    pub(crate) async fn recover_installed_certificate(
        &self,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<Option<VerifiedStateImportedCertificate>, DepositStateImportStoreError> {
        self.context.validate_current(target, identity)?;
        self.recover_installed_certificate_authorized(source, handoff, target_registry, target)
            .await
    }

    async fn recover_installed_certificate_authorized(
        &self,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<VerifiedStateImportedCertificate>, DepositStateImportStoreError> {
        let _guard = self.mutation.lock().await;
        let Some(state) = self.load().await? else {
            return Ok(None);
        };
        let statement = state.validate_durable(&self.context)?;
        if !state.installed_and_reclaimed {
            return Ok(None);
        }
        let certificate =
            DepositStateImportedCertificate::from_bytes(&installed_certificate_bytes(&state)?.0)?;
        if certificate.statement() != &statement {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }
        Ok(Some(certificate.verify(source, handoff, target_registry, target)?))
    }

    /// Semantically record a late exact target ACK after finalization, without reconstructing
    /// [`VerifiedDepositStateImport`]. `true` means this call added new durable evidence.
    pub(crate) async fn record_finalized_ack(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
        authenticated_signer: PartyId,
        acknowledgement: &DepositStateImportedAck,
    ) -> Result<bool, DepositStateImportStoreError> {
        let installed_certificate = self.validate_terminal_authority(
            installed,
            source,
            handoff,
            target_registry,
            target,
            identity,
        )?;
        let signer = acknowledgement.verify(installed_certificate.statement())?;
        if signer != authenticated_signer {
            return Err(DepositStateImportStoreError::WrongAuthenticatedSigner {
                authenticated: authenticated_signer,
                acknowledgement: signer,
            });
        }
        let canonical = AckBytes(acknowledgement.to_bytes(installed_certificate.statement())?);
        let _guard = self.mutation.lock().await;
        let mut state =
            self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        validate_terminal_state(&state, &self.context, &installed_certificate)?;
        if durable_ack_is_exact(&state, installed_certificate.statement(), signer, &canonical)? {
            return Ok(false);
        }
        if signer == self.context.local_party {
            return Err(DepositStateImportStoreError::UnjournaledLocalAcknowledgement);
        }
        match state.acknowledgements.get(&signer) {
            Some(existing) if existing == &canonical => return Ok(false),
            Some(_) => {
                return Err(DepositStateImportStoreError::ConflictingAcknowledgement(signer));
            }
            None => {}
        }
        state.acknowledgements.insert(signer, canonical);
        self.persist_successor(state).await?;
        Ok(true)
    }

    /// Validate a late alternate `n-f` certificate as the same already-installed semantic state.
    ///
    /// The incoming witness representation is not allowed to replace the exact certificate which
    /// crossed the local wallet CAS.
    pub(crate) async fn validate_finalized_certificate_ingress(
        &self,
        installed: &VerifiedStateImportedCertificate,
        incoming: &DepositStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<(), DepositStateImportStoreError> {
        let installed_certificate = self.validate_terminal_authority(
            installed,
            source,
            handoff,
            target_registry,
            target,
            identity,
        )?;
        self.validate_finalized_certificate_ingress_authorized(
            installed_certificate,
            incoming,
            source,
            handoff,
            target_registry,
            target,
        )
        .await
    }

    async fn validate_finalized_certificate_ingress_authorized(
        &self,
        installed_certificate: DepositStateImportedCertificate,
        incoming: &DepositStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateImportStoreError> {
        incoming.verify(source, handoff, target_registry, target)?;
        if incoming.statement() != installed_certificate.statement() {
            return Err(DepositStateImportStoreError::WrongCertificate);
        }
        let _guard = self.mutation.lock().await;
        let state = self.load().await?.ok_or(DepositStateImportStoreError::UnknownImportSlot)?;
        validate_terminal_state(&state, &self.context, &installed_certificate)
    }

    /// Recover every typed artifact after re-authenticating the current non-serial authority.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, a conflicting statement, malformed durable state,
    /// failed certificate reconstruction, or storage failure.
    pub async fn recover(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<DepositStateImportStoreRecovery, DepositStateImportStoreError> {
        self.validate_authority(completed, target, identity)?;
        let _guard = self.mutation.lock().await;
        let state = self.load().await?;
        if let Some(state) = &state {
            state.validate_for(&self.context, completed, target)?;
        }
        self.recovery_for_state(state.as_ref(), completed, target)
    }

    /// Return an authority-checked bounded progress summary.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, a conflicting statement, malformed durable state,
    /// failed certificate reconstruction, or storage failure.
    pub async fn status(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<DepositStateImportStoreStatus, DepositStateImportStoreError> {
        self.validate_authority(completed, target, identity)?;
        let _guard = self.mutation.lock().await;
        let state = self.load().await?;
        if let Some(state) = &state {
            state.validate_for(&self.context, completed, target)?;
        }
        self.status_for_state(state.as_ref(), completed, target)
    }

    fn validate_authority(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<(), DepositStateImportStoreError> {
        self.context.validate_current(target, identity)?;
        validate_completed_target(&self.context, completed, target)
    }

    fn validate_outbound_authority(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        identity: &Identity,
    ) -> Result<(), DepositStateImportStoreError> {
        self.validate_authority(completed, target, identity)?;
        validate_completed_source_handoff(completed, target, source, handoff)
    }

    fn validate_terminal_authority(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<DepositStateImportedCertificate, DepositStateImportStoreError> {
        self.context.validate_current(target, identity)?;
        self.validate_terminal_certificate(installed, source, handoff, target_registry, target)
    }

    fn validate_terminal_certificate(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositStateImportedCertificate, DepositStateImportStoreError> {
        let certificate =
            DepositStateImportedCertificate::from_bytes(installed.certificate_bytes())?;
        let verified = certificate.verify(source, handoff, target_registry, target)?;
        if verified.certificate_bytes() != installed.certificate_bytes()
            || verified.certificate_digest() != installed.certificate_digest()
            || verified.network() != self.context.network
            || verified.wallet() != self.context.wallet
            || verified.target_epoch() != self.context.target_epoch
            || verified.target_committee_digest() != self.context.target_committee
        {
            return Err(DepositStateImportStoreError::WrongCertificate);
        }
        Ok(certificate)
    }

    fn seal_certificate_if_ready(
        &self,
        state: &mut DurableDepositStateImport,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<bool, DepositStateImportStoreError> {
        if state.certificate.is_some() {
            return Ok(false);
        }
        let required = required_acknowledgements(target)?;
        if state.acknowledgements.len() < required {
            return Ok(false);
        }
        let acknowledgements = state
            .acknowledgements
            .values()
            .take(required)
            .map(|bytes| DepositStateImportedAck::from_bytes(completed.statement(), &bytes.0))
            .collect::<Result<Vec<_>, _>>()?;
        let certificate = DepositStateImportedCertificate::from_completed_import(
            completed,
            acknowledgements,
            target,
        )?;
        state.certificate = Some(CertificateBytes(certificate.to_bytes()?));
        Ok(true)
    }

    fn initialize_ack_recipients(
        &self,
        state: &mut DurableDepositStateImport,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<bool, DepositStateImportStoreError> {
        if state.terminal {
            return Ok(false);
        }
        let acknowledgement = state
            .local_ack
            .as_ref()
            .map(|bytes| DepositStateImportedAck::from_bytes(completed.statement(), &bytes.0))
            .transpose()?
            .ok_or(DepositStateImportStoreError::UnjournaledLocalAcknowledgement)?;
        let mut expected = target
            .committee()
            .members
            .iter()
            .map(|member| member.id)
            .filter(|recipient| *recipient != self.context.local_party)
            .map(|recipient| {
                DurableImportedAckRecipient::new(completed.statement(), &acknowledgement, recipient)
            })
            .collect::<Result<Vec<_>, _>>()?;
        expected.sort_by_key(|recipient| recipient.recipient);
        if state.ack_recipients.is_empty() {
            state.ack_recipients = expected;
            return Ok(true);
        }
        validate_exact_ack_recipients(&state.ack_recipients, &expected)?;
        Ok(false)
    }

    async fn load(
        &self,
    ) -> Result<Option<DurableDepositStateImport>, DepositStateImportStoreError> {
        let path = self.snapshots.wallet_snapshot_path(self.slot);
        match tokio::fs::symlink_metadata(&path).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let snapshot = self.snapshots.load_snapshot(self.slot).await?;
        let state = decode_state(snapshot.state.as_bytes())?;
        if state.revision != snapshot.metadata.revision {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }
        state.validate_durable(&self.context)?;
        Ok(Some(state))
    }

    async fn persist_successor(
        &self,
        mut state: DurableDepositStateImport,
    ) -> Result<DurableDepositStateImport, DepositStateImportStoreError> {
        let exists = tokio::fs::symlink_metadata(self.snapshots.wallet_snapshot_path(self.slot))
            .await
            .map_or_else(
                |error| {
                    if error.kind() == io::ErrorKind::NotFound { Ok(false) } else { Err(error) }
                },
                |_| Ok(true),
            )?;
        if exists {
            state.revision = state.next_revision()?;
        } else if state.revision != 0 {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }
        let bytes = encode_state(&state)?;
        let metadata =
            self.snapshots.save_snapshot(self.slot, state.revision, &bytes, &mut OsRng).await?;
        if metadata.revision != state.revision {
            return Err(DepositStateImportStoreError::StorageRevisionMismatch);
        }
        let stored = self.snapshots.load_snapshot(self.slot).await?;
        if stored.metadata.revision != state.revision || stored.state.as_bytes() != bytes {
            return Err(DepositStateImportStoreError::StorageRevisionMismatch);
        }
        let reopened = decode_state(stored.state.as_bytes())?;
        if reopened != state {
            return Err(DepositStateImportStoreError::StorageRevisionMismatch);
        }
        reopened.validate_durable(&self.context)?;
        Ok(reopened)
    }

    fn recovery_for_state(
        &self,
        state: Option<&DurableDepositStateImport>,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositStateImportStoreRecovery, DepositStateImportStoreError> {
        let status = self.status_for_state(state, completed, target)?;
        let Some(state) = state else {
            return Ok(DepositStateImportStoreRecovery {
                status,
                local_acknowledgement: None,
                acknowledgements: Vec::new(),
                certificate: None,
                installed_certificate: None,
            });
        };
        let local_acknowledgement = state
            .local_ack
            .as_ref()
            .map(|bytes| DepositStateImportedAck::from_bytes(completed.statement(), &bytes.0))
            .transpose()?;
        let acknowledgements = state
            .acknowledgements
            .values()
            .map(|bytes| DepositStateImportedAck::from_bytes(completed.statement(), &bytes.0))
            .collect::<Result<Vec<_>, _>>()?;
        let certificate = reconstruct_certificate(state, completed, target)?;
        let installed_certificate = reconstruct_installed_certificate(state, completed, target)?;
        Ok(DepositStateImportStoreRecovery {
            status,
            local_acknowledgement,
            acknowledgements,
            certificate,
            installed_certificate,
        })
    }

    fn status_for_state(
        &self,
        state: Option<&DurableDepositStateImport>,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositStateImportStoreStatus, DepositStateImportStoreError> {
        let required = required_acknowledgements(target)?;
        let Some(state) = state else {
            return Ok(DepositStateImportStoreStatus {
                phase: DepositStateImportStorePhase::Empty,
                acknowledgements: 0,
                required_acknowledgements: required,
                has_local_acknowledgement: false,
                certificate_digest: None,
                installed_certificate_digest: None,
            });
        };
        let certificate = reconstruct_certificate(state, completed, target)?;
        let certificate_digest = certificate
            .as_ref()
            .map(|certificate| {
                certificate
                    .verify_completed_import(completed, target)
                    .map(|verified| verified.certificate_digest())
            })
            .transpose()?;
        let installed_certificate_digest =
            reconstruct_installed_certificate(state, completed, target)?
                .as_ref()
                .map(|certificate| {
                    certificate
                        .verify_completed_import(completed, target)
                        .map(|verified| verified.certificate_digest())
                })
                .transpose()?;
        let phase = if state.terminal {
            DepositStateImportStorePhase::Terminal
        } else if state.installed_and_reclaimed {
            DepositStateImportStorePhase::InstalledAndReclaimed
        } else if certificate.is_some() {
            DepositStateImportStorePhase::Certified
        } else {
            DepositStateImportStorePhase::Collecting
        };
        Ok(DepositStateImportStoreStatus {
            phase,
            acknowledgements: if state.terminal { required } else { state.acknowledgements.len() },
            required_acknowledgements: required,
            has_local_acknowledgement: state.local_ack.is_some(),
            certificate_digest,
            installed_certificate_digest,
        })
    }
}

impl fmt::Debug for InstalledDepositStateImportStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstalledDepositStateImportStore")
            .field("wallet", &self.store.context.wallet)
            .field("local_party", &self.store.context.local_party)
            .field("target_epoch", &self.store.context.target_epoch)
            .finish_non_exhaustive()
    }
}

impl InstalledDepositStateImportStore {
    /// Reopen one exact historical target-member slot without retaining the retired full identity.
    ///
    /// Every exposed method first requires an exact installed certificate. The wrapper has no
    /// pre-final or acknowledgement surface, so stable party identity cannot become signing or
    /// installation authority.
    pub(crate) fn open(
        directory: impl Into<PathBuf>,
        network: [u8; 32],
        wallet: DepositWalletId,
        target: &VerifiedRegistryHandoffTarget,
        local_party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DepositStateImportStoreError> {
        let context = DepositStateImportStoreContext::for_target_member(
            network,
            wallet,
            target,
            local_party,
        )?;
        let member = target.committee().member(local_party)?;
        let signing_public = Identity::signing_public_key_from_seed(identity_seed)
            .map_err(|_| DepositStateImportStoreError::WrongAuthority)?;
        if member.signing_key != signing_public {
            return Err(DepositStateImportStoreError::WrongAuthority);
        }
        Ok(Self {
            store: DepositStateImportStore::from_context(directory, context, identity_seed)?,
        })
    }

    fn validate_target(
        &self,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateImportStoreError> {
        self.store.context.validate_target_member(target, self.store.context.local_party)
    }

    pub(crate) async fn recover_installed_certificate(
        &self,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<VerifiedStateImportedCertificate>, DepositStateImportStoreError> {
        self.validate_target(target)?;
        self.store
            .recover_installed_certificate_authorized(source, handoff, target_registry, target)
            .await
    }

    pub(crate) async fn prepare_certificate_fanout(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Vec<DepositStateImportWorkLocator>, DepositStateImportStoreError> {
        self.validate_target(target)?;
        let certificate = self.store.validate_terminal_certificate(
            installed,
            source,
            handoff,
            target_registry,
            target,
        )?;
        self.store.prepare_certificate_fanout_authorized(certificate, source, target).await
    }

    pub(crate) async fn pending_certificate_deliveries(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Vec<DepositStateImportWorkLocator>, DepositStateImportStoreError> {
        self.validate_target(target)?;
        let certificate = self.store.validate_terminal_certificate(
            installed,
            source,
            handoff,
            target_registry,
            target,
        )?;
        self.store.pending_certificate_deliveries_authorized(certificate, source, target).await
    }

    pub(crate) async fn certificate_delivery_for_locator(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        locator: DepositStateImportWorkLocator,
    ) -> Result<DepositStateImportedCertificateDelivery, DepositStateImportStoreError> {
        self.validate_target(target)?;
        let certificate = self.store.validate_terminal_certificate(
            installed,
            source,
            handoff,
            target_registry,
            target,
        )?;
        self.store
            .certificate_delivery_for_locator_authorized(certificate, source, target, locator)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn acknowledge_certificate_delivery(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        authenticated_recipient: PartyId,
        locator: DepositStateImportWorkLocator,
        receipt: DepositStateImportedCertificateReceipt,
    ) -> Result<(), DepositStateImportStoreError> {
        self.validate_target(target)?;
        let certificate = self.store.validate_terminal_certificate(
            installed,
            source,
            handoff,
            target_registry,
            target,
        )?;
        self.store
            .acknowledge_certificate_delivery_authorized(
                certificate,
                source,
                target,
                authenticated_recipient,
                locator,
                receipt,
            )
            .await
    }

    pub(crate) async fn terminalize_availability(
        &self,
        installed: &VerifiedStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<bool, DepositStateImportStoreError> {
        self.validate_target(target)?;
        let certificate = self.store.validate_terminal_certificate(
            installed,
            source,
            handoff,
            target_registry,
            target,
        )?;
        self.store.terminalize_availability_authorized(certificate, source, target).await
    }

    pub(crate) async fn validate_finalized_certificate_ingress(
        &self,
        installed: &VerifiedStateImportedCertificate,
        incoming: &DepositStateImportedCertificate,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateImportStoreError> {
        self.validate_target(target)?;
        let installed_certificate = self.store.validate_terminal_certificate(
            installed,
            source,
            handoff,
            target_registry,
            target,
        )?;
        self.store
            .validate_finalized_certificate_ingress_authorized(
                installed_certificate,
                incoming,
                source,
                handoff,
                target_registry,
                target,
            )
            .await
    }
}

fn validate_completed_source_handoff(
    completed: &VerifiedDepositStateImport,
    target: &VerifiedRegistryHandoffTarget,
    source: &CompactEpochRegistry,
    handoff: &RegistryHandoffCertificate,
) -> Result<(), DepositStateImportStoreError> {
    source.validate().map_err(DepositStateImportError::from)?;
    handoff.verify(source).map_err(DepositStateImportError::from)?;
    let statement = completed.statement();
    let transition = handoff.statement();
    if statement.wallet() != source.wallet()
        || source.active_epoch().checked_add(1) != Some(target.committee().epoch)
        || statement.target_epoch() != target.committee().epoch
        || statement.handoff_statement_digest() != transition.digest()
        || statement.handoff_export_context() != transition.export_capability_context()
        || transition.target_epoch() != target.committee().epoch
        || transition.target_key_id() != target.key_id()
        || transition.target_group_key() != target.group_key()
        || transition.target_committee() != target.committee().digest()
        || transition.target_fault_bound() != target.fault_bound()
        || transition.target_activation() != target.activation()
        || transition.target_certified_activation_root() != target.certified_activation_root()
    {
        return Err(DepositStateImportStoreError::WrongAuthority);
    }
    Ok(())
}

fn validate_terminal_state(
    state: &DurableDepositStateImport,
    context: &DepositStateImportStoreContext,
    certificate: &DepositStateImportedCertificate,
) -> Result<(), DepositStateImportStoreError> {
    let statement = state.validate_durable(context)?;
    let certificate_bytes = CertificateBytes(certificate.to_bytes()?);
    if &statement != certificate.statement()
        || !state.installed_and_reclaimed
        || installed_certificate_bytes(state)? != &certificate_bytes
    {
        return Err(DepositStateImportStoreError::InvalidDurableState);
    }
    for recipient in &state.certificate_recipients {
        recipient.delivery(certificate, context.local_party)?;
    }
    Ok(())
}

fn local_ack(
    state: &DurableDepositStateImport,
    statement: &DepositStateImportedStatement,
) -> Result<DepositStateImportedAck, DepositStateImportStoreError> {
    let bytes = state
        .local_ack
        .as_ref()
        .ok_or(DepositStateImportStoreError::UnjournaledLocalAcknowledgement)?;
    Ok(DepositStateImportedAck::from_bytes(statement, &bytes.0)?)
}

fn expected_ack_recipients(
    context: &DepositStateImportStoreContext,
    statement: &DepositStateImportedStatement,
    target: &VerifiedRegistryHandoffTarget,
    state: &DurableDepositStateImport,
) -> Result<Vec<DurableImportedAckRecipient>, DepositStateImportStoreError> {
    let acknowledgement = local_ack(state, statement)?;
    let mut recipients = target
        .committee()
        .members
        .iter()
        .map(|member| member.id)
        .filter(|recipient| *recipient != context.local_party)
        .map(|recipient| DurableImportedAckRecipient::new(statement, &acknowledgement, recipient))
        .collect::<Result<Vec<_>, _>>()?;
    recipients.sort_by_key(|recipient| recipient.recipient);
    Ok(recipients)
}

fn validate_exact_ack_recipients(
    actual: &[DurableImportedAckRecipient],
    expected: &[DurableImportedAckRecipient],
) -> Result<(), DepositStateImportStoreError> {
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(actual, expected)| {
            actual.recipient != expected.recipient
                || actual.acknowledgement_digest != expected.acknowledgement_digest
                || actual.delivery_digest != expected.delivery_digest
        })
    {
        return Err(DepositStateImportStoreError::ConflictingFanout);
    }
    Ok(())
}

fn ack_locator(
    context: &DepositStateImportStoreContext,
    statement: &DepositStateImportedStatement,
    recipient: &DurableImportedAckRecipient,
) -> Result<DepositStateImportWorkLocator, DepositStateImportStoreError> {
    DepositStateImportWorkLocator::new(
        context,
        DepositStateImportWorkKind::AcknowledgementDelivery,
        recipient.recipient,
        statement.transition_binding(),
        statement.digest(),
        recipient.acknowledgement_digest,
        recipient.delivery_digest,
    )
}

fn pending_ack_locators(
    context: &DepositStateImportStoreContext,
    statement: &DepositStateImportedStatement,
    recipients: &[DurableImportedAckRecipient],
) -> Result<Vec<DepositStateImportWorkLocator>, DepositStateImportStoreError> {
    recipients
        .iter()
        .filter(|recipient| recipient.receipt.is_none())
        .map(|recipient| ack_locator(context, statement, recipient))
        .collect()
}

fn find_ack_recipient(
    state: &DurableDepositStateImport,
    party: PartyId,
) -> Result<&DurableImportedAckRecipient, DepositStateImportStoreError> {
    let index = state
        .ack_recipients
        .binary_search_by_key(&party, |recipient| recipient.recipient)
        .map_err(|_| DepositStateImportStoreError::InvalidWorkLocator)?;
    Ok(&state.ack_recipients[index])
}

fn expected_certificate_recipients(
    context: &DepositStateImportStoreContext,
    certificate: &DepositStateImportedCertificate,
    source: &CompactEpochRegistry,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<Vec<DurableImportedCertificateRecipient>, DepositStateImportStoreError> {
    let recipients = source
        .active()
        .committee()
        .members
        .iter()
        .chain(target.committee().members.iter())
        .map(|member| member.id)
        .collect::<BTreeSet<_>>();
    if recipients.is_empty() || recipients.len() > MAX_DEPOSIT_STATE_IMPORT_CERTIFICATE_RECIPIENTS {
        return Err(DepositStateImportStoreError::InvalidDurableState);
    }
    recipients
        .into_iter()
        .map(|recipient| {
            DurableImportedCertificateRecipient::new(certificate, context.local_party, recipient)
        })
        .collect()
}

fn validate_exact_certificate_recipients(
    actual: &[DurableImportedCertificateRecipient],
    expected: &[DurableImportedCertificateRecipient],
) -> Result<(), DepositStateImportStoreError> {
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(actual, expected)| {
            actual.recipient != expected.recipient
                || actual.certificate_digest != expected.certificate_digest
                || actual.delivery_digest != expected.delivery_digest
        })
    {
        return Err(DepositStateImportStoreError::ConflictingFanout);
    }
    Ok(())
}

fn certificate_locator(
    context: &DepositStateImportStoreContext,
    statement: &DepositStateImportedStatement,
    recipient: &DurableImportedCertificateRecipient,
) -> Result<DepositStateImportWorkLocator, DepositStateImportStoreError> {
    DepositStateImportWorkLocator::new(
        context,
        DepositStateImportWorkKind::CertificateDelivery,
        recipient.recipient,
        statement.transition_binding(),
        statement.digest(),
        recipient.certificate_digest,
        recipient.delivery_digest,
    )
}

fn pending_certificate_locators(
    context: &DepositStateImportStoreContext,
    statement: &DepositStateImportedStatement,
    recipients: &[DurableImportedCertificateRecipient],
) -> Result<Vec<DepositStateImportWorkLocator>, DepositStateImportStoreError> {
    recipients
        .iter()
        .filter(|recipient| recipient.receipt.is_none())
        .map(|recipient| certificate_locator(context, statement, recipient))
        .collect()
}

fn find_certificate_recipient(
    state: &DurableDepositStateImport,
    party: PartyId,
) -> Result<&DurableImportedCertificateRecipient, DepositStateImportStoreError> {
    let index = state
        .certificate_recipients
        .binary_search_by_key(&party, |recipient| recipient.recipient)
        .map_err(|_| DepositStateImportStoreError::InvalidWorkLocator)?;
    Ok(&state.certificate_recipients[index])
}

fn validate_completed_target(
    context: &DepositStateImportStoreContext,
    completed: &VerifiedDepositStateImport,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<(), DepositStateImportStoreError> {
    let statement = completed.statement();
    if statement.network() != context.network
        || statement.wallet() != context.wallet
        || target.wallet() != context.wallet
        || statement.target_epoch() != context.target_epoch
        || statement.target_committee() != target.committee()
        || statement.target_committee().digest() != context.target_committee
        || target.fault_bound() != context.target_fault_bound
        || target.key_id() != context.target_key_id
        || target.group_key() != context.target_group_key
        || statement.target_activation() != context.target_activation
        || target.activation() != context.target_activation
        || statement.target_certified_activation_root() != context.target_certified_activation_root
        || target.certified_activation_root() != context.target_certified_activation_root
    {
        return Err(DepositStateImportStoreError::WrongAuthority);
    }
    Ok(())
}

fn required_acknowledgements(
    target: &VerifiedRegistryHandoffTarget,
) -> Result<usize, DepositStateImportStoreError> {
    target.committee().validate_async_security_with_faults(target.fault_bound())?;
    let required = target
        .committee()
        .n()
        .checked_sub(target.fault_bound())
        .ok_or(DepositStateImportStoreError::InvalidDurableState)?;
    Ok(usize::from(required))
}

fn validate_embedded_certificate(
    bytes: &CertificateBytes,
    statement: &DepositStateImportedStatement,
    acknowledgements: &BTreeMap<PartyId, AckBytes>,
) -> Result<(), DepositStateImportStoreError> {
    let certificate = DepositStateImportedCertificate::from_bytes(&bytes.0)?;
    if certificate.statement() != statement {
        return Err(DepositStateImportStoreError::InvalidDurableState);
    }
    for acknowledgement in certificate.acknowledgements() {
        let canonical = AckBytes(acknowledgement.to_bytes(statement)?);
        if acknowledgements.get(&acknowledgement.signer()) != Some(&canonical) {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }
    }
    Ok(())
}

/// Classify one exact ACK against every representation which can survive in the journal.
///
/// A certificate is itself durable ACK evidence. Treating terminal compaction as if it erased
/// that evidence could falsely report a replay as newly recorded; accepting a different valid
/// signature from the same signer would also violate first-wins equivocation semantics.
fn durable_ack_is_exact(
    state: &DurableDepositStateImport,
    statement: &DepositStateImportedStatement,
    signer: PartyId,
    candidate: &AckBytes,
) -> Result<bool, DepositStateImportStoreError> {
    let mut exact = false;
    let mut observe = |bytes: &AckBytes| -> Result<(), DepositStateImportStoreError> {
        if bytes != candidate {
            return Err(DepositStateImportStoreError::ConflictingAcknowledgement(signer));
        }
        exact = true;
        Ok(())
    };

    if let Some(bytes) = state.local_ack.as_ref() {
        let acknowledgement = DepositStateImportedAck::from_bytes(statement, &bytes.0)?;
        if acknowledgement.signer() == signer {
            observe(bytes)?;
        }
    }
    if let Some(bytes) = state.acknowledgements.get(&signer) {
        observe(bytes)?;
    }

    let mut observe_certificate =
        |bytes: &CertificateBytes| -> Result<(), DepositStateImportStoreError> {
            let certificate = DepositStateImportedCertificate::from_bytes(&bytes.0)?;
            if certificate.statement() != statement {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
            for acknowledgement in certificate
                .acknowledgements()
                .iter()
                .filter(|acknowledgement| acknowledgement.signer() == signer)
            {
                let bytes = AckBytes(acknowledgement.to_bytes(statement)?);
                observe(&bytes)?;
            }
            Ok(())
        };
    if let Some(bytes) = state.certificate.as_ref() {
        observe_certificate(bytes)?;
    }
    if let Some(DurableInstalledCertificate::Distinct(bytes)) = state.installed_certificate.as_ref()
    {
        observe_certificate(bytes)?;
    }
    Ok(exact)
}

fn reconstruct_certificate(
    state: &DurableDepositStateImport,
    completed: &VerifiedDepositStateImport,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<Option<DepositStateImportedCertificate>, DepositStateImportStoreError> {
    reconstruct_certificate_bytes(state, state.certificate.as_ref(), completed, target)
}

fn reconstruct_installed_certificate(
    state: &DurableDepositStateImport,
    completed: &VerifiedDepositStateImport,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<Option<DepositStateImportedCertificate>, DepositStateImportStoreError> {
    if !state.installed_and_reclaimed {
        return Ok(None);
    }
    let bytes = match state
        .installed_certificate
        .as_ref()
        .ok_or(DepositStateImportStoreError::InvalidDurableState)?
    {
        DurableInstalledCertificate::Canonical => state.certificate.as_ref(),
        DurableInstalledCertificate::Distinct(bytes) => Some(bytes),
    };
    reconstruct_certificate_bytes(state, bytes, completed, target)
}

fn installed_certificate_bytes(
    state: &DurableDepositStateImport,
) -> Result<&CertificateBytes, DepositStateImportStoreError> {
    match state
        .installed_certificate
        .as_ref()
        .ok_or(DepositStateImportStoreError::InvalidDurableState)?
    {
        DurableInstalledCertificate::Canonical => {
            state.certificate.as_ref().ok_or(DepositStateImportStoreError::InvalidDurableState)
        }
        DurableInstalledCertificate::Distinct(bytes) => Ok(bytes),
    }
}

fn reconstruct_certificate_bytes(
    state: &DurableDepositStateImport,
    stored_bytes: Option<&CertificateBytes>,
    completed: &VerifiedDepositStateImport,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<Option<DepositStateImportedCertificate>, DepositStateImportStoreError> {
    let Some(stored_bytes) = stored_bytes else {
        return Ok(None);
    };
    let stored = DepositStateImportedCertificate::from_bytes(&stored_bytes.0)?;
    if state.terminal {
        stored.verify_completed_import(completed, target)?;
        if stored.to_bytes()? != stored_bytes.0 {
            return Err(DepositStateImportStoreError::InvalidDurableState);
        }
        return Ok(Some(stored));
    }
    let acknowledgements = stored
        .acknowledgements()
        .iter()
        .map(|stored_ack| {
            let bytes = state
                .acknowledgements
                .get(&stored_ack.signer())
                .ok_or(DepositStateImportStoreError::InvalidDurableState)?;
            let ack = DepositStateImportedAck::from_bytes(completed.statement(), &bytes.0)?;
            if &ack != stored_ack {
                return Err(DepositStateImportStoreError::InvalidDurableState);
            }
            Ok(ack)
        })
        .collect::<Result<Vec<_>, DepositStateImportStoreError>>()?;
    let reconstructed = DepositStateImportedCertificate::from_completed_import(
        completed,
        acknowledgements,
        target,
    )?;
    reconstructed.verify_completed_import(completed, target)?;
    if reconstructed.to_bytes()? != stored_bytes.0 {
        return Err(DepositStateImportStoreError::InvalidDurableState);
    }
    Ok(Some(reconstructed))
}

fn target_slot(context: &DepositStateImportStoreContext) -> WalletId {
    let mut hasher = blake3::Hasher::new_derive_key(DEPOSIT_STATE_IMPORT_SLOT_DOMAIN);
    hasher.update(&DEPOSIT_STATE_IMPORT_STORE_VERSION.to_le_bytes());
    hasher.update(&context.network);
    hasher.update(&context.wallet.0);
    hasher.update(&context.local_party.0.to_le_bytes());
    hasher.update(&context.target_epoch.to_le_bytes());
    WalletId(*hasher.finalize().as_bytes())
}

fn slot_mutation(slot: WalletId) -> Result<Arc<Mutex<()>>, DepositStateImportStoreError> {
    let registry = SLOT_MUTATIONS.get_or_init(|| StdMutex::new(BTreeMap::new()));
    let mut registry =
        registry.lock().map_err(|_| DepositStateImportStoreError::MutationRegistryPoisoned)?;
    if let Some(mutation) = registry.get(&slot).and_then(Weak::upgrade) {
        return Ok(mutation);
    }
    registry.retain(|_, mutation| mutation.strong_count() != 0);
    let mutation = Arc::new(Mutex::new(()));
    registry.insert(slot, Arc::downgrade(&mutation));
    Ok(mutation)
}

fn encode_state(
    state: &DurableDepositStateImport,
) -> Result<Vec<u8>, DepositStateImportStoreError> {
    let bytes =
        postcard::to_allocvec(state).map_err(|_| DepositStateImportStoreError::Serialization)?;
    if bytes.len() > MAX_DEPOSIT_STATE_IMPORT_STORE_BYTES {
        return Err(DepositStateImportStoreError::StateTooLarge {
            actual: bytes.len(),
            maximum: MAX_DEPOSIT_STATE_IMPORT_STORE_BYTES,
        });
    }
    Ok(bytes)
}

fn decode_state(bytes: &[u8]) -> Result<DurableDepositStateImport, DepositStateImportStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_DEPOSIT_STATE_IMPORT_STORE_BYTES {
        return Err(DepositStateImportStoreError::StateTooLarge {
            actual: bytes.len(),
            maximum: MAX_DEPOSIT_STATE_IMPORT_STORE_BYTES,
        });
    }
    let (state, trailing) = postcard::take_from_bytes(bytes)
        .map_err(|_| DepositStateImportStoreError::Serialization)?;
    if !trailing.is_empty() {
        return Err(DepositStateImportStoreError::TrailingBytes(trailing.len()));
    }
    if postcard::to_allocvec(&state).map_err(|_| DepositStateImportStoreError::Serialization)?
        != bytes
    {
        return Err(DepositStateImportStoreError::NonCanonicalEncoding);
    }
    Ok(state)
}

fn deserialize_bounded_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, D::Error> {
    struct BoundedBytesVisitor {
        maximum: usize,
        kind: &'static str,
    }

    impl<'de> Visitor<'de> for BoundedBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {} bytes for {}", self.maximum, self.kind)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > self.maximum) {
                return Err(A::Error::custom(format_args!("{} exceeds its bound", self.kind)));
            }
            let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == self.maximum {
                    return Err(A::Error::custom(format_args!("{} exceeds its bound", self.kind)));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }

        fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
            if value.len() > self.maximum {
                return Err(E::custom(format_args!("{} exceeds its bound", self.kind)));
            }
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E: DeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            if value.len() > self.maximum {
                return Err(E::custom(format_args!("{} exceeds its bound", self.kind)));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_seq(BoundedBytesVisitor { maximum, kind })
}

fn deserialize_acknowledgements<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<PartyId, AckBytes>, D::Error> {
    struct AckMapVisitor;

    impl<'de> Visitor<'de> for AckMapVisitor {
        type Value = BTreeMap<PartyId, AckBytes>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_COMMITTEE_MEMBERS} unique acknowledgements")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            if map.size_hint().is_some_and(|length| length > MAX_COMMITTEE_MEMBERS) {
                return Err(A::Error::custom("too many state-import acknowledgements"));
            }
            let mut acknowledgements = BTreeMap::new();
            while let Some((party, acknowledgement)) = map.next_entry()? {
                if acknowledgements.len() == MAX_COMMITTEE_MEMBERS {
                    return Err(A::Error::custom("too many state-import acknowledgements"));
                }
                if acknowledgements.insert(party, acknowledgement).is_some() {
                    return Err(A::Error::custom("duplicate state-import acknowledgement signer"));
                }
            }
            Ok(acknowledgements)
        }
    }

    deserializer.deserialize_map(AckMapVisitor)
}

fn deserialize_imported_ack_recipients<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DurableImportedAckRecipient>, D::Error> {
    deserialize_bounded_sequence(
        deserializer,
        MAX_COMMITTEE_MEMBERS.saturating_sub(1),
        "too many state-import ACK delivery recipients",
    )
}

fn deserialize_imported_certificate_recipients<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DurableImportedCertificateRecipient>, D::Error> {
    deserialize_bounded_sequence(
        deserializer,
        MAX_DEPOSIT_STATE_IMPORT_CERTIFICATE_RECIPIENTS,
        "too many state-import certificate recipients",
    )
}

fn deserialize_bounded_sequence<'de, D, T>(
    deserializer: D,
    maximum: usize,
    expectation: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedSequenceVisitor<T> {
        maximum: usize,
        expectation: &'static str,
        marker: std::marker::PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for BoundedSequenceVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.expectation)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > self.maximum) {
                return Err(A::Error::custom(self.expectation));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.maximum {
                    return Err(A::Error::custom(self.expectation));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedSequenceVisitor {
        maximum,
        expectation,
        marker: std::marker::PhantomData,
    })
}

#[derive(Debug, Error)]
pub enum DepositStateImportStoreError {
    #[error("storage error: {0}")]
    Storage(#[from] StoreError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("deposit state-import error: {0}")]
    StateImport(#[from] DepositStateImportError),
    #[error("deposit state-transfer wire error: {0}")]
    Wire(#[from] DepositStateTransferWireError),
    #[error("committee error: {0}")]
    Committee(#[from] crate::committee::CommitteeError),
    #[error(
        "the target authority or local identity/storage seed does not match this import journal"
    )]
    WrongAuthority,
    #[error(
        "target slot already signed statement {durable_statement:?}, conflicting with {requested_statement:?}"
    )]
    Equivocation { durable_statement: [u8; 32], requested_statement: [u8; 32] },
    #[error("party {0} supplied a second acknowledgement encoding")]
    ConflictingAcknowledgement(PartyId),
    #[error(
        "transport authenticated party {authenticated}, but the acknowledgement names {acknowledgement}"
    )]
    WrongAuthenticatedSigner { authenticated: PartyId, acknowledgement: PartyId },
    #[error("the local acknowledgement was not created by the persist-before-return signer")]
    UnjournaledLocalAcknowledgement,
    #[error("the supplied verified certificate does not reconstruct for this completed import")]
    WrongCertificate,
    #[error("a different canonical availability certificate is already frozen")]
    ConflictingCertificate,
    #[error("target-availability work locator is malformed or belongs to another exact slot")]
    InvalidWorkLocator,
    #[error("target-availability work is already durably complete")]
    WorkAlreadyComplete,
    #[error("target-availability receipt came from the wrong authenticated QUIC recipient")]
    WrongReceiptPeer,
    #[error("target-availability receipt conflicts with its durable tombstone")]
    ConflictingReceipt,
    #[error("target-availability fanout conflicts with the exact committee union")]
    ConflictingFanout,
    #[error("target-availability certificate fanout has not been prepared")]
    FanoutNotPrepared,
    #[error("target-availability fanout still has unacknowledged recipients")]
    FanoutIncomplete,
    #[error("the local import/install/reclaim effect is not durably complete")]
    LocalInstallIncomplete,
    #[error("the target import journal slot does not exist")]
    UnknownImportSlot,
    #[error("target-availability work locator key derivation failed")]
    KeyDerivation,
    #[error("deposit state-import journal is malformed or context-mismatched")]
    InvalidDurableState,
    #[error("deposit state-import journal revision exhausted")]
    RevisionExhausted,
    #[error("deposit state-import journal readback did not match its exact CAS write")]
    StorageRevisionMismatch,
    #[error("deposit state-import journal mutation registry was poisoned")]
    MutationRegistryPoisoned,
    #[error("deposit state-import journal serialization failed")]
    Serialization,
    #[error("deposit state-import journal has {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("deposit state-import journal encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("deposit state-import journal has {actual} bytes; maximum is {maximum}")]
    StateTooLarge { actual: usize, maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(epoch: u64, tag: u8) -> DepositStateImportStoreContext {
        DepositStateImportStoreContext {
            network: [0x11; 32],
            wallet: DepositWalletId([0x12; 32]),
            local_party: PartyId(3),
            target_epoch: epoch,
            target_committee: [tag; 32],
            target_fault_bound: 1,
            target_key_id: [tag.wrapping_add(1); 32],
            target_group_key: [tag.wrapping_add(2); 32],
            target_activation: [tag.wrapping_add(3); 32],
            target_certified_activation_root: [tag.wrapping_add(4); 32],
        }
    }

    fn durable() -> DurableDepositStateImport {
        let context = context(7, 0x21);
        DurableDepositStateImport {
            version: DEPOSIT_STATE_IMPORT_STORE_VERSION,
            domain: DEPOSIT_STATE_IMPORT_STORE_DOMAIN,
            revision: 4,
            network: context.network,
            wallet: context.wallet,
            local_party: context.local_party,
            target_epoch: context.target_epoch,
            target_committee: context.target_committee,
            target_fault_bound: context.target_fault_bound,
            target_key_id: context.target_key_id,
            target_group_key: context.target_group_key,
            target_activation: context.target_activation,
            target_certified_activation_root: context.target_certified_activation_root,
            statement: StatementBytes(vec![1]),
            statement_digest: [0x31; 32],
            semantic_transition: [0x32; 32],
            local_ack: None,
            acknowledgements: BTreeMap::new(),
            certificate: None,
            installed_certificate: None,
            ack_recipients: Vec::new(),
            certificate_recipients: Vec::new(),
            installed_and_reclaimed: false,
            terminal: false,
        }
    }

    #[test]
    fn target_slot_is_unique_per_network_wallet_party_and_epoch() {
        let first = context(7, 0x21);
        let same_slot_different_authenticated_target = context(7, 0x51);
        let successor = context(8, 0x21);
        assert_eq!(target_slot(&first), target_slot(&same_slot_different_authenticated_target));
        assert_ne!(target_slot(&first), target_slot(&successor));
    }

    #[test]
    fn installed_store_reopen_requires_the_historical_members_stable_signing_seed() {
        use crate::committee::{Committee, Member};

        let local_seed = [0x31; 32];
        let local_signing = Identity::signing_public_key_from_seed(&local_seed).unwrap();
        let committee = Committee {
            epoch: 7,
            threshold: 2,
            members: vec![
                Member { id: PartyId(1), signing_key: local_signing, encryption_key: [0x41; 32] },
                Member { id: PartyId(2), signing_key: [0x42; 32], encryption_key: [0x52; 32] },
                Member { id: PartyId(3), signing_key: [0x43; 32], encryption_key: [0x53; 32] },
                Member { id: PartyId(4), signing_key: [0x44; 32], encryption_key: [0x54; 32] },
            ],
        };
        let wallet = DepositWalletId([0x61; 32]);
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee, 1, [0x62; 32], [0x63; 32], wallet, [0x64; 32], [0x65; 32],
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();

        assert!(
            InstalledDepositStateImportStore::open(
                directory.path(),
                [0x66; 32],
                wallet,
                &target,
                PartyId(1),
                &local_seed,
            )
            .is_ok()
        );
        assert!(matches!(
            InstalledDepositStateImportStore::open(
                directory.path(),
                [0x66; 32],
                wallet,
                &target,
                PartyId(1),
                &[0x32; 32],
            ),
            Err(DepositStateImportStoreError::WrongAuthority)
        ));
    }

    #[test]
    fn durable_encoding_is_exact_and_rejects_trailing_bytes() {
        let state = durable();
        let bytes = encode_state(&state).unwrap();
        assert_eq!(decode_state(&bytes).unwrap(), state);

        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            decode_state(&trailing),
            Err(DepositStateImportStoreError::TrailingBytes(1))
        ));
    }

    #[test]
    fn durable_decoder_bounds_ack_count_before_collection() {
        let mut state = durable();
        for party in 1..=u16::try_from(MAX_COMMITTEE_MEMBERS + 1).unwrap() {
            state
                .acknowledgements
                .insert(PartyId(party), AckBytes(vec![u8::try_from(party).unwrap()]));
        }
        let bytes = encode_state(&state).unwrap();
        assert!(matches!(decode_state(&bytes), Err(DepositStateImportStoreError::Serialization)));
    }

    #[test]
    fn durable_decoder_bounds_each_ack_before_allocation() {
        let mut state = durable();
        state
            .acknowledgements
            .insert(PartyId(1), AckBytes(vec![0x41; MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES + 1]));
        let bytes = encode_state(&state).unwrap();
        assert!(matches!(decode_state(&bytes), Err(DepositStateImportStoreError::Serialization)));
    }

    #[test]
    fn durable_decoder_bounds_certificate_recipient_fanout() {
        let mut state = durable();
        for party in 1..=u16::try_from(MAX_DEPOSIT_STATE_IMPORT_CERTIFICATE_RECIPIENTS + 1).unwrap()
        {
            state.certificate_recipients.push(DurableImportedCertificateRecipient {
                recipient: PartyId(party),
                certificate_digest: [0x51; 32],
                delivery_digest: [u8::try_from(party).unwrap(); 32],
                receipt: None,
            });
        }
        let bytes = encode_state(&state).unwrap();
        assert!(matches!(decode_state(&bytes), Err(DepositStateImportStoreError::Serialization)));
    }

    #[test]
    fn work_locator_binds_every_route_projection() {
        let context = context(7, 0x61);
        let locator = DepositStateImportWorkLocator::new(
            &context,
            DepositStateImportWorkKind::CertificateDelivery,
            PartyId(8),
            [0x62; 32],
            [0x63; 32],
            [0x64; 32],
            [0x65; 32],
        )
        .unwrap();
        assert_eq!(locator.network(), context.network);
        assert_eq!(locator.wallet(), context.wallet);
        assert_eq!(locator.sender(), context.local_party);
        assert_eq!(locator.recipient(), PartyId(8));
        assert_eq!(locator.target_epoch(), context.target_epoch);
        assert_eq!(locator.transition_binding(), [0x62; 32]);
        assert_eq!(locator.statement_digest(), [0x63; 32]);
        assert_eq!(locator.primary_digest(), [0x64; 32]);
        assert_eq!(locator.delivery_digest(), [0x65; 32]);
        assert_eq!(locator.binding, locator.expected_binding());

        let mut spliced = locator;
        spliced.recipient = PartyId(9);
        assert_ne!(spliced.binding, spliced.expected_binding());
    }

    #[test]
    fn installed_certificate_deduplicates_only_the_exact_canonical_body() {
        let mut state = durable();
        state.certificate = Some(CertificateBytes(vec![0x71, 0x72]));
        state.installed_certificate = Some(DurableInstalledCertificate::Canonical);
        state.installed_and_reclaimed = true;
        assert_eq!(installed_certificate_bytes(&state).unwrap().0.as_slice(), &[0x71, 0x72]);

        state.installed_certificate =
            Some(DurableInstalledCertificate::Distinct(CertificateBytes(vec![0x73, 0x74])));
        assert_eq!(installed_certificate_bytes(&state).unwrap().0.as_slice(), &[0x73, 0x74]);
    }

    #[tokio::test]
    async fn deferred_certificate_receipt_preserves_exact_outbox_across_restart() {
        use crate::deposit_state_transfer_wire::tests::{
            export_evidence_fixture, seal_certificate_for,
        };

        let fixture = export_evidence_fixture().await;
        let seal = seal_certificate_for(&fixture, &[PartyId(1), PartyId(2), PartyId(3)])
            .verify(&fixture.source, &fixture.handoff)
            .unwrap();
        let completed = VerifiedDepositStateImport::from_verified_export_seal_for_test(
            fixture.network,
            &fixture.source,
            &fixture.handoff,
            &fixture.target,
            &seal,
        )
        .unwrap();
        let identity = |party: PartyId| {
            let mut seed = [u8::try_from(party.0).unwrap(); 32];
            seed[0] ^= 1;
            let mut secret = [0x58; 32];
            secret[1..9].copy_from_slice(&1_u64.to_le_bytes());
            secret[9..11].copy_from_slice(&party.0.to_le_bytes());
            Identity::from_test_secrets(party, 1, &seed, secret).unwrap()
        };
        let certificate = DepositStateImportedCertificate::new(
            completed.statement().clone(),
            [PartyId(1), PartyId(2), PartyId(3)]
                .into_iter()
                .map(|party| DepositStateImportedAck::sign(&completed, &identity(party)).unwrap())
                .collect(),
            &fixture.source,
            &fixture.handoff,
            fixture.evidence.advertisement().unwrap().registry_archive().registry(),
            &fixture.target,
        )
        .unwrap();
        let installed = certificate.verify_completed_import(&completed, &fixture.target).unwrap();
        let local = identity(PartyId(1));
        let directory = tempfile::tempdir().unwrap();
        let open = || {
            DepositStateImportStore::open(
                directory.path(),
                fixture.network,
                fixture.source.wallet(),
                &fixture.target,
                &local,
                &[0x71; 32],
            )
            .unwrap()
        };
        let store = open();
        store.sign_or_replay_ack(&completed, &fixture.target, &local).await.unwrap();
        store.mark_installed(&completed, &fixture.target, &local, &installed).await.unwrap();
        let pending = store
            .prepare_certificate_fanout_authorized(
                certificate.clone(),
                &fixture.source,
                &fixture.target,
            )
            .await
            .unwrap();
        let locator = *pending.iter().find(|locator| locator.recipient() == PartyId(2)).unwrap();
        let delivery = DepositStateImportedCertificateDelivery::new(
            certificate.clone(),
            local.party(),
            locator.recipient(),
        )
        .unwrap();
        let deferred = DepositStateImportedCertificateReceipt::issue(
            &delivery,
            DepositStateImportedCertificateDisposition::Deferred,
        )
        .unwrap();
        let bytes = deferred.to_bytes(&delivery).unwrap();
        assert_eq!(
            DepositStateImportedCertificateReceipt::from_bytes(&delivery, &bytes).unwrap(),
            deferred
        );
        let wrong_delivery = DepositStateImportedCertificateDelivery::new(
            certificate.clone(),
            local.party(),
            PartyId(3),
        )
        .unwrap();
        assert!(
            DepositStateImportedCertificateReceipt::from_bytes(&wrong_delivery, &bytes).is_err()
        );
        let before = store.load().await.unwrap().unwrap();
        for reopened in [store, open()] {
            reopened
                .acknowledge_certificate_delivery_authorized(
                    certificate.clone(),
                    &fixture.source,
                    &fixture.target,
                    locator.recipient(),
                    locator,
                    deferred,
                )
                .await
                .unwrap();
            assert_eq!(reopened.load().await.unwrap().unwrap(), before);
            assert_eq!(
                reopened
                    .pending_certificate_deliveries_authorized(
                        certificate.clone(),
                        &fixture.source,
                        &fixture.target,
                    )
                    .await
                    .unwrap(),
                pending
            );
            assert!(matches!(
                reopened
                    .terminalize_availability_authorized(
                        certificate.clone(),
                        &fixture.source,
                        &fixture.target,
                    )
                    .await,
                Err(DepositStateImportStoreError::FanoutIncomplete)
            ));
        }
        let mut forged = before.clone();
        forged
            .certificate_recipients
            .iter_mut()
            .find(|recipient| recipient.recipient == locator.recipient())
            .unwrap()
            .receipt = Some(deferred);
        assert!(validate_terminal_state(&forged, &open().context, &certificate).is_err());
        let complete = DepositStateImportedCertificateReceipt::issue(
            &delivery,
            DepositStateImportedCertificateDisposition::Installed,
        )
        .unwrap();
        let reopened = open();
        reopened
            .acknowledge_certificate_delivery_authorized(
                certificate.clone(),
                &fixture.source,
                &fixture.target,
                locator.recipient(),
                locator,
                complete,
            )
            .await
            .unwrap();
        let after = open().load().await.unwrap().unwrap();
        assert_eq!(after.revision, before.revision + 1);
        assert_eq!(
            after
                .certificate_recipients
                .iter()
                .find(|recipient| recipient.recipient == locator.recipient())
                .unwrap()
                .receipt,
            Some(complete)
        );
    }

    #[test]
    fn outer_snapshot_bound_is_exact() {
        assert!(matches!(
            decode_state(&vec![0; MAX_DEPOSIT_STATE_IMPORT_STORE_BYTES + 1]),
            Err(DepositStateImportStoreError::StateTooLarge {
                actual,
                maximum: MAX_DEPOSIT_STATE_IMPORT_STORE_BYTES,
            }) if actual == MAX_DEPOSIT_STATE_IMPORT_STORE_BYTES + 1
        ));
    }
}
