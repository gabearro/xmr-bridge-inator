//! Private-Regtest deposit clock used by the end-to-end TTL acceptance.
//!
//! Production and ordinary Regtest parties always use [`DepositClock::System`]. The file-backed
//! clock is available only to an explicitly configured demo-only Regtest process with deposits
//! enabled. It has no network control surface: the one-shot acceptance driver receives the sole
//! writable mount while parties receive the same directory read-only.
//!
//! Before the first valid control file appears, a configured reader samples the system clock.
//! After activation, an absent, malformed, cross-network, or non-monotonic file fails closed; it
//! is never replaced with a system-clock sample. A later strictly newer valid generation can
//! restore liveness.

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

use crate::config::{NetworkKind, Scenario};

pub(crate) const ACCEPTANCE_DEPOSIT_CLOCK_ENV: &str = "TM_ACCEPTANCE_DEPOSIT_CLOCK_FILE";
pub(crate) const E2E_DEPOSIT_CLOCK_ENV: &str = "TM_E2E_DEPOSIT_CLOCK_FILE";

const CLOCK_FILE_HEADER: &str = "threshold-monero-deposit-clock-v1";
const MAX_CLOCK_FILE_BYTES: usize = 256;
const MAX_UNIX_SECONDS: u64 = 253_402_300_799;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DepositClockSample {
    pub unix_seconds: u64,
    pub unix_millis: u64,
}

impl DepositClockSample {
    fn fixed_seconds(unix_seconds: u64) -> Result<Self, DepositClockError> {
        validate_unix_seconds(unix_seconds)?;
        let unix_millis = unix_seconds.checked_mul(1_000).ok_or(DepositClockError::InvalidTime)?;
        Ok(Self { unix_seconds, unix_millis })
    }
}

#[derive(Debug)]
pub(crate) enum DepositClock {
    System,
    PrivateRegtestFile(RegtestClockReader),
}

impl DepositClock {
    pub(crate) fn from_scenario_env(
        scenario: &Scenario,
        deposits_enabled: bool,
    ) -> Result<Self, DepositClockError> {
        Self::configured(
            scenario,
            deposits_enabled,
            std::env::var_os(ACCEPTANCE_DEPOSIT_CLOCK_ENV).map(PathBuf::from),
        )
    }

    pub(crate) fn configured(
        scenario: &Scenario,
        deposits_enabled: bool,
        path: Option<PathBuf>,
    ) -> Result<Self, DepositClockError> {
        let Some(path) = path else {
            return Ok(Self::System);
        };
        validate_private_regtest_gate(scenario, deposits_enabled, &path)?;
        Ok(Self::PrivateRegtestFile(RegtestClockReader::new(
            path,
            scenario
                .quic_network_id()
                .map_err(|error| DepositClockError::InvalidScenario(error.to_string()))?,
        )))
    }

    pub(crate) fn sample(&self) -> Result<DepositClockSample, DepositClockError> {
        match self {
            Self::System => system_sample(),
            Self::PrivateRegtestFile(reader) => reader.sample(),
        }
    }

    #[cfg(test)]
    fn is_system(&self) -> bool {
        matches!(self, Self::System)
    }
}

#[derive(Debug)]
pub(crate) struct RegtestClockReader {
    path: PathBuf,
    network: [u8; 32],
    state: Mutex<ReaderState>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReaderState {
    activated: bool,
    generation: u64,
    unix_seconds: u64,
}

impl RegtestClockReader {
    fn new(path: PathBuf, network: [u8; 32]) -> Self {
        Self { path, network, state: Mutex::new(ReaderState::default()) }
    }

    fn sample(&self) -> Result<DepositClockSample, DepositClockError> {
        let mut state = self.state.lock().map_err(|_| DepositClockError::Poisoned)?;
        let bytes = match read_bounded(&self.path) {
            Ok(bytes) => bytes,
            Err(ReadClockError::Missing) if !state.activated => return system_sample(),
            Err(ReadClockError::Missing) => {
                return Err(DepositClockError::UnavailableAfterActivation);
            }
            Err(ReadClockError::TooLarge) => {
                return Err(DepositClockError::InvalidClockFile("file exceeds 256 bytes"));
            }
            Err(ReadClockError::Io(error)) => return Err(DepositClockError::Io(error)),
        };
        let record = ClockRecord::parse(&bytes, self.network)?;
        if state.activated {
            if record.generation < state.generation {
                return Err(DepositClockError::GenerationRegression {
                    previous: state.generation,
                    observed: record.generation,
                });
            }
            if record.generation == state.generation {
                if record.unix_seconds != state.unix_seconds {
                    return Err(DepositClockError::GenerationMutation {
                        generation: record.generation,
                    });
                }
                return DepositClockSample::fixed_seconds(record.unix_seconds);
            }
            if record.unix_seconds <= state.unix_seconds {
                return Err(DepositClockError::TimeRegression {
                    previous: state.unix_seconds,
                    observed: record.unix_seconds,
                });
            }
        }
        *state = ReaderState {
            activated: true,
            generation: record.generation,
            unix_seconds: record.unix_seconds,
        };
        DepositClockSample::fixed_seconds(record.unix_seconds)
    }
}

#[derive(Debug)]
pub(crate) struct RegtestClockWriter {
    path: PathBuf,
    network: [u8; 32],
    generation: u64,
    unix_seconds: Option<u64>,
}

impl RegtestClockWriter {
    pub(crate) fn from_e2e_env(scenario: &Scenario) -> Result<Option<Self>, DepositClockError> {
        let Some(path) = std::env::var_os(E2E_DEPOSIT_CLOCK_ENV).map(PathBuf::from) else {
            return Ok(None);
        };
        Self::new(scenario, path).map(Some)
    }

    pub(crate) fn new(
        scenario: &Scenario,
        path: impl Into<PathBuf>,
    ) -> Result<Self, DepositClockError> {
        let path = path.into();
        validate_private_regtest_gate(scenario, true, &path)?;
        let network = scenario
            .quic_network_id()
            .map_err(|error| DepositClockError::InvalidScenario(error.to_string()))?;
        let existing = match read_bounded(&path) {
            Ok(bytes) => Some(ClockRecord::parse(&bytes, network)?),
            Err(ReadClockError::Missing) => None,
            Err(ReadClockError::TooLarge) => {
                return Err(DepositClockError::InvalidClockFile("file exceeds 256 bytes"));
            }
            Err(ReadClockError::Io(error)) => return Err(DepositClockError::Io(error)),
        };
        Ok(Self {
            path,
            network,
            generation: existing.map_or(0, |record| record.generation),
            unix_seconds: existing.map(|record| record.unix_seconds),
        })
    }

    pub(crate) fn set_unix_seconds(
        &mut self,
        unix_seconds: u64,
    ) -> Result<DepositClockSample, DepositClockError> {
        validate_unix_seconds(unix_seconds)?;
        if let Some(previous) = self.unix_seconds
            && unix_seconds <= previous
        {
            return Err(DepositClockError::TimeRegression { previous, observed: unix_seconds });
        }
        let generation =
            self.generation.checked_add(1).ok_or(DepositClockError::GenerationExhausted)?;
        let record = ClockRecord { generation, unix_seconds };
        let bytes = record.encode(self.network);
        debug_assert!(bytes.len() <= MAX_CLOCK_FILE_BYTES);
        atomic_replace(&self.path, &bytes)?;
        self.generation = generation;
        self.unix_seconds = Some(unix_seconds);
        DepositClockSample::fixed_seconds(unix_seconds)
    }

    #[cfg(test)]
    fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClockRecord {
    generation: u64,
    unix_seconds: u64,
}

impl ClockRecord {
    fn encode(self, network: [u8; 32]) -> Vec<u8> {
        format!(
            "{CLOCK_FILE_HEADER}\nnetwork={}\ngeneration={}\nunix_seconds={}\n",
            hex::encode(network),
            self.generation,
            self.unix_seconds,
        )
        .into_bytes()
    }

    fn parse(bytes: &[u8], expected_network: [u8; 32]) -> Result<Self, DepositClockError> {
        if bytes.len() > MAX_CLOCK_FILE_BYTES {
            return Err(DepositClockError::InvalidClockFile("file exceeds 256 bytes"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| DepositClockError::InvalidClockFile("file is not UTF-8"))?;
        let lines = text.split('\n').collect::<Vec<_>>();
        if lines.len() != 5 || !lines[4].is_empty() {
            return Err(DepositClockError::InvalidClockFile("file has non-canonical line framing"));
        }
        if lines[0] != CLOCK_FILE_HEADER {
            return Err(DepositClockError::InvalidClockFile("unsupported clock schema"));
        }
        let network = lines[1]
            .strip_prefix("network=")
            .ok_or(DepositClockError::InvalidClockFile("network field is missing"))?;
        if network != hex::encode(expected_network) {
            return Err(DepositClockError::NetworkMismatch);
        }
        let generation = parse_canonical_u64(
            lines[2]
                .strip_prefix("generation=")
                .ok_or(DepositClockError::InvalidClockFile("generation field is missing"))?,
        )?;
        if generation == 0 {
            return Err(DepositClockError::InvalidClockFile("generation is zero"));
        }
        let unix_seconds = parse_canonical_u64(
            lines[3]
                .strip_prefix("unix_seconds=")
                .ok_or(DepositClockError::InvalidClockFile("time field is missing"))?,
        )?;
        validate_unix_seconds(unix_seconds)?;
        Ok(Self { generation, unix_seconds })
    }
}

fn validate_private_regtest_gate(
    scenario: &Scenario,
    deposits_enabled: bool,
    path: &Path,
) -> Result<(), DepositClockError> {
    if !deposits_enabled {
        return Err(DepositClockError::DepositsRequired);
    }
    if !scenario.demo_only || scenario.network != NetworkKind::Regtest {
        return Err(DepositClockError::PrivateRegtestRequired);
    }
    if !path.is_absolute() {
        return Err(DepositClockError::AbsolutePathRequired);
    }
    Ok(())
}

fn validate_unix_seconds(unix_seconds: u64) -> Result<(), DepositClockError> {
    if unix_seconds == 0 || unix_seconds > MAX_UNIX_SECONDS {
        return Err(DepositClockError::InvalidTime);
    }
    Ok(())
}

fn parse_canonical_u64(value: &str) -> Result<u64, DepositClockError> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(DepositClockError::InvalidClockFile("integer is not canonically encoded"));
    }
    value.parse().map_err(|_| DepositClockError::InvalidClockFile("integer exceeds u64"))
}

fn system_sample() -> Result<DepositClockSample, DepositClockError> {
    let elapsed =
        SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| DepositClockError::InvalidTime)?;
    let unix_seconds = elapsed.as_secs();
    validate_unix_seconds(unix_seconds)?;
    let unix_millis =
        u64::try_from(elapsed.as_millis()).map_err(|_| DepositClockError::InvalidTime)?;
    Ok(DepositClockSample { unix_seconds, unix_millis })
}

enum ReadClockError {
    Missing,
    TooLarge,
    Io(io::Error),
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ReadClockError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ReadClockError::Missing);
        }
        Err(error) => return Err(ReadClockError::Io(error)),
    };
    let mut bytes = Vec::with_capacity(MAX_CLOCK_FILE_BYTES);
    file.take((MAX_CLOCK_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(ReadClockError::Io)?;
    if bytes.len() > MAX_CLOCK_FILE_BYTES {
        return Err(ReadClockError::TooLarge);
    }
    Ok(bytes)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), DepositClockError> {
    if bytes.len() > MAX_CLOCK_FILE_BYTES {
        return Err(DepositClockError::InvalidClockFile("file exceeds 256 bytes"));
    }
    let parent = path.parent().ok_or(DepositClockError::AbsolutePathRequired)?;
    let file_name = path.file_name().and_then(OsStr::to_str).ok_or(
        DepositClockError::InvalidClockFile("clock path has no canonical UTF-8 file name"),
    )?;
    let nonce = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(DepositClockError::Io)
}

#[derive(Debug, Error)]
pub(crate) enum DepositClockError {
    #[error("acceptance deposit clock requires deposits to be enabled")]
    DepositsRequired,
    #[error("acceptance deposit clock is restricted to a demo-only private Regtest scenario")]
    PrivateRegtestRequired,
    #[error("acceptance deposit clock path must be absolute")]
    AbsolutePathRequired,
    #[error("acceptance deposit clock scenario is invalid: {0}")]
    InvalidScenario(String),
    #[error("acceptance deposit clock file is invalid: {0}")]
    InvalidClockFile(&'static str),
    #[error("acceptance deposit clock belongs to another network")]
    NetworkMismatch,
    #[error("acceptance deposit clock disappeared after activation")]
    UnavailableAfterActivation,
    #[error("acceptance deposit clock generation regressed from {previous} to {observed}")]
    GenerationRegression { previous: u64, observed: u64 },
    #[error("acceptance deposit clock generation {generation} changed its time")]
    GenerationMutation { generation: u64 },
    #[error("acceptance deposit clock time did not advance from {previous} to {observed}")]
    TimeRegression { previous: u64, observed: u64 },
    #[error("acceptance deposit clock generation is exhausted")]
    GenerationExhausted,
    #[error("acceptance deposit clock time is invalid")]
    InvalidTime,
    #[error("acceptance deposit clock mutex is poisoned")]
    Poisoned,
    #[error("acceptance deposit clock I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario() -> Scenario {
        serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json"))
            .expect("Regtest scenario fixture")
    }

    fn clock_path(directory: &tempfile::TempDir) -> PathBuf {
        directory.path().join("deposit-clock")
    }

    fn configured_reader(scenario: &Scenario, path: &Path) -> DepositClock {
        DepositClock::configured(scenario, true, Some(path.to_path_buf()))
            .expect("configured private Regtest clock")
    }

    fn canonical_bytes(scenario: &Scenario, generation: u64, unix_seconds: u64) -> Vec<u8> {
        ClockRecord { generation, unix_seconds }
            .encode(scenario.quic_network_id().expect("network id"))
    }

    #[test]
    fn ordinary_configuration_always_uses_the_system_clock() {
        let scenario = scenario();
        let clock = DepositClock::configured(&scenario, true, None).unwrap();
        assert!(clock.is_system());
        let sample = clock.sample().unwrap();
        assert!(sample.unix_seconds > 0);
        assert!(sample.unix_millis / 1_000 >= sample.unix_seconds);
    }

    #[test]
    fn file_clock_is_gated_by_deposits_private_regtest_and_absolute_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = clock_path(&directory);
        let mut scenario = scenario();

        assert!(matches!(
            DepositClock::configured(&scenario, false, Some(path.clone())),
            Err(DepositClockError::DepositsRequired)
        ));
        assert!(matches!(
            DepositClock::configured(&scenario, true, Some(PathBuf::from("relative-clock"))),
            Err(DepositClockError::AbsolutePathRequired)
        ));

        scenario.demo_only = false;
        assert!(matches!(
            DepositClock::configured(&scenario, true, Some(path.clone())),
            Err(DepositClockError::PrivateRegtestRequired)
        ));
        scenario.demo_only = true;
        scenario.network = NetworkKind::Testnet;
        assert!(matches!(
            DepositClock::configured(&scenario, true, Some(path.clone())),
            Err(DepositClockError::PrivateRegtestRequired)
        ));
        scenario.network = NetworkKind::Mainnet;
        assert!(matches!(
            DepositClock::configured(&scenario, true, Some(path)),
            Err(DepositClockError::PrivateRegtestRequired)
        ));
    }

    #[test]
    fn absent_file_uses_system_time_only_before_activation() {
        let directory = tempfile::tempdir().unwrap();
        let path = clock_path(&directory);
        let scenario = scenario();
        let clock = configured_reader(&scenario, &path);
        assert!(clock.sample().unwrap().unix_seconds > 0);

        fs::write(&path, canonical_bytes(&scenario, 1, 1_700_000_000)).unwrap();
        assert_eq!(
            clock.sample().unwrap(),
            DepositClockSample { unix_seconds: 1_700_000_000, unix_millis: 1_700_000_000_000 }
        );
        fs::remove_file(&path).unwrap();
        assert!(matches!(clock.sample(), Err(DepositClockError::UnavailableAfterActivation)));

        fs::write(&path, canonical_bytes(&scenario, 2, 1_700_000_001)).unwrap();
        assert_eq!(clock.sample().unwrap().unix_seconds, 1_700_000_001);
    }

    #[test]
    fn writer_atomically_publishes_exact_canonical_seconds() {
        let directory = tempfile::tempdir().unwrap();
        let path = clock_path(&directory);
        let scenario = scenario();
        let clock = configured_reader(&scenario, &path);
        let mut writer = RegtestClockWriter::new(&scenario, &path).unwrap();

        let sample = writer.set_unix_seconds(1_700_000_123).unwrap();
        assert_eq!(
            sample,
            DepositClockSample { unix_seconds: 1_700_000_123, unix_millis: 1_700_000_123_000 }
        );
        assert_eq!(fs::read(&path).unwrap(), canonical_bytes(&scenario, 1, 1_700_000_123));
        assert!(fs::read(&path).unwrap().len() <= MAX_CLOCK_FILE_BYTES);
        assert_eq!(clock.sample().unwrap(), sample);
        assert!(
            fs::read_dir(directory.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
        );
    }

    #[test]
    fn writer_restart_continues_generation_and_rejects_nonadvancing_time() {
        let directory = tempfile::tempdir().unwrap();
        let path = clock_path(&directory);
        let scenario = scenario();
        let mut writer = RegtestClockWriter::new(&scenario, &path).unwrap();
        writer.set_unix_seconds(1_700_000_000).unwrap();
        drop(writer);

        let mut restarted = RegtestClockWriter::new(&scenario, &path).unwrap();
        assert_eq!(restarted.generation(), 1);
        assert!(matches!(
            restarted.set_unix_seconds(1_700_000_000),
            Err(DepositClockError::TimeRegression { .. })
        ));
        restarted.set_unix_seconds(1_700_000_001).unwrap();
        assert_eq!(restarted.generation(), 2);
    }

    #[test]
    fn reader_rejects_generation_mutation_and_all_regressions() {
        let directory = tempfile::tempdir().unwrap();
        let path = clock_path(&directory);
        let scenario = scenario();
        let clock = configured_reader(&scenario, &path);

        fs::write(&path, canonical_bytes(&scenario, 2, 1_700_000_002)).unwrap();
        assert_eq!(clock.sample().unwrap().unix_seconds, 1_700_000_002);
        fs::write(&path, canonical_bytes(&scenario, 2, 1_700_000_003)).unwrap();
        assert!(matches!(
            clock.sample(),
            Err(DepositClockError::GenerationMutation { generation: 2 })
        ));
        fs::write(&path, canonical_bytes(&scenario, 1, 1_700_000_004)).unwrap();
        assert!(matches!(
            clock.sample(),
            Err(DepositClockError::GenerationRegression { previous: 2, observed: 1 })
        ));
        fs::write(&path, canonical_bytes(&scenario, 3, 1_700_000_001)).unwrap();
        assert!(matches!(
            clock.sample(),
            Err(DepositClockError::TimeRegression {
                previous: 1_700_000_002,
                observed: 1_700_000_001
            })
        ));
        fs::write(&path, canonical_bytes(&scenario, 3, 1_700_000_003)).unwrap();
        assert_eq!(clock.sample().unwrap().unix_seconds, 1_700_000_003);
    }

    #[test]
    fn parser_rejects_every_noncanonical_shape() {
        let scenario = scenario();
        let network = hex::encode(scenario.quic_network_id().unwrap());
        let valid =
            format!("{CLOCK_FILE_HEADER}\nnetwork={network}\ngeneration=1\nunix_seconds=1\n");
        let wrong_network = "00".repeat(32);
        let oversized = "x".repeat(MAX_CLOCK_FILE_BYTES + 1);
        let invalid = vec![
            String::new(),
            valid.trim_end().to_owned(),
            format!("{valid}\n"),
            valid.replace(CLOCK_FILE_HEADER, "threshold-monero-deposit-clock-v0"),
            valid.replace("network=", "net="),
            valid.replace(&network, &network.to_uppercase()),
            valid.replace(&network, &wrong_network),
            valid.replace("generation=1", "generation=0"),
            valid.replace("generation=1", "generation=01"),
            valid.replace("generation=1", "generation=+1"),
            valid.replace("unix_seconds=1", "unix_seconds=0"),
            valid.replace("unix_seconds=1", "unix_seconds=01"),
            valid.replace("unix_seconds=1", "unix_seconds= 1"),
            valid.replace('\n', "\r\n"),
            format!("{valid}extra=1\n"),
            oversized,
        ];
        for bytes in invalid {
            assert!(
                ClockRecord::parse(bytes.as_bytes(), scenario.quic_network_id().unwrap()).is_err(),
                "accepted invalid clock file: {bytes:?}"
            );
        }
        assert_eq!(
            ClockRecord::parse(valid.as_bytes(), scenario.quic_network_id().unwrap()).unwrap(),
            ClockRecord { generation: 1, unix_seconds: 1 }
        );
    }

    #[test]
    fn parser_rejects_time_and_integer_overflow() {
        let scenario = scenario();
        let network = hex::encode(scenario.quic_network_id().unwrap());
        for (generation, unix_seconds) in
            [("18446744073709551616", "1"), ("1", "18446744073709551616"), ("1", "253402300800")]
        {
            let bytes = format!(
                "{CLOCK_FILE_HEADER}\nnetwork={network}\ngeneration={generation}\n\
                 unix_seconds={unix_seconds}\n"
            );
            assert!(
                ClockRecord::parse(bytes.as_bytes(), scenario.quic_network_id().unwrap()).is_err()
            );
        }
    }

    #[test]
    fn bounded_reader_rejects_oversized_files_without_full_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let path = clock_path(&directory);
        let scenario = scenario();
        fs::write(&path, vec![b'x'; MAX_CLOCK_FILE_BYTES + 1]).unwrap();
        let clock = configured_reader(&scenario, &path);
        assert!(matches!(
            clock.sample(),
            Err(DepositClockError::InvalidClockFile("file exceeds 256 bytes"))
        ));
        assert!(matches!(
            RegtestClockWriter::new(&scenario, &path),
            Err(DepositClockError::InvalidClockFile("file exceeds 256 bytes"))
        ));
    }

    #[test]
    fn record_is_bound_to_the_exact_network() {
        let directory = tempfile::tempdir().unwrap();
        let path = clock_path(&directory);
        let scenario = scenario();
        let mut other = scenario.clone();
        other.proactive_refresh_interval_seconds =
            other.proactive_refresh_interval_seconds.checked_add(1).unwrap();
        assert_ne!(scenario.quic_network_id().unwrap(), other.quic_network_id().unwrap());
        fs::write(&path, canonical_bytes(&scenario, 1, 1_700_000_000)).unwrap();
        let clock = configured_reader(&other, &path);
        assert!(matches!(clock.sample(), Err(DepositClockError::NetworkMismatch)));
        assert!(matches!(
            RegtestClockWriter::new(&other, &path),
            Err(DepositClockError::NetworkMismatch)
        ));
    }
}
