//! Universal compute seam: one contract, every substrate.
//!
//! This coin is for every generation of hardware — CPU, GPU, NPU, TPU,
//! photonic chips, domestic accelerators — so the PoW is deliberately
//! portable: pure integer arithmetic and SHA-256, no floats anywhere, which
//! means every substrate that implements two's-complement math computes
//! bit-identical results. No single exotic chip can dominate either, because
//! the three stages pull in different directions: hash chains want raw
//! scalar throughput, the NN wants matrix-vector units (photonic MAC arrays
//! shine here), and the HBM path wants random memory bandwidth (which optical
//! and systolic hardware is bad at).
//!
//! The consensus math is **not** reimplemented here: backends implement the
//! [`ComputeBackend`] contract against the portable kernel surface
//! (`srct-core::puzzle::{ACTIVATION_SHIFT, fold32}`, `in_dim`, the weight and
//! bias accessors, `DOM_S2`, plain `sha256`). [`BatchSolver`] drives one
//! backend with one weight derivation per batch, and
//! [`solve_header_batched`] is the threaded grind over that interface.
//! Equivalence with the sequential solver is pinned by differential tests, so
//! a new backend can never silently change what counts as a solution: any
//! substrate that passes the differential test mines the same chain.

use srct_core::block::Header;
use srct_core::error::{Error, Result};
use srct_core::hash::{sha256, Hash, DOM_S2};
use srct_core::puzzle::{
    fold32, stage1_seed, stage2_activation_digest_with, stage3_final, EpochWeights, PuzzleRun,
    PuzzleSolver, PuzzleSpec, ACTIVATION_SHIFT,
};

/// Stage-2 compute contract: digests for `seeds` under `weights`, in order.
///
/// A photonic/NPU/TPU/GPU implementation moves the forward pass (and only
/// the forward pass) onto its substrate; weight derivation and stages 1/3
/// stay on the host, so the host still commits every layer exactly as
/// consensus requires. Same inputs, same outputs, same order — on every chip.
pub trait ComputeBackend {
    /// Backend name for selection and logging (`cpu`, `portable`, ...).
    fn name(&self) -> &'static str;
    fn stage2_batch(&self, spec: &PuzzleSpec, seeds: &[Hash], weights: &EpochWeights) -> Vec<Hash>;
}

/// Reference backend: the verified host forward pass, one seed at a time.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuBackend;

impl ComputeBackend for CpuBackend {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn stage2_batch(&self, spec: &PuzzleSpec, seeds: &[Hash], weights: &EpochWeights) -> Vec<Hash> {
        seeds
            .iter()
            .map(|seed| stage2_activation_digest_with(spec, seed, weights))
            .collect()
    }
}

/// Portable backend: an independently written forward pass over the public
/// kernel surface — separate loop structure and buffer handling from the
/// reference, identical arithmetic order, so the differential test proves the
/// spec is implementable without copying the reference implementation. This
/// is the template a silicon vendor ports: replace the scalar loops with
/// device kernels, keep the commit layout byte-identical.
#[derive(Debug, Clone, Copy, Default)]
pub struct PortableBackend;

impl ComputeBackend for PortableBackend {
    fn name(&self) -> &'static str {
        "portable"
    }

    fn stage2_batch(&self, spec: &PuzzleSpec, seeds: &[Hash], weights: &EpochWeights) -> Vec<Hash> {
        seeds
            .iter()
            .map(|seed| portable_digest(spec, seed, weights))
            .collect()
    }
}

/// Forward pass written only against the kernel surface: seed expansion,
/// per-layer matrix-vector products via the weight/bias accessors, ReLU
/// after [`ACTIVATION_SHIFT`], every layer's pre-activation values committed
/// little-endian under [`DOM_S2`] — the same commit layout as consensus.
fn portable_digest(spec: &PuzzleSpec, seed: &Hash, weights: &EpochWeights) -> Hash {
    // Same total state expansion as the consensus `forward`, index for
    // index: wrapped seed reads past byte 31, zero-padded state past the
    // input width. For every shape that evaluated before (`input <= 32`,
    // `hidden <= input`) this is byte-identical to plain `seed[j]` over
    // exactly `nn_input_dim` entries; for wider shapes it is defined
    // instead of panicking — and identical to consensus either way.
    let state_len = spec.nn_input_dim.max(spec.nn_hidden_dim);
    let mut x: Vec<i32> = (0..state_len)
        .map(|j| {
            if j < spec.nn_input_dim {
                seed[j % seed.len()] as i32 - 128
            } else {
                0
            }
        })
        .collect();
    let mut committed: Vec<u8> =
        Vec::with_capacity(DOM_S2.len() + spec.nn_layers * spec.nn_hidden_dim * 4);
    committed.extend_from_slice(DOM_S2);
    let mut z = vec![0i32; spec.nn_hidden_dim];
    for layer in 0..spec.nn_layers {
        let width = spec.in_dim(layer);
        for (out, z_out) in z.iter_mut().enumerate().take(spec.nn_hidden_dim) {
            let mut acc: i64 = weights.bias(spec, layer, out) as i64;
            for (inp, x_inp) in x.iter().enumerate().take(width) {
                acc += *x_inp as i64 * weights.weight(spec, layer, out, inp) as i64;
            }
            *z_out = fold32(acc);
        }
        for value in &z {
            committed.extend_from_slice(&value.to_le_bytes());
        }
        for (o, value) in z.iter().enumerate() {
            x[o] = (*value >> ACTIVATION_SHIFT).max(0);
        }
    }
    sha256(&[&committed])
}

/// Which compute substrate grinds a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendKind {
    /// [`CpuBackend`]: the reference host implementation.
    #[default]
    Cpu,
    /// [`PortableBackend`]: the independent implementation (and the template
    /// silicon vendors port to their substrate).
    Portable,
}

impl BackendKind {
    /// `auto` (or unset) means the reference CPU backend. The environment
    /// override `SRCT_MINER_BACKEND=cpu|portable|auto` lets operators pin a
    /// substrate without rebuilding; unknown values refuse loudly rather than
    /// silently grinding on the wrong chip.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cpu" => Ok(BackendKind::Cpu),
            "portable" => Ok(BackendKind::Portable),
            "auto" | "" => Ok(BackendKind::Cpu),
            other => Err(Error::BadPuzzleSpec(format!(
                "unknown backend '{other}' (cpu|portable|auto)"
            ))),
        }
    }

    pub fn from_env() -> Result<Self> {
        Self::parse(&std::env::var("SRCT_MINER_BACKEND").unwrap_or_default())
    }
}

/// Batched evaluator: one weight derivation per batch, backend-driven
/// stage 2, consensus-identical stage 1/3. All headers in a batch must share
/// `epoch_id` (mining batches always do — they grind one template); mixed
/// batches are refused rather than silently evaluated under one epoch's
/// weights.
#[derive(Debug, Clone)]
pub struct BatchSolver<B: ComputeBackend = CpuBackend> {
    spec: PuzzleSpec,
    weights: EpochWeights,
    backend: B,
}

impl<B: ComputeBackend> BatchSolver<B> {
    pub fn with_backend(spec: PuzzleSpec, backend: B) -> Self {
        let weights = EpochWeights::build(&spec, 0);
        BatchSolver {
            spec,
            weights,
            backend,
        }
    }

    /// Full runs for `headers`, in input order.
    pub fn evaluate(&mut self, headers: &[Header]) -> Result<Vec<PuzzleRun>> {
        let Some(first) = headers.first() else {
            return Ok(Vec::new());
        };
        if headers.iter().any(|h| h.epoch_id != first.epoch_id) {
            return Err(Error::Malformed("batch spans more than one epoch"));
        }
        if self.weights.epoch_id != first.epoch_id {
            self.weights = EpochWeights::build(&self.spec, first.epoch_id);
        }
        let seeds: Vec<Hash> = headers.iter().map(|h| stage1_seed(&self.spec, h)).collect();
        let acts = self.backend.stage2_batch(&self.spec, &seeds, &self.weights);
        Ok(headers
            .iter()
            .zip(seeds.iter().zip(acts.iter()))
            .map(|(h, (seed, act))| {
                let final_hash = stage3_final(&self.spec, seed, act, h.nonce, h.epoch_id);
                PuzzleRun {
                    seed: *seed,
                    activation_digest: *act,
                    final_hash,
                }
            })
            .collect())
    }
}

impl BatchSolver<CpuBackend> {
    pub fn new(spec: PuzzleSpec) -> Self {
        BatchSolver::with_backend(spec, CpuBackend)
    }
}

/// Batched grind: same search order and solution as [`crate::solve_header`]
/// (single thread), but candidates are evaluated `batch` at a time through
/// [`BatchSolver`]. `batch == 0` means 1 (sequential-equivalent). This is the
/// entry point a device backend accelerates: swap [`CpuBackend`] for the
/// substrate backend and the loop above it does not change.
pub fn evaluate_batch_sequential(spec: &PuzzleSpec, headers: &[Header]) -> Result<Vec<PuzzleRun>> {
    BatchSolver::new(spec.clone()).evaluate(headers)
}

/// Threaded grind over the batch interface.
///
/// `batch <= 1` delegates to [`crate::solve_header`] exactly (same code path
/// the existing tests pin); larger batches evaluate `batch` strided nonces
/// per step through one [`BatchSolver`] per thread. Search order — and hence
/// the winning nonce on one thread — is identical either way.
///
/// HBM templates fall back to the sequential grind regardless of `batch`:
/// the memory-hard pass has no batch interface (that is what a device
/// backend would add), and running chunks through no solver would report
/// "no solution" for a puzzle that was never attempted.
pub fn solve_header_batched(
    template: &Header,
    mode: crate::PowMode,
    threads: usize,
    batch: usize,
    max_attempts: u64,
) -> Result<Option<crate::MineSolution>> {
    solve_header_batched_with(template, mode, threads, batch, max_attempts, CpuBackend)
}

/// Threaded grind over any [`ComputeBackend`]: the same loop as
/// [`solve_header_batched`], with the stage-2 substrate swapped. A photonic
/// array, an NPU, a TPU, a domestic accelerator — each plugs in here, and the
/// differential tests prove the swap changes nothing but speed.
pub fn solve_header_batched_with<B: ComputeBackend + Clone + Send>(
    template: &Header,
    mode: crate::PowMode,
    threads: usize,
    batch: usize,
    max_attempts: u64,
    backend: B,
) -> Result<Option<crate::MineSolution>> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    if batch <= 1 {
        return crate::solve_header(template, mode, threads, max_attempts);
    }
    // The batched path only implements the hybrid puzzle (a `BatchSolver`
    // exists only for `spec`): with an HBM template every chunk evaluated
    // to `Ok(None)` until the budget ran out, reporting "no solution" for a
    // puzzle that was never attempted. Fall back to the sequential HBM grind
    // instead.
    if matches!(mode, crate::PowMode::Hbm(_)) {
        return crate::solve_header(template, mode, threads, max_attempts);
    }
    if max_attempts == 0 {
        return Ok(None);
    }
    if template.difficulty == 0 {
        return Err(Error::InvalidDifficulty(0));
    }
    let target = srct_core::u256::target_for_difficulty(template.difficulty)?;
    // Same agreement check as the sequential path: the mode's puzzle must be
    // the template's puzzle, or a miner could "solve" under one puzzle and
    // submit under another.
    let spec = match &mode {
        crate::PowMode::Hybrid(spec) => {
            if template.puzzle_id != spec.id {
                return Err(Error::BadPuzzleSpec(format!(
                    "template names puzzle {} but the miner holds {}",
                    template.puzzle_id, spec.id
                )));
            }
            spec.validate()?;
            Some(spec.clone())
        }
        crate::PowMode::Hbm(cfg) => {
            if template.puzzle_id != 2 {
                return Err(Error::BadPuzzleSpec(format!(
                    "template names puzzle {} but the miner holds hbm-v1",
                    template.puzzle_id
                )));
            }
            cfg.validate()?;
            None
        }
        crate::PowMode::VwcLinked(spec) => {
            if template.puzzle_id != spec.id {
                return Err(Error::BadPuzzleSpec(format!(
                    "template names puzzle {} but the miner holds {}",
                    template.puzzle_id, spec.id
                )));
            }
            if spec.kind != srct_core::puzzle::PuzzleKind::VwcLinked {
                return Err(Error::BadPuzzleSpec(
                    "vwc-linked mode needs a vwc-linked spec".into(),
                ));
            }
            spec.validate()?;
            Some(spec.clone())
        }
    };

    let n_threads = if threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        threads
    }
    .max(1);
    let per_thread = max_attempts.div_ceil(n_threads as u64);
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let solution: Arc<Mutex<Option<Header>>> = Arc::new(Mutex::new(None));
    // First backend refusal, if any: same rule as the sequential path — a
    // poisoned backend must surface as an error, never as "no solution".
    let first_err: Arc<Mutex<Option<srct_core::error::Error>>> = Arc::new(Mutex::new(None));

    std::thread::scope(|s| {
        for t in 0..n_threads {
            let found = found.clone();
            let attempts = attempts.clone();
            let solution = solution.clone();
            let first_err = first_err.clone();
            let template = template.clone();
            let mode = mode.clone();
            let spec = spec.clone();
            let backend = backend.clone();
            s.spawn(move || {
                let stride = n_threads as u64;
                let mut extra: u128 = u128::from_le_bytes(template.extra_nonce);
                let mut batch_solver = spec
                    .clone()
                    .map(|s| BatchSolver::with_backend(s, backend.clone()));
                let mut seq_solver = match &mode {
                    crate::PowMode::Hybrid(spec) => Some(PuzzleSolver::new(spec.clone())),
                    crate::PowMode::Hbm(_) => None,
                    crate::PowMode::VwcLinked(spec) => Some(PuzzleSolver::new(spec.clone())),
                };
                let mut local: u64 = 0;
                let mut chunk: Vec<Header> = Vec::with_capacity(batch);
                // Evaluate one filled chunk in nonce order.
                // Ok(Some(h)) = solution found; Ok(None) = keep grinding;
                // Err(e) = solver refused (poisoned backend) — record, stop,
                // never spin and never report "no solution" for it.
                let mut flush = |chunk: &mut Vec<Header>| -> std::result::Result<
                    Option<Header>,
                    srct_core::error::Error,
                > {
                    if chunk.is_empty() {
                        return Ok(None);
                    }
                    if let Some(bs) = batch_solver.as_mut() {
                        let runs = match bs.evaluate(chunk) {
                            Ok(runs) => runs,
                            Err(e) => {
                                return Err(srct_core::error::Error::BadPuzzleSpec(format!(
                                    "compute backend refused: {e}"
                                )))
                            }
                        };
                        for (h, run) in chunk.iter().zip(runs.iter()) {
                            if srct_core::u256::U256::from_be_bytes(run.final_hash) <= target {
                                return Ok(Some(h.clone()));
                            }
                        }
                        Ok(None)
                    } else if let Some(solver) = seq_solver.as_mut() {
                        for h in chunk.iter() {
                            match solver.satisfies(h) {
                                Ok(true) => return Ok(Some(h.clone())),
                                Ok(false) => {}
                                Err(e) => return Err(e),
                            }
                        }
                        Ok(None)
                    } else {
                        Ok(None)
                    }
                };
                loop {
                    let mut nonce = t as u64;
                    let mut wrapped = false;
                    loop {
                        if found.load(Ordering::Relaxed) {
                            return;
                        }
                        if local >= per_thread {
                            return;
                        }
                        // Fill one batch from this thread's strided subsequence.
                        chunk.clear();
                        let mut exhausted = false;
                        while chunk.len() < batch {
                            let prev = attempts.fetch_add(1, Ordering::Relaxed);
                            if prev >= max_attempts {
                                exhausted = true;
                                break;
                            }
                            let mut h = template.clone();
                            h.nonce = nonce;
                            h.extra_nonce = extra.to_le_bytes();
                            chunk.push(h);
                            local += 1;
                            match nonce.checked_add(stride) {
                                Some(next) => nonce = next,
                                None => {
                                    wrapped = true;
                                    break;
                                }
                            }
                        }
                        let won = match flush(&mut chunk) {
                            Err(e) => {
                                *first_err.lock().unwrap_or_else(|e| e.into_inner()) = Some(e);
                                found.store(true, Ordering::Relaxed);
                                return;
                            }
                            Ok(hit) => hit,
                        };
                        if let Some(h) = won {
                            if !found.swap(true, Ordering::Relaxed) {
                                *solution.lock().unwrap_or_else(|e| e.into_inner()) = Some(h);
                            }
                            return;
                        }
                        if exhausted {
                            return;
                        }
                        if wrapped {
                            break;
                        }
                        let _ = t;
                    }
                    extra = extra.wrapping_add(1);
                    if extra == u128::from_le_bytes(template.extra_nonce) {
                        return;
                    }
                }
            });
        }
    });

    // A recorded backend refusal outranks "no solution" (see `lib.rs`).
    if let Some(e) = first_err.lock().unwrap_or_else(|e| e.into_inner()).take() {
        return Err(e);
    }
    let header = solution.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match header {
        Some(header) => Ok(Some(crate::MineSolution {
            header,
            // Same overcount guard as `solve_header`: in-flight threads
            // increment once past the budget before observing it.
            attempts: attempts.load(Ordering::Relaxed).min(max_attempts),
        })),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PowMode;
    use srct_core::puzzle::run_puzzle;

    fn header_with_nonce(nonce: u64) -> Header {
        let mut h = srct_core::block::genesis_block(1).header;
        h.height = 1;
        h.difficulty = 1;
        h.puzzle_id = 1;
        h.nonce = nonce;
        h
    }

    #[test]
    fn batch_matches_sequential_candidate_for_candidate() {
        let spec = PuzzleSpec::hybrid_v1();
        let headers: Vec<Header> = (0..64u64).map(header_with_nonce).collect();
        let mut solver = BatchSolver::new(spec.clone());
        let batched = solver.evaluate(&headers).unwrap();
        for (h, run) in headers.iter().zip(batched.iter()) {
            assert_eq!(*run, run_puzzle(&spec, h));
        }
    }

    /// The universality test: two independently written implementations plus
    /// the consensus reference agree on every candidate, across epochs. Any
    /// future substrate backend (NPU, TPU, photonic, ...) joins this test:
    /// pass it and you mine the same chain.
    #[test]
    fn backends_agree_candidate_for_candidate_across_epochs() {
        let spec = PuzzleSpec::hybrid_v1();
        let mut cpu = BatchSolver::new(spec.clone());
        let mut portable = BatchSolver::with_backend(spec.clone(), PortableBackend);
        for epoch in [0u32, 1, 7, 255] {
            let headers: Vec<Header> = (0..32u64)
                .map(|n| {
                    let mut h = header_with_nonce(n * 7919);
                    h.epoch_id = epoch;
                    h
                })
                .collect();
            let a = cpu.evaluate(&headers).unwrap();
            let b = portable.evaluate(&headers).unwrap();
            for ((h, x), y) in headers.iter().zip(a.iter()).zip(b.iter()) {
                assert_eq!(*x, run_puzzle(&spec, h), "cpu disagrees at epoch {epoch}");
                assert_eq!(
                    *y,
                    run_puzzle(&spec, h),
                    "portable disagrees at epoch {epoch}"
                );
            }
        }
        assert_eq!(CpuBackend.name(), "cpu");
        assert_eq!(PortableBackend.name(), "portable");
    }

    /// Non-square dimensions evaluate identically on every backend — and do
    /// not panic. `nn_input_dim > 32` overruns the 32-byte seed, and
    /// `nn_hidden_dim > nn_input_dim` overruns an input-sized state buffer;
    /// both shapes below pass `validate()` (hence `register()`), so a
    /// governance-approved spec with either shape would previously have
    /// crashed every node that evaluated it. Comparing portable against the
    /// CPU backend *and* the consensus reference pins the fix on all three
    /// paths, across epochs.
    #[test]
    fn backends_agree_on_nonsquare_dims() {
        use srct_core::puzzle::{PuzzleKind, PuzzleRegistry};

        let wide_input = PuzzleSpec {
            id: 11,
            name: "wide-input".into(),
            kind: PuzzleKind::Hybrid,
            hash_rounds: 16,
            nn_input_dim: 40,
            nn_hidden_dim: 16,
            nn_layers: 3,
            min_nn_share_bps: 3_000,
            max_nn_share_bps: 5_000,
        };
        let wide_hidden = PuzzleSpec {
            id: 12,
            name: "wide-hidden".into(),
            kind: PuzzleKind::Hybrid,
            hash_rounds: 16,
            nn_input_dim: 8,
            nn_hidden_dim: 16,
            nn_layers: 3,
            min_nn_share_bps: 3_000,
            max_nn_share_bps: 5_000,
        };
        for spec in [wide_input, wide_hidden] {
            // Registrable: this shape can reach consensus evaluation.
            spec.validate().unwrap();
            let mut registry = PuzzleRegistry::genesis();
            registry.register(spec.clone()).unwrap();
            let mut cpu = BatchSolver::new(spec.clone());
            let mut portable = BatchSolver::with_backend(spec.clone(), PortableBackend);
            for epoch in [0u32, 5] {
                let headers: Vec<Header> = (0..16u64)
                    .map(|n| {
                        let mut h = header_with_nonce(n * 131 + 7);
                        h.epoch_id = epoch;
                        h
                    })
                    .collect();
                let a = cpu.evaluate(&headers).unwrap();
                let b = portable.evaluate(&headers).unwrap();
                for ((h, x), y) in headers.iter().zip(a.iter()).zip(b.iter()) {
                    let r = run_puzzle(&spec, h);
                    assert_eq!(*x, r, "cpu diverged at epoch {epoch}");
                    assert_eq!(*y, r, "portable diverged at epoch {epoch}");
                }
            }
        }
    }

    /// The portable backend grinds the same winning nonce as the reference:
    /// substrates differ in speed, never in the solution.
    #[test]
    fn portable_backend_finds_the_same_solution() {
        use crate::accel::solve_header_batched_with;

        let template = header_with_nonce(0);
        let seq = crate::solve_header(
            &template,
            PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
            1,
            50_000,
        )
        .unwrap()
        .expect("difficulty 1 solves");
        let port = solve_header_batched_with(
            &template,
            PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
            1,
            64,
            50_000,
            PortableBackend,
        )
        .unwrap()
        .expect("portable must solve too");
        assert_eq!(port.header.nonce, seq.header.nonce);
    }

    #[test]
    fn backend_selection_parses_and_defaults() {
        assert_eq!(BackendKind::parse("cpu").unwrap(), BackendKind::Cpu);
        assert_eq!(
            BackendKind::parse("portable").unwrap(),
            BackendKind::Portable
        );
        assert_eq!(BackendKind::parse("auto").unwrap(), BackendKind::Cpu);
        assert_eq!(BackendKind::parse("").unwrap(), BackendKind::Cpu);
        assert_eq!(BackendKind::default(), BackendKind::Cpu);
        assert!(BackendKind::parse("quantum").is_err());
    }

    /// Differential fuzz: 512 pseudorandom headers across hostile epochs,
    /// difficulties and extra-nonces — all three implementations (reference,
    /// portable, consensus) must agree on every digest. A silicon vendor's
    /// backend joins this exact test: any divergence is a consensus split,
    /// not rounding noise.
    #[test]
    fn backends_agree_on_pseudorandom_headers() {
        // xorshift64*: deterministic, no dependencies, full-period.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state = state.wrapping_mul(0x2545F4914F6CDD1D);
            state
        };

        let spec = PuzzleSpec::hybrid_v1();
        let mut cpu = BatchSolver::new(spec.clone());
        let mut portable = BatchSolver::with_backend(spec.clone(), PortableBackend);
        for _ in 0..16 {
            let headers: Vec<Header> = (0..32)
                .map(|_| {
                    let mut h = srct_core::block::genesis_block(1).header;
                    h.height = next();
                    h.difficulty = (next() | 1) as u128;
                    h.puzzle_id = 1;
                    h.epoch_id = (next() % 300) as u32;
                    h.nonce = next();
                    let mut extra = [0u8; 16];
                    for b in extra.iter_mut() {
                        *b = (next() & 0xFF) as u8;
                    }
                    h.extra_nonce = extra;
                    h.timestamp_ms = next();
                    h
                })
                .collect();
            // Batches must be epoch-homogeneous; group before evaluating.
            let mut by_epoch: std::collections::BTreeMap<u32, Vec<Header>> =
                std::collections::BTreeMap::new();
            for h in headers {
                by_epoch.entry(h.epoch_id).or_default().push(h);
            }
            for headers in by_epoch.values() {
                let a = cpu.evaluate(headers).unwrap();
                let b = portable.evaluate(headers).unwrap();
                for ((h, x), y) in headers.iter().zip(a.iter()).zip(b.iter()) {
                    let r = run_puzzle(&spec, h);
                    assert_eq!(*x, r, "cpu diverged on {:?}", h.nonce);
                    assert_eq!(*y, r, "portable diverged on {:?}", h.nonce);
                }
            }
        }
    }

    #[test]
    fn batch_rebuilds_weights_across_epochs() {
        let spec = PuzzleSpec::hybrid_v1();
        let mut solver = BatchSolver::new(spec.clone());
        let mut a = header_with_nonce(0);
        a.epoch_id = 3;
        let mut b = header_with_nonce(1);
        b.epoch_id = 3;
        let batched = solver.evaluate(&[a.clone(), b.clone()]).unwrap();
        assert_eq!(batched[0], run_puzzle(&spec, &a));
        assert_eq!(batched[1], run_puzzle(&spec, &b));
        // A later batch under another epoch re-derives instead of reusing.
        let mut c = header_with_nonce(2);
        c.epoch_id = 4;
        let batched2 = solver.evaluate(&[c.clone()]).unwrap();
        assert_eq!(batched2[0], run_puzzle(&spec, &c));
    }

    #[test]
    fn mixed_epoch_batch_is_refused() {
        let spec = PuzzleSpec::hybrid_v1();
        let mut solver = BatchSolver::new(spec);
        let mut b = header_with_nonce(1);
        b.epoch_id = 9;
        let err = solver.evaluate(&[header_with_nonce(0), b]).unwrap_err();
        assert_eq!(err, Error::Malformed("batch spans more than one epoch"));
    }

    #[test]
    fn empty_batch_is_empty() {
        let spec = PuzzleSpec::hybrid_v1();
        let mut solver = BatchSolver::new(spec);
        assert!(solver.evaluate(&[]).unwrap().is_empty());
    }

    /// The batched grind finds the same first solution as the sequential
    /// grind on the same template: batching must never reorder the search.
    #[test]
    fn solve_batched_matches_solve_sequential() {
        use crate::accel::solve_header_batched;

        let template = header_with_nonce(0);
        let seq = crate::solve_header(
            &template,
            PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
            1,
            50_000,
        )
        .unwrap()
        .expect("difficulty 1 solves");
        for batch in [2usize, 7, 64, 1024] {
            let batched = solve_header_batched(
                &template,
                PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
                1,
                batch,
                50_000,
            )
            .unwrap()
            .expect("batched must solve too");
            assert_eq!(
                batched.header.nonce, seq.header.nonce,
                "batch {batch} must find the same first nonce"
            );
        }
    }

    #[test]
    fn solve_batched_zero_budget_and_passthrough() {
        use crate::accel::solve_header_batched;

        let template = header_with_nonce(0);
        assert!(solve_header_batched(
            &template,
            PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
            1,
            64,
            0
        )
        .unwrap()
        .is_none());
        // batch <= 1 delegates to the sequential path exactly.
        let sol = solve_header_batched(
            &template,
            PowMode::Hybrid(PuzzleSpec::hybrid_v1()),
            1,
            1,
            100,
        )
        .unwrap()
        .expect("passthrough must solve");
        assert_eq!(sol.header.nonce, 0);
    }
}
