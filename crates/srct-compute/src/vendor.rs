//! Vendor attestation evidence: parsed TDX quotes, SNP reports, NVIDIA reports.
//!
//! The [`SignedTeeQuote`] in [`crate::tee`] proves an approved environment
//! executed a workload. This module proves the *hardware* part: it parses
//! real vendor evidence formats (Intel TDX DCAP quotes, AMD SEV-SNP
//! attestation reports, NVIDIA GPU attestation reports), verifies the
//! vendor certificate chains against pinned roots, and enforces the policy
//! the consumer's SLA demands (debug off, TCB minimums, approved
//! measurement, fresh nonce bound into `report_data`).
//!
//! # What this is not
//!
//! - **Not validated on real hardware.** Every layout below follows the
//!   public specifications (Intel DCAP Quote Library quote format v4/v5,
//!   AMD SEV-SNP ABI attestation report, NVIDIA NRAS-style JWT reports),
//!   but no path here has run against a real TDX, SEV-SNP or NVIDIA CC
//!   host. Everything is simulator-tested only until the hardware-gated
//!   runs pass; the layout details this module is unsure about (the SNP
//!   debug policy bit, the VCEK signature container placement) are marked
//!   inline for re-verification at gating time.
//! - **Not networked.** CRL bodies, TCB status lists, RIM reference
//!   values and the KDS VCEK/VLEK chain arrive as function inputs
//!   (`VendorInputs`, `snp_vcek_chain`). Fetching them over the network
//!   (Intel PCS, AMD KDS, NVIDIA RIM service) lives in the node, never in
//!   this crate.
//!
//! # Report-data binding
//!
//! Every family binds the same 32-byte commitment: the first 32 bytes of
//! the evidence `report_data` must equal `SHA256(enclave_ephemeral_pubkey
//! || session_nonce_le)`, where the ephemeral key is presented over the
//! attested channel and the nonce is the quote's session nonce. A mismatch
//! means the key was never released: [`crate::tee::TeeError::BadReportData`].

use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::X509Certificate;

use crate::tee::TeeError;

/// Wire version of the vendor evidence envelope.
pub const VENDOR_EVIDENCE_VERSION: u8 = 1;

/// Largest accepted vendor evidence blob: a DCAP quote with a full PCK
/// chain is on the order of kilobytes; anything larger is not evidence.
pub const MAX_VENDOR_EVIDENCE_BYTES: usize = 65_536;

/// Largest accepted certificate chain (leaf plus intermediates).
pub const MAX_CHAIN_CERTS: usize = 8;

/// Largest accepted single DER certificate.
pub const MAX_CERT_BYTES: usize = 8_192;

/// Which vendor family produced the evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VendorFamily {
    Tdx,
    Snp,
    Nvidia,
}

/// Parsed vendor evidence, one variant per family. Decoded fail-closed:
/// every offset and length is bounds-checked, trailing bytes refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VendorEvidence {
    Tdx(TdxQuote),
    Snp(SnpReport),
    Nvidia(NvidiaReport),
}

impl VendorEvidence {
    pub fn family(&self) -> VendorFamily {
        match self {
            VendorEvidence::Tdx(_) => VendorFamily::Tdx,
            VendorEvidence::Snp(_) => VendorFamily::Snp,
            VendorEvidence::Nvidia(_) => VendorFamily::Nvidia,
        }
    }

    /// Composite measurement id the SLA allowlists: SHA256 over the
    /// family-normalised measurements (TDX: mr_td || rtmr0..3; SNP: the
    /// 48-byte measurement; NVIDIA: sorted concatenated decoded
    /// measurements).
    pub fn measurement_id(&self) -> [u8; 32] {
        match self {
            VendorEvidence::Tdx(q) => q.measurement_id(),
            VendorEvidence::Snp(r) => r.measurement_id(),
            VendorEvidence::Nvidia(r) => r.measurement_id(),
        }
    }

    /// First 32 bytes of the evidence report data: the slot that must
    /// carry `SHA256(ephem_pubkey || nonce_le)`.
    pub fn report_binding(&self) -> [u8; 32] {
        match self {
            VendorEvidence::Tdx(q) => q.report_binding(),
            VendorEvidence::Snp(r) => r.report_binding(),
            VendorEvidence::Nvidia(r) => r.report_binding,
        }
    }

    /// Whether the guest ran with debugging enabled.
    pub fn debug_enabled(&self) -> bool {
        match self {
            VendorEvidence::Tdx(q) => q.debug_enabled(),
            VendorEvidence::Snp(r) => r.debug_enabled(),
            VendorEvidence::Nvidia(_) => false,
        }
    }

    /// Normalised 16-byte big-endian TCB security version for minimum
    /// comparison: TDX native 16 bytes; SNP reported TCB zero-left-padded;
    /// NVIDIA firmware version as big-endian u64 zero-left-padded.
    pub fn tcb_svn(&self) -> [u8; 16] {
        match self {
            VendorEvidence::Tdx(q) => q.tee_tcb_svn,
            VendorEvidence::Snp(r) => {
                let mut out = [0u8; 16];
                out[8..].copy_from_slice(&r.reported_tcb);
                out
            }
            VendorEvidence::Nvidia(r) => {
                let mut out = [0u8; 16];
                out[8..].copy_from_slice(&r.fw_version.to_be_bytes());
                out
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let (tag, body) = match self {
            VendorEvidence::Tdx(q) => (1u8, q.encode()),
            VendorEvidence::Snp(r) => (2u8, r.encode()),
            VendorEvidence::Nvidia(r) => (3u8, r.encode()),
        };
        let mut w = Vec::with_capacity(8 + body.len());
        w.push(VENDOR_EVIDENCE_VERSION);
        w.push(tag);
        w.extend_from_slice(&(body.len() as u32).to_le_bytes());
        w.extend_from_slice(&body);
        w
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TeeError> {
        if bytes.len() > MAX_VENDOR_EVIDENCE_BYTES {
            return Err(TeeError::Malformed("vendor evidence over cap".into()));
        }
        if bytes.len() < 6 {
            return Err(TeeError::Malformed("vendor evidence truncated".into()));
        }
        if bytes[0] != VENDOR_EVIDENCE_VERSION {
            return Err(TeeError::Malformed(format!(
                "unsupported vendor evidence version {}",
                bytes[0]
            )));
        }
        let len = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
        if len != bytes.len() - 6 {
            return Err(TeeError::Malformed(
                "vendor evidence length mismatch".into(),
            ));
        }
        let body = &bytes[6..];
        match bytes[1] {
            1 => Ok(VendorEvidence::Tdx(TdxQuote::decode(body)?)),
            2 => Ok(VendorEvidence::Snp(SnpReport::decode(body)?)),
            3 => Ok(VendorEvidence::Nvidia(NvidiaReport::decode(body)?)),
            _ => Err(TeeError::UnknownVendorFormat),
        }
    }
}

// ---------------------------------------------------------------------------
// Intel TDX DCAP quote (v4 layout)
// ---------------------------------------------------------------------------

/// DCAP quote v4 fixed offsets, per the Intel DCAP Quote Library format.
/// Header (48 B) + TD report body (584 B) + QE report (384 B) + QE report
/// signature (64 B) + auth-data length (2 B). Our on-wire envelope is these
/// exact DCAP bytes followed by the variable section (auth data, raw
/// concatenated DER certs) plus a 65-byte attestation-pubkey trailer: the
/// key is conveyed explicitly so the QE binding is checkable without
/// platform calls. Reserved TD fields we do not model (mr_seam,
/// mr_signer_seam, seam/xfam attributes, config/owner hashes) encode as
/// zero and are ignored on decode; measurement binding covers mr_td plus
/// the four RTMRs only.
pub mod tdx_layout {
    pub const VERSION_OFFSET: usize = 0;
    pub const ATT_KEY_TYPE_OFFSET: usize = 2;
    pub const TEE_TYPE_OFFSET: usize = 4;
    pub const QE_SVN_OFFSET: usize = 28;
    pub const PCE_SVN_OFFSET: usize = 30;
    pub const QE_VENDOR_ID_OFFSET: usize = 32;
    pub const HEADER_LEN: usize = 48;
    pub const QUOTE_VERSION_4: u16 = 4;
    pub const ATT_KEY_ECDSA_P256: u16 = 2;
    pub const TEE_TYPE_TDX: u32 = 0x0000_0081;
    pub const BODY_LEN: usize = 584;
    pub const TEE_TCB_SVN_OFFSET: usize = 48;
    pub const TD_ATTRIBUTES_OFFSET: usize = 168;
    pub const DEBUG_FLAG: u64 = 1;
    pub const MR_TD_OFFSET: usize = 184;
    pub const RTMR0_OFFSET: usize = 376;
    pub const REPORT_DATA_OFFSET: usize = 568;
    pub const REPORT_DATA_LEN: usize = 64;
    pub const QE_REPORT_OFFSET: usize = 632;
    pub const QE_REPORT_LEN: usize = 384;
    pub const QE_REPORT_DATA_OFFSET: usize = QE_REPORT_OFFSET + 320;
    pub const QE_REPORT_SIG_OFFSET: usize = 1016;
    pub const QE_REPORT_SIG_LEN: usize = 64;
    pub const QE_AUTH_DATA_LEN_OFFSET: usize = 1080;
    /// End of the fixed section: header + body + QE report + QE signature
    /// + auth-data length field.
    pub const FIXED_LEN: usize = 1082;
}

/// Parsed Intel TDX DCAP quote (v4): the TD report body plus the QE
/// certification that vouches for it, plus the attestation public key the
/// QE report binds (conveyed explicitly so the binding is checkable
/// without platform calls).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdxQuote {
    pub version: u16,
    pub att_key_type: u16,
    pub tee_type: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub qe_vendor_id: [u8; 16],
    pub tee_tcb_svn: [u8; 16],
    pub td_attributes: u64,
    pub mr_td: [u8; 48],
    pub rtmrs: [[u8; 48]; 4],
    /// Full 64-byte TD report_data; bytes [..32] carry the session binding.
    pub report_data: [u8; 64],
    /// Raw QE report bytes (384).
    pub qe_report: [u8; 384],
    /// Raw QE report signature, r||s (64).
    pub qe_report_sig: [u8; 64],
    pub qe_auth_data: Vec<u8>,
    /// Concatenated DER certificates, leaf first.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// Attestation public key, uncompressed SEC1 (65 B, 0x04||X||Y).
    pub attestation_pubkey: [u8; 65],
}

impl TdxQuote {
    pub fn debug_enabled(&self) -> bool {
        self.td_attributes & tdx_layout::DEBUG_FLAG != 0
    }

    pub fn report_binding(&self) -> [u8; 32] {
        self.report_data[..32].try_into().expect("slice of 32")
    }

    /// Composite measurement id for the SLA allowlist:
    /// SHA256(mr_td || rtmr0 || rtmr1 || rtmr2 || rtmr3).
    pub fn measurement_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.mr_td);
        for rtmr in &self.rtmrs {
            h.update(rtmr);
        }
        h.finalize().into()
    }

    /// Encode the genuine DCAP v4 layout (header + TD body + QE report +
    /// QE signature + auth data + concatenated raw DER certs) plus the
    /// 65-byte attestation-pubkey trailer. Reserved TD fields we do not
    /// model encode as zero. The output (minus trailer) is byte-layout
    /// compatible with real DCAP quotes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = vec![0u8; tdx_layout::FIXED_LEN];
        w[tdx_layout::VERSION_OFFSET..tdx_layout::VERSION_OFFSET + 2]
            .copy_from_slice(&self.version.to_le_bytes());
        w[tdx_layout::ATT_KEY_TYPE_OFFSET..tdx_layout::ATT_KEY_TYPE_OFFSET + 2]
            .copy_from_slice(&self.att_key_type.to_le_bytes());
        w[tdx_layout::TEE_TYPE_OFFSET..tdx_layout::TEE_TYPE_OFFSET + 4]
            .copy_from_slice(&self.tee_type.to_le_bytes());
        // Reserved bytes stay zero.
        w[tdx_layout::QE_SVN_OFFSET..tdx_layout::QE_SVN_OFFSET + 2]
            .copy_from_slice(&self.qe_svn.to_le_bytes());
        w[tdx_layout::PCE_SVN_OFFSET..tdx_layout::PCE_SVN_OFFSET + 2]
            .copy_from_slice(&self.pce_svn.to_le_bytes());
        w[tdx_layout::QE_VENDOR_ID_OFFSET..tdx_layout::QE_VENDOR_ID_OFFSET + 16]
            .copy_from_slice(&self.qe_vendor_id);
        w[tdx_layout::TEE_TCB_SVN_OFFSET..tdx_layout::TEE_TCB_SVN_OFFSET + 16]
            .copy_from_slice(&self.tee_tcb_svn);
        w[tdx_layout::TD_ATTRIBUTES_OFFSET..tdx_layout::TD_ATTRIBUTES_OFFSET + 8]
            .copy_from_slice(&self.td_attributes.to_le_bytes());
        w[tdx_layout::MR_TD_OFFSET..tdx_layout::MR_TD_OFFSET + 48].copy_from_slice(&self.mr_td);
        for (i, rtmr) in self.rtmrs.iter().enumerate() {
            let o = tdx_layout::RTMR0_OFFSET + i * 48;
            w[o..o + 48].copy_from_slice(rtmr);
        }
        w[tdx_layout::REPORT_DATA_OFFSET..tdx_layout::REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&self.report_data);
        w[tdx_layout::QE_REPORT_OFFSET..tdx_layout::QE_REPORT_OFFSET + 384]
            .copy_from_slice(&self.qe_report);
        w[tdx_layout::QE_REPORT_SIG_OFFSET..tdx_layout::QE_REPORT_SIG_OFFSET + 64]
            .copy_from_slice(&self.qe_report_sig);
        let auth_len = self.qe_auth_data.len();
        w[tdx_layout::QE_AUTH_DATA_LEN_OFFSET..tdx_layout::QE_AUTH_DATA_LEN_OFFSET + 2]
            .copy_from_slice(&(auth_len as u16).to_le_bytes());
        w.extend_from_slice(&self.qe_auth_data);
        for cert in &self.cert_chain_der {
            w.extend_from_slice(cert);
        }
        w.extend_from_slice(&self.attestation_pubkey);
        // Envelope version byte up front.
        let mut out = Vec::with_capacity(1 + w.len());
        out.push(1u8);
        out.extend_from_slice(&w);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TeeError> {
        use tdx_layout as L;
        let malformed = |d: &str| TeeError::Malformed(format!("tdx quote {d}"));
        if bytes.is_empty() || bytes[0] != 1 {
            return Err(malformed("unknown encoding version"));
        }
        let b = &bytes[1..];
        if b.len() < L::FIXED_LEN + 65 {
            return Err(malformed("truncated"));
        }
        let u16le = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32le = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64le = |o: usize| {
            u64::from_le_bytes([
                b[o],
                b[o + 1],
                b[o + 2],
                b[o + 3],
                b[o + 4],
                b[o + 5],
                b[o + 6],
                b[o + 7],
            ])
        };
        if u16le(L::VERSION_OFFSET) != L::QUOTE_VERSION_4 {
            return Err(malformed("unsupported quote version"));
        }
        if u16le(L::ATT_KEY_TYPE_OFFSET) != L::ATT_KEY_ECDSA_P256 {
            return Err(malformed("unsupported attestation key type"));
        }
        if u32le(L::TEE_TYPE_OFFSET) != L::TEE_TYPE_TDX {
            return Err(malformed("not a TDX quote"));
        }
        let mut qe_vendor_id = [0u8; 16];
        qe_vendor_id.copy_from_slice(&b[L::QE_VENDOR_ID_OFFSET..L::QE_VENDOR_ID_OFFSET + 16]);
        let mut tee_tcb_svn = [0u8; 16];
        tee_tcb_svn.copy_from_slice(&b[L::TEE_TCB_SVN_OFFSET..L::TEE_TCB_SVN_OFFSET + 16]);
        let mut mr_td = [0u8; 48];
        mr_td.copy_from_slice(&b[L::MR_TD_OFFSET..L::MR_TD_OFFSET + 48]);
        let mut rtmrs = [[0u8; 48]; 4];
        for (i, rtmr) in rtmrs.iter_mut().enumerate() {
            let o = L::RTMR0_OFFSET + i * 48;
            rtmr.copy_from_slice(&b[o..o + 48]);
        }
        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&b[L::REPORT_DATA_OFFSET..L::REPORT_DATA_OFFSET + 64]);
        let mut qe_report = [0u8; 384];
        qe_report.copy_from_slice(&b[L::QE_REPORT_OFFSET..L::QE_REPORT_OFFSET + 384]);
        let mut qe_report_sig = [0u8; 64];
        qe_report_sig.copy_from_slice(&b[L::QE_REPORT_SIG_OFFSET..L::QE_REPORT_SIG_OFFSET + 64]);
        let auth_len = u16le(L::QE_AUTH_DATA_LEN_OFFSET) as usize;
        if auth_len > 16_384 {
            return Err(malformed("auth data over cap"));
        }
        let mut cursor = L::FIXED_LEN;
        let auth_end = cursor
            .checked_add(auth_len)
            .ok_or_else(|| malformed("length overflow"))?;
        if auth_end + 65 > b.len() {
            return Err(malformed("truncated auth data"));
        }
        let qe_auth_data = b[cursor..auth_end].to_vec();
        cursor = auth_end;
        // The certificate chain runs to 65 bytes before the end: the
        // attestation-pubkey trailer. Split the stream into DER certificates.
        let chain_end = b
            .len()
            .checked_sub(65)
            .ok_or_else(|| malformed("truncated pubkey trailer"))?;
        if cursor >= chain_end {
            return Err(malformed("empty certificate chain"));
        }
        let mut cert_chain_der = Vec::new();
        let mut o = cursor;
        while o < chain_end {
            let (_tag, hdr_len, content_start, content_len) =
                der_tlv(b, o).map_err(|_| malformed("bad cert der"))?;
            if hdr_len > 8 {
                return Err(malformed("bad cert header"));
            }
            let cert_end = content_start
                .checked_add(content_len)
                .ok_or_else(|| malformed("length overflow"))?;
            if cert_end > chain_end || cert_end - o > MAX_CERT_BYTES {
                return Err(malformed("cert out of range"));
            }
            cert_chain_der.push(b[o..cert_end].to_vec());
            o = cert_end;
            if cert_chain_der.len() > MAX_CHAIN_CERTS {
                return Err(malformed("cert count out of range"));
            }
        }
        let tail = b
            .get(chain_end..)
            .ok_or_else(|| malformed("truncated pubkey trailer"))?;
        if tail.len() != 65 || tail[0] != 0x04 {
            return Err(malformed("attestation key is not uncompressed P-256"));
        }
        let mut attestation_pubkey = [0u8; 65];
        attestation_pubkey.copy_from_slice(tail);
        let _ = cursor;
        Ok(TdxQuote {
            version: u16le(L::VERSION_OFFSET),
            att_key_type: u16le(L::ATT_KEY_TYPE_OFFSET),
            tee_type: u32le(L::TEE_TYPE_OFFSET),
            qe_svn: u16le(L::QE_SVN_OFFSET),
            pce_svn: u16le(L::PCE_SVN_OFFSET),
            qe_vendor_id,
            tee_tcb_svn,
            td_attributes: u64le(L::TD_ATTRIBUTES_OFFSET),
            mr_td,
            rtmrs,
            report_data,
            qe_report,
            qe_report_sig,
            qe_auth_data,
            cert_chain_der,
            attestation_pubkey,
        })
    }
}

// ---------------------------------------------------------------------------
// AMD SEV-SNP attestation report
// ---------------------------------------------------------------------------

/// SNP report field offsets per the AMD SEV-SNP ABI (report version 2/3
/// layout, 1184-byte report + 512-byte P-384 signature). Only the fields
/// this crate checks are named; everything else is skipped by offset.
/// RE-VERIFY AT HARDWARE GATING, especially SNP_POLICY_DEBUG_BIT.
pub mod snp_layout {
    /// Total report bytes before the signature.
    pub const REPORT_LEN: usize = 1184;
    /// P-384 signature length.
    pub const SIG_LEN: usize = 512;
    pub const VERSION_OFFSET: usize = 0;
    pub const POLICY_OFFSET: usize = 8;
    /// DEBUG policy bit. Per the AMD SEV-SNP ABI specification, policy bit
    /// 19 disables debugging restrictions when set; RE-VERIFY this offset
    /// against the spec at hardware gating time.
    pub const SNP_POLICY_DEBUG_BIT: u64 = 19;
    pub const REPORT_DATA_OFFSET: usize = 80;
    pub const MEASUREMENT_OFFSET: usize = 144;
    pub const REPORTED_TCB_OFFSET: usize = 384;
    pub const CHIP_ID_OFFSET: usize = 392;
    pub const CURRENT_TCB_OFFSET: usize = 56;
}

/// Parsed AMD SEV-SNP attestation report (ABI v2/v3 layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpReport {
    pub version: u32,
    pub policy: u64,
    /// Full 64-byte report_data; bytes [..32] carry the session binding.
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub reported_tcb: [u8; 8],
    pub current_tcb: [u8; 8],
    pub chip_id: [u8; 64],
    /// P-384 signature over the report. Verified only once a P-384
    /// verifier is approved; until then any SNP chain check fails closed.
    pub signature: [u8; 512],
}

impl SnpReport {
    pub fn debug_enabled(&self) -> bool {
        self.policy & (1u64 << snp_layout::SNP_POLICY_DEBUG_BIT) != 0
    }

    pub fn report_binding(&self) -> [u8; 32] {
        self.report_data[..32].try_into().expect("slice of 32")
    }

    /// Canonical 1184-byte ABI report layout (unmodelled fields zeroed).
    /// Both encode and signature verification use these exact bytes.
    pub fn abi_bytes(&self) -> Vec<u8> {
        let mut w = vec![0u8; snp_layout::REPORT_LEN];
        w[snp_layout::VERSION_OFFSET..snp_layout::VERSION_OFFSET + 4]
            .copy_from_slice(&self.version.to_le_bytes());
        w[snp_layout::POLICY_OFFSET..snp_layout::POLICY_OFFSET + 8]
            .copy_from_slice(&self.policy.to_le_bytes());
        w[snp_layout::CURRENT_TCB_OFFSET..snp_layout::CURRENT_TCB_OFFSET + 8]
            .copy_from_slice(&self.current_tcb);
        w[snp_layout::REPORT_DATA_OFFSET..snp_layout::REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&self.report_data);
        w[snp_layout::MEASUREMENT_OFFSET..snp_layout::MEASUREMENT_OFFSET + 48]
            .copy_from_slice(&self.measurement);
        w[snp_layout::REPORTED_TCB_OFFSET..snp_layout::REPORTED_TCB_OFFSET + 8]
            .copy_from_slice(&self.reported_tcb);
        w[snp_layout::CHIP_ID_OFFSET..snp_layout::CHIP_ID_OFFSET + 64]
            .copy_from_slice(&self.chip_id);
        w
    }

    /// Composite measurement id for the SLA allowlist:
    /// SHA256(measurement).
    pub fn measurement_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.measurement);
        h.finalize().into()
    }

    pub fn encode(&self) -> Vec<u8> {
        // Envelope version byte + canonical ABI report + 512-byte signature
        // slot. The simulator carries the 96-byte P-384 signature (r||s) in
        // the first 96 bytes; the hardware gating run confirms placement
        // against real VCEK-signed reports.
        let abi = self.abi_bytes();
        let mut w = Vec::with_capacity(1 + abi.len() + snp_layout::SIG_LEN);
        w.push(1u8);
        w.extend_from_slice(&abi);
        w.extend_from_slice(&self.signature);
        w
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TeeError> {
        use snp_layout as L;
        let malformed = |d: &str| TeeError::Malformed(format!("snp report {d}"));
        if bytes.is_empty() || bytes[0] != 1 {
            return Err(malformed("unknown encoding version"));
        }
        let b = &bytes[1..];
        if b.len() != L::REPORT_LEN + L::SIG_LEN {
            return Err(malformed("wrong length for ABI report + signature"));
        }
        let u32le = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64le = |o: usize| {
            u64::from_le_bytes([
                b[o],
                b[o + 1],
                b[o + 2],
                b[o + 3],
                b[o + 4],
                b[o + 5],
                b[o + 6],
                b[o + 7],
            ])
        };
        let version = u32le(L::VERSION_OFFSET);
        if version != 2 && version != 3 {
            return Err(malformed("unsupported report version"));
        }
        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&b[L::REPORT_DATA_OFFSET..L::REPORT_DATA_OFFSET + 64]);
        let mut measurement = [0u8; 48];
        measurement.copy_from_slice(&b[L::MEASUREMENT_OFFSET..L::MEASUREMENT_OFFSET + 48]);
        let mut reported_tcb = [0u8; 8];
        reported_tcb.copy_from_slice(&b[L::REPORTED_TCB_OFFSET..L::REPORTED_TCB_OFFSET + 8]);
        let mut current_tcb = [0u8; 8];
        current_tcb.copy_from_slice(&b[L::CURRENT_TCB_OFFSET..L::CURRENT_TCB_OFFSET + 8]);
        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(&b[L::CHIP_ID_OFFSET..L::CHIP_ID_OFFSET + 64]);
        let mut signature = [0u8; 512];
        signature.copy_from_slice(&b[L::REPORT_LEN..L::REPORT_LEN + L::SIG_LEN]);
        Ok(SnpReport {
            version,
            policy: u64le(L::POLICY_OFFSET),
            report_data,
            measurement,
            reported_tcb,
            current_tcb,
            chip_id,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// NVIDIA GPU attestation report (NRAS-style JWT)
// ---------------------------------------------------------------------------

/// Required JWT claim names, following the NVIDIA remote-attestation
/// report shape. `x-nvidia-overall-cc-mode` must be `"on"`;
/// `measurements` is an array of hex-encoded digests; `nonce` is the
/// hex-encoded 32-byte session binding; `exp` is a unix timestamp.
pub mod nvidia_layout {
    pub const CC_MODE_CLAIM: &str = "x-nvidia-overall-cc-mode";
    pub const CC_MODE_ON: &str = "on";
    pub const MEASUREMENTS_CLAIM: &str = "measurements";
    pub const NONCE_CLAIM: &str = "nonce";
    pub const EXP_CLAIM: &str = "exp";
    pub const ISS_CLAIM: &str = "iss";
    pub const FW_VERSION_CLAIM: &str = "fw_version";
    pub const MAX_ISS_LEN: usize = 256;
    pub const MAX_MEASUREMENTS: usize = 32;
}

/// Parsed NVIDIA GPU attestation report: a P-256-signed JWT whose claims
/// carry CC mode, measurements, the session nonce binding and expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvidiaReport {
    /// Raw ASCII `header_b64.payload_b64` (the JWS signing input).
    pub signing_input: Vec<u8>,
    /// Raw 64-byte JWS ES256 signature (r||s).
    pub signature: [u8; 64],
    pub cc_mode_on: bool,
    pub measurements: Vec<[u8; 32]>,
    /// Hex-decoded 32-byte nonce binding from the claims.
    pub report_binding: [u8; 32],
    pub exp_unix: u64,
    pub issuer: String,
    /// Firmware TCB version from the `fw_version` claim (0 if absent).
    pub fw_version: u64,
}

impl NvidiaReport {
    /// Composite measurement id for the SLA allowlist: SHA256 over the
    /// sorted concatenated measurement digests.
    pub fn measurement_id(&self) -> [u8; 32] {
        let mut blobs: Vec<&[u8]> = self.measurements.iter().map(|m| &m[..]).collect();
        blobs.sort_unstable();
        let mut h = Sha256::new();
        for b in blobs {
            h.update(b);
        }
        h.finalize().into()
    }
    pub fn encode(&self) -> Vec<u8> {
        // Canonical envelope: the real JWT input bytes are preserved
        // verbatim; fw_version is a parsed claim, re-derived on decode.
        let mut w = Vec::with_capacity(64 + self.signing_input.len());
        w.push(1u8);
        w.extend_from_slice(&(self.signing_input.len() as u32).to_le_bytes());
        w.extend_from_slice(&self.signing_input);
        w.extend_from_slice(&self.signature);
        w
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TeeError> {
        let malformed = |d: &str| TeeError::Malformed(format!("nvidia report {d}"));
        if bytes.len() < 1 + 4 + 64 + 3 {
            return Err(malformed("truncated"));
        }
        if bytes[0] != 1 {
            return Err(malformed("unknown encoding version"));
        }
        let len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        if len > 65_536 {
            return Err(malformed("signing input over cap"));
        }
        let input = bytes
            .get(5..5 + len)
            .ok_or_else(|| malformed("truncated input"))?;
        let sig = bytes
            .get(5 + len..5 + len + 64)
            .ok_or_else(|| malformed("truncated sig"))?;
        if 5 + len + 64 != bytes.len() {
            return Err(malformed("trailing bytes"));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(sig);
        Self::from_signing_input(input, signature)
    }

    /// Parse and policy-check a raw `header_b64.payload_b64` signing input
    /// plus its detached signature. Shared by decode and the node-side
    /// fetch path so both enforce the same claims.
    pub fn from_signing_input(signing_input: &[u8], signature: [u8; 64]) -> Result<Self, TeeError> {
        use base64::Engine as _;
        let malformed = |d: &str| TeeError::Malformed(format!("nvidia report {d}"));
        let input = std::str::from_utf8(signing_input)
            .map_err(|_| malformed("signing input is not ASCII"))?;
        let mut parts = input.splitn(3, '.');
        let (header_b64, payload_b64) = match (parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), None) => (h, p),
            _ => return Err(malformed("not a two-part JWS input")),
        };
        if header_b64.is_empty() || payload_b64.is_empty() {
            return Err(malformed("empty JWT part"));
        }
        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(header_b64)
                .map_err(|_| malformed("bad header base64"))?,
        )
        .map_err(|_| malformed("bad header json"))?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
            return Err(malformed("unexpected JWS alg"));
        }
        let payload: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload_b64)
                .map_err(|_| malformed("bad payload base64"))?,
        )
        .map_err(|_| malformed("bad payload json"))?;
        let get_str = |name: &str| {
            payload
                .get(name)
                .and_then(|v| v.as_str())
                .ok_or_else(|| malformed("missing claim"))
        };
        if get_str(nvidia_layout::CC_MODE_CLAIM)? != nvidia_layout::CC_MODE_ON {
            return Err(TeeError::Malformed("cc mode is not on".into()));
        }
        let measurements_raw = payload
            .get(nvidia_layout::MEASUREMENTS_CLAIM)
            .and_then(|v| v.as_array())
            .ok_or_else(|| malformed("missing claim"))?;
        if measurements_raw.is_empty() || measurements_raw.len() > nvidia_layout::MAX_MEASUREMENTS {
            return Err(malformed("measurements out of range"));
        }
        let mut measurements = Vec::with_capacity(measurements_raw.len());
        for m in measurements_raw {
            let hex = m.as_str().ok_or_else(|| malformed("bad measurement"))?;
            let raw = hex_decode_32(hex).ok_or_else(|| malformed("bad measurement"))?;
            measurements.push(raw);
        }
        let nonce_hex = get_str(nvidia_layout::NONCE_CLAIM)?;
        let report_binding = hex_decode_32(nonce_hex).ok_or_else(|| malformed("bad nonce"))?;
        let exp_unix = payload
            .get(nvidia_layout::EXP_CLAIM)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| malformed("bad exp"))?;
        let issuer = get_str(nvidia_layout::ISS_CLAIM)?;
        if issuer.len() > nvidia_layout::MAX_ISS_LEN {
            return Err(malformed("iss over cap"));
        }
        // Firmware TCB version is optional: absent means 0, which only
        // passes a zero minimum.
        let fw_version = payload
            .get(nvidia_layout::FW_VERSION_CLAIM)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(NvidiaReport {
            signing_input: signing_input.to_vec(),
            signature,
            cc_mode_on: true,
            measurements,
            report_binding,
            exp_unix,
            issuer: issuer.to_string(),
            fw_version,
        })
    }
}

fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Policy inputs, roots and verification
// ---------------------------------------------------------------------------

/// Expected report-data binding: `SHA256(ephem_pubkey || nonce_le)`.
pub fn expected_report_binding(ephem_pubkey: &[u8], nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ephem_pubkey);
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

/// Operator-configured trust for vendor chains: pinned root SPKI hashes
/// (SHA256 over the canonical DER SubjectPublicKeyInfo), CRL serials as
/// raw big-endian bytes, and the TCB minimums per family.
#[derive(Clone, Debug, Default)]
pub struct VendorRoots {
    /// SHA256(canonical DER SPKI) of each trusted root, any family.
    pub pinned_root_spki: Vec<[u8; 32]>,
    /// Revoked certificate serials (raw big-endian), any level.
    pub revoked_serials: Vec<Vec<u8>>,
}

/// TCB minimums per family, compared as 16-byte big-endian against the
/// normalised [`VendorEvidence::tcb_svn`].
#[derive(Clone, Debug, Default)]
pub struct TcbPolicy {
    pub min_tdx_svn: [u8; 16],
    pub min_snp_tcb: [u8; 16],
    pub min_nvidia_fw: [u8; 16],
}

impl TcbPolicy {
    pub fn minimum_for(&self, family: VendorFamily) -> [u8; 16] {
        match family {
            VendorFamily::Tdx => self.min_tdx_svn,
            VendorFamily::Snp => self.min_snp_tcb,
            VendorFamily::Nvidia => self.min_nvidia_fw,
        }
    }
}

/// Inputs the verifier needs beyond the evidence itself. No clock and no
/// network inside: the caller supplies time, the expected binding inputs
/// and the revocation/status inputs (fetched node-side via the pluggable
/// RIM/PCK/KDS fetchers).
#[derive(Clone, Debug)]
pub struct VendorInputs {
    /// Unix time the caller vouches for (cert validity, report expiry).
    pub now_unix: u64,
    /// Enclave ephemeral public key presented over the attested channel.
    pub presented_pubkey: Vec<u8>,
    /// Session nonce the quote must bind.
    pub expected_nonce: u64,
    /// Approved composite measurement (see [`VendorEvidence::measurement_id`]).
    /// Used by the standalone [`verify_tdx`]/[`verify_snp`]/[`verify_nvidia`]
    /// calls (node-side pre-checks, tests). The full quote path
    /// (`TeeVerifier::verify_v2`) takes the SLA's `measurement` instead —
    /// the consumer's signed policy is the single source of truth there.
    pub approved_measurement: [u8; 32],
    /// Per-family TCB minimums.
    pub tcb: TcbPolicy,
    /// Pinned roots + CRL serials.
    pub roots: VendorRoots,
    /// Whether a debug-enabled guest is accepted. Defaults off; opting in
    /// is explicit because debug guests are inspectable by the host.
    /// Mirrors the SLA flag; the verifier copies the SLA value in.
    pub allow_debug: bool,
    /// Pinned NVIDIA report-signing key (uncompressed SEC1). Required only
    /// when the evidence is NVIDIA; the JWT is verified against this key.
    pub nvidia_signing_key: Option<[u8; 65]>,
    /// DER-encoded VCEK/VLEK certificate chain, leaf first (fetched
    /// node-side via KDS). Required only when the evidence is SNP.
    pub snp_vcek_chain: Vec<Vec<u8>>,
}

impl VendorInputs {
    pub fn binding_ok(&self, evidence: &VendorEvidence) -> bool {
        evidence.report_binding()
            == expected_report_binding(&self.presented_pubkey, self.expected_nonce)
    }

    pub fn binding_matches(&self, report_binding: &[u8; 32]) -> bool {
        *report_binding == expected_report_binding(&self.presented_pubkey, self.expected_nonce)
    }

    pub fn measurement_ok(&self, evidence: &VendorEvidence) -> bool {
        evidence.measurement_id() == self.approved_measurement
    }
}

/// Verify a raw (r||s) or DER ECDSA signature of `msg` under an
/// uncompressed SEC1 public key on `curve`.
pub fn verify_sig(
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
    curve: ChainCurve,
) -> Result<(), TeeError> {
    if pubkey.len() != curve.pubkey_len() || pubkey[0] != 0x04 {
        return Err(TeeError::Malformed("key is not uncompressed SEC1".into()));
    }
    match curve {
        ChainCurve::P256 => {
            use p256::ecdsa::signature::Verifier as _;
            let key = VerifyingKey::from_sec1_bytes(pubkey)
                .map_err(|e| TeeError::BadSignature(format!("bad p256 key: {e}")))?;
            let signature = if sig.len() == 64 {
                P256Signature::from_slice(&sig[..64])
                    .map_err(|e| TeeError::BadSignature(format!("bad raw sig: {e}")))?
            } else {
                P256Signature::from_der(sig)
                    .map_err(|e| TeeError::BadSignature(format!("bad der sig: {e}")))?
            };
            key.verify(msg, &signature)
                .map_err(|e| TeeError::BadSignature(format!("p256 verify failed: {e}")))
        }
        ChainCurve::P384 => {
            use p384::ecdsa::signature::Verifier as _;
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(pubkey)
                .map_err(|e| TeeError::BadSignature(format!("bad p384 key: {e}")))?;
            let signature = if sig.len() == 96 {
                p384::ecdsa::Signature::from_slice(&sig[..96])
                    .map_err(|e| TeeError::BadSignature(format!("bad raw sig: {e}")))?
            } else {
                p384::ecdsa::Signature::from_der(sig)
                    .map_err(|e| TeeError::BadSignature(format!("bad der sig: {e}")))?
            };
            key.verify(msg, &signature)
                .map_err(|e| TeeError::BadSignature(format!("p384 verify failed: {e}")))
        }
    }
}

/// Verify raw ECDSA P-256 (DER or 64-byte r||s) of `msg` under an
/// uncompressed SEC1 public key.
pub fn verify_p256_sig(pubkey65: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), TeeError> {
    verify_sig(pubkey65, msg, sig, ChainCurve::P256)
}

/// Split top-level DER Certificate into (tbs_der, signature_bytes).
/// Exact bytes: the signature is verified over the re-emitted TBS TLV, so
/// no re-encoding risk.
pub fn split_cert_der(der: &[u8]) -> Result<(&[u8], &[u8]), TeeError> {
    let malformed = || TeeError::Malformed("certificate DER shape".into());
    let (children, end) = der_children(der, 0).map_err(|_| malformed())?;
    if end != der.len() || children.len() != 3 {
        return Err(malformed());
    }
    let (tbs_start, tbs_end) = children[0];
    let (sig_start, sig_end) = children[2];
    let sig_tlv = der.get(sig_start..sig_end).ok_or_else(malformed)?;
    if sig_tlv.first() != Some(&0x03) {
        return Err(malformed());
    }
    let (_, _, cs, cl) = der_tlv(sig_tlv, 0).map_err(|_| malformed())?;
    let sig_content = sig_tlv.get(cs..cs + cl).ok_or_else(malformed)?;
    if sig_content.is_empty() || sig_content[0] != 0 {
        return Err(malformed());
    }
    let tbs = der.get(tbs_start..tbs_end).ok_or_else(malformed)?;
    Ok((tbs, &sig_content[1..]))
}

/// Minimal DER reader: tag + length only, no value parsing. Returns the
/// byte ranges of the immediate children of the SEQUENCE at `off`, plus
/// the offset just past the sequence.
fn der_children(der: &[u8], off: usize) -> Result<(Vec<(usize, usize)>, usize), ()> {
    let (tag, hdr_len, content_start, content_len) = der_tlv(der, off)?;
    if tag != 0x30 {
        return Err(());
    }
    let mut children = Vec::new();
    let mut o = content_start;
    let end = content_start.checked_add(content_len).ok_or(())?;
    if end > der.len() || hdr_len > 8 {
        return Err(());
    }
    while o < end {
        let (ctag, chdr, cstart, clen) = der_tlv(der, o)?;
        let _ = ctag;
        let cend = cstart.checked_add(clen).ok_or(())?;
        if cend > end || chdr > 8 {
            return Err(());
        }
        children.push((o, cend));
        o = cend;
        if children.len() > 64 {
            return Err(());
        }
    }
    if o != end {
        return Err(());
    }
    Ok((children, end))
}

/// Read one TLV header at `off`: (tag, header_len, content_start,
/// content_len). Rejects indefinite and overlong forms.
fn der_tlv(der: &[u8], off: usize) -> Result<(u8, usize, usize, usize), ()> {
    let tag = *der.get(off).ok_or(())?;
    let l0 = *der.get(off + 1).ok_or(())?;
    if l0 < 0x80 {
        let len = l0 as usize;
        Ok((tag, 2, off + 2, len))
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(());
        }
        let lb = der.get(off + 2..off + 2 + n).ok_or(())?;
        if lb[0] == 0 {
            return Err(());
        }
        let mut len = 0usize;
        for b in lb {
            len = len
                .checked_mul(256)
                .ok_or(())?
                .checked_add(*b as usize)
                .ok_or(())?;
        }
        if len < 128 {
            return Err(());
        }
        Ok((tag, 2 + n, off + 2 + n, len))
    }
}

/// Canonical DER encoding of a SubjectPublicKeyInfo for an uncompressed
/// key on `curve`, used for root pinning (SHA256 over these bytes).
/// ecPublicKey = 06 07 2A 86 48 CE 3D 02 01.
pub fn canonical_spki_der(pubkey: &[u8], curve: ChainCurve) -> Result<Vec<u8>, TeeError> {
    if pubkey.len() != curve.pubkey_len() || pubkey[0] != 0x04 {
        return Err(TeeError::Malformed("key is not uncompressed SEC1".into()));
    }
    // SEQUENCE { SEQUENCE { OID ecPublicKey, OID namedCurve }, BIT STRING }.
    let mut alg_body = vec![0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    alg_body.extend_from_slice(&match curve {
        ChainCurve::P256 => vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // secp384r1 1.3.132.0.34.
        ChainCurve::P384 => vec![0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
    });
    let alg = der_wrap(0x30, &alg_body);
    let mut bitstring_body = vec![0x00];
    bitstring_body.extend_from_slice(pubkey);
    let bitstring = der_wrap(0x03, &bitstring_body);
    let mut spki_body = alg;
    spki_body.extend_from_slice(&bitstring);
    Ok(der_wrap(0x30, &spki_body))
}

fn der_wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(body);
    out
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else {
        let mut b = Vec::new();
        let mut v = n;
        while v > 0 {
            b.push((v & 0xff) as u8);
            v >>= 8;
        }
        b.reverse();
        let mut out = vec![0x80 | (b.len() as u8)];
        out.extend_from_slice(&b);
        out
    }
}

/// Curve used by one link of a vendor certificate chain. P-256 covers
/// Intel PCK chains and NVIDIA JWT keys; P-384 covers AMD VCEK/VLEK
/// chains and SNP report signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainCurve {
    P256,
    P384,
}

impl ChainCurve {
    /// DER content bytes of the named-curve parameters.
    fn params_content(&self) -> &'static [u8] {
        match self {
            // secp256r1 1.2.840.10045.3.1.7 value bytes.
            ChainCurve::P256 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
            // secp384r1 1.3.132.0.34 value bytes.
            ChainCurve::P384 => &[0x2B, 0x81, 0x04, 0x00, 0x22],
        }
    }

    fn pubkey_len(&self) -> usize {
        match self {
            ChainCurve::P256 => 65,
            ChainCurve::P384 => 97,
        }
    }

    fn sig_alg_oid(&self) -> &'static str {
        match self {
            // ecdsa-with-SHA256 / ecdsa-with-SHA384.
            ChainCurve::P256 => "1.2.840.10045.4.3.2",
            ChainCurve::P384 => "1.2.840.10045.4.3.3",
        }
    }
}

/// Extract an uncompressed public key for `curve` from a parsed SPKI,
/// enforcing the algorithm OID (ecPublicKey) and the named-curve
/// parameters.
fn uncompressed_key(
    spki: &x509_parser::x509::SubjectPublicKeyInfo,
    curve: ChainCurve,
) -> Result<Vec<u8>, TeeError> {
    // OID ecPublicKey 1.2.840.10045.2.1. `Any.data` is the content bytes
    // (tag/length stripped), so the params compare against the bare OID
    // value bytes.
    let is_curve = spki.algorithm.algorithm.to_id_string() == "1.2.840.10045.2.1"
        && spki
            .algorithm
            .parameters
            .as_ref()
            .map(|p| p.data == curve.params_content())
            .unwrap_or(false);
    if !is_curve {
        return Err(TeeError::Malformed("non-matching subject key".into()));
    }
    if spki.subject_public_key.data.len() != curve.pubkey_len()
        || spki.subject_public_key.data[0] != 0x04
    {
        return Err(TeeError::Malformed(
            "subject key is not the expected uncompressed key".into(),
        ));
    }
    Ok(spki.subject_public_key.data.to_vec())
}

/// Walk a leaf-first DER chain to a pinned root. Verifies every link
/// signature (ECDSA with the chain's hash: SHA-256 for P-256, SHA-384 for
/// P-384), DN chaining, validity window and CRL serials. Returns the leaf
/// public key (uncompressed SEC1).
#[allow(clippy::too_many_arguments)]
pub fn verify_cert_chain(
    chain_der: &[Vec<u8>],
    pinned_root_spki: &[[u8; 32]],
    revoked_serials: &[Vec<u8>],
    now_unix: u64,
    curve: ChainCurve,
) -> Result<Vec<u8>, TeeError> {
    use x509_parser::prelude::FromDer;
    let malformed = |d: &str| TeeError::Malformed(format!("cert chain {d}"));
    if chain_der.is_empty() || chain_der.len() > MAX_CHAIN_CERTS {
        return Err(malformed("cert count out of range"));
    }
    for der in chain_der {
        if der.len() > MAX_CERT_BYTES || der.is_empty() {
            return Err(malformed("cert size out of range"));
        }
    }
    // Parse every cert first (fail-closed before any crypto).
    let mut certs = Vec::with_capacity(chain_der.len());
    for der in chain_der {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|_| malformed("unparseable certificate"))?;
        certs.push(cert);
    }
    // Walk leaf -> ... -> pinned root.
    let mut leaf_key = None;
    for (i, cert) in certs.iter().enumerate() {
        let tbs = &cert.tbs_certificate;
        if tbs.serial.to_bytes_be().is_empty() {
            return Err(malformed("empty serial"));
        }
        if revoked_serials
            .iter()
            .any(|s| *s == tbs.serial.to_bytes_be())
        {
            return Err(TeeError::RevokedVendorCert);
        }
        let not_before = tbs.validity.not_before.timestamp();
        let not_after = tbs.validity.not_after.timestamp();
        if not_before < 0 || not_after < 0 {
            return Err(malformed("negative validity time"));
        }
        if (now_unix as i64) < not_before || (now_unix as i64) > not_after {
            return Err(TeeError::Expired);
        }
        let subject_key = uncompressed_key(&tbs.subject_pki, curve)?;
        // If this cert's SPKI is pinned, it is the trust anchor: stop.
        // Every cert below it was already checked against its issuer.
        let spki_der = canonical_spki_der(&subject_key, curve)?;
        let mut digest = Sha256::new();
        digest.update(&spki_der);
        let pin: [u8; 32] = digest.finalize().into();
        if i == 0 {
            leaf_key = Some(subject_key.clone());
        }
        if pinned_root_spki.contains(&pin) {
            break;
        }
        // Otherwise the next cert must exist and issue this one.
        let next = certs
            .get(i + 1)
            .ok_or_else(|| malformed("chain ends before a pinned root"))?;
        if tbs.issuer.as_raw() != next.tbs_certificate.subject.as_raw() {
            return Err(TeeError::Malformed("issuer/subject mismatch".into()));
        }
        // Signature algorithm must match the chain's curve hash at every link.
        if cert.signature.algorithm.to_id_string() != curve.sig_alg_oid() {
            return Err(TeeError::Malformed("non-matching link signature".into()));
        }
        let next_key = uncompressed_key(&next.tbs_certificate.subject_pki, curve)?;
        let (tbs_der, sig_bytes) = split_cert_der(&chain_der[i])?;
        verify_sig(&next_key, tbs_der, sig_bytes, curve)?;
    }
    // The loop breaks only at a pinned root; reaching here through the
    // last cert without a pin means no anchor.
    leaf_key.ok_or_else(|| malformed("chain ends before a pinned root"))
}

/// Full TDX verification: policy, QE binding, chain, QE signature,
/// measurement, report-data binding.
pub fn verify_tdx(evidence: &TdxQuote, inputs: &VendorInputs) -> Result<(), TeeError> {
    if evidence.debug_enabled() && !inputs.allow_debug {
        return Err(TeeError::DebugForbidden);
    }
    if evidence.tee_tcb_svn < inputs.tcb.minimum_for(VendorFamily::Tdx) {
        return Err(TeeError::TcbTooOld);
    }
    // QE report binds the attestation key: report_data[..32] ==
    // SHA256(attestation_pubkey || qe_auth_data).
    let mut h = Sha256::new();
    h.update(evidence.attestation_pubkey);
    h.update(&evidence.qe_auth_data);
    let qe_binding: [u8; 32] = h.finalize().into();
    if evidence.qe_report[320..352] != qe_binding {
        return Err(TeeError::BadSignature(
            "qe report does not bind the attestation key".into(),
        ));
    }
    // Chain to a pinned root; leaf key signs the QE report.
    let leaf_key = verify_cert_chain(
        &evidence.cert_chain_der,
        &inputs.roots.pinned_root_spki,
        &inputs.roots.revoked_serials,
        inputs.now_unix,
        ChainCurve::P256,
    )?;
    verify_sig(
        &leaf_key,
        &evidence.qe_report,
        &evidence.qe_report_sig,
        ChainCurve::P256,
    )?;
    // Approved measurement only.
    if !inputs.measurement_ok(&VendorEvidence::Tdx(evidence.clone())) {
        return Err(TeeError::MeasurementMismatch);
    }
    // Session binding: report_data[..32] == SHA256(pubkey || nonce).
    if !inputs.binding_ok(&VendorEvidence::Tdx(evidence.clone())) {
        return Err(TeeError::BadReportData);
    }
    Ok(())
}

/// Full SNP verification: policy, TCB, VCEK/VLEK chain to a pinned AMD
/// root, P-384 report signature, measurement, report-data binding.
pub fn verify_snp(evidence: &SnpReport, inputs: &VendorInputs) -> Result<(), TeeError> {
    if evidence.debug_enabled() && !inputs.allow_debug {
        return Err(TeeError::DebugForbidden);
    }
    let mut reported = [0u8; 16];
    reported[8..].copy_from_slice(&evidence.reported_tcb);
    if reported < inputs.tcb.minimum_for(VendorFamily::Snp) {
        return Err(TeeError::TcbTooOld);
    }
    let mut current = [0u8; 16];
    current[8..].copy_from_slice(&evidence.current_tcb);
    if current < inputs.tcb.minimum_for(VendorFamily::Snp) {
        return Err(TeeError::TcbTooOld);
    }
    // VCEK/VLEK chain to a pinned AMD root; leaf key signs the report.
    // The DER chain is supplied by the caller (fetched node-side via KDS);
    // the verifier itself performs no network access.
    let leaf_key = verify_cert_chain(
        &inputs.snp_vcek_chain,
        &inputs.roots.pinned_root_spki,
        &inputs.roots.revoked_serials,
        inputs.now_unix,
        ChainCurve::P384,
    )?;
    // The simulator envelope carries the 96-byte P-384 signature (r||s)
    // in the first 96 bytes of the 512-byte slot; the hardware gating run
    // confirms placement against real VCEK-signed reports.
    verify_sig(
        &leaf_key,
        &evidence.abi_bytes(),
        &evidence.signature[..96],
        ChainCurve::P384,
    )?;
    if !inputs.measurement_ok(&VendorEvidence::Snp(evidence.clone())) {
        return Err(TeeError::MeasurementMismatch);
    }
    if !inputs.binding_ok(&VendorEvidence::Snp(evidence.clone())) {
        return Err(TeeError::BadReportData);
    }
    Ok(())
}

/// Full NVIDIA verification: JWT signature against the pinned key,
/// expiry, CC mode, measurement allowlist, session binding.
pub fn verify_nvidia(
    evidence: &NvidiaReport,
    inputs: &VendorInputs,
    signing_key65: &[u8; 65],
) -> Result<(), TeeError> {
    verify_p256_sig(signing_key65, &evidence.signing_input, &evidence.signature)?;
    if inputs.now_unix >= evidence.exp_unix {
        return Err(TeeError::Expired);
    }
    if !evidence.cc_mode_on {
        return Err(TeeError::Malformed("cc mode is not on".into()));
    }
    if !inputs.measurement_ok(&VendorEvidence::Nvidia(evidence.clone())) {
        return Err(TeeError::MeasurementMismatch);
    }
    if !inputs.binding_ok(&VendorEvidence::Nvidia(evidence.clone())) {
        return Err(TeeError::BadReportData);
    }
    Ok(())
}
