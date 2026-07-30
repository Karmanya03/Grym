#![deny(unsafe_code)]

use std::path::Path;

use goblin::elf::Elf;
use goblin::pe::PE;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BinaryAnalysisResult {
    pub artifact: String,
    pub file_format: FileFormat,
    pub hashes: FileHashes,
    pub hardening: HardeningProfile,
    pub strings_analysis: StringsAnalysis,
    pub entropy_analysis: EntropyAnalysis,
    pub crypto_detection: Vec<CryptoSignature>,
    pub packer_detection: Vec<PackerIndicator>,
    pub anti_analysis: AntiAnalysisIndicators,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<String>,
    pub sections: Vec<SectionInfo>,
    pub compile_info: CompileInfo,
    pub suspicious_indicators: Vec<SuspiciousIndicator>,
    pub yara_matches: Vec<YaraMatch>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum FileFormat {
    Unknown,
    PE {
        subsystem: String,
        machine: String,
        linker_version: String,
    },
    ELF {
        bits: u8,
        endian: String,
        os_abi: String,
        abi_version: u8,
    },
    MachO {
        cputype: String,
        cpusubtype: u32,
        filetype: u32,
        flags: u32,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub imphash: String,
    pub ssdeep: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HardeningProfile {
    pub nx_enabled: bool,
    pub pie_enabled: bool,
    pub stack_canary: Option<bool>,
    pub relro: RelroKind,
    pub rpath_runpath: Vec<String>,
    pub fortified: Option<bool>,
    pub safe_seh: Option<bool>,
    pub aslr: bool,
    pub cfg: Option<bool>,
    pub integrity_checks: Option<bool>,
    pub control_flow_guard: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum RelroKind {
    None,
    Partial,
    Full,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StringsAnalysis {
    pub total_count: usize,
    pub urls: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub file_paths: Vec<String>,
    pub registry_paths: Vec<String>,
    pub email_addresses: Vec<String>,
    pub encoded_strings: Vec<EncodedString>,
    pub high_entropy_strings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EncodedString {
    pub encoding: String,
    pub value: String,
    pub decoded: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EntropyAnalysis {
    pub overall_entropy: f64,
    pub sections: Vec<SectionEntropy>,
    pub packed_likelihood: f64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SectionEntropy {
    pub name: String,
    pub entropy: f64,
    pub size: u64,
    pub raw_size: u64,
    pub suspicious: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CryptoSignature {
    pub name: String,
    pub algorithm: String,
    pub location: String,
    pub confidence: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PackerIndicator {
    pub name: String,
    pub indicator: String,
    pub severity: String,
    pub confidence: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AntiAnalysisIndicators {
    pub anti_debug: Vec<String>,
    pub anti_vm: Vec<String>,
    pub anti_sandbox: Vec<String>,
    pub obfuscation: Vec<String>,
    pub timestamp_anomaly: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ImportEntry {
    pub library: String,
    pub functions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub characteristics: Vec<String>,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CompileInfo {
    pub compiler: Option<String>,
    pub compiler_version: Option<String>,
    pub linker_version: Option<String>,
    pub compile_timestamp: Option<String>,
    pub debug_info_present: bool,
    pub language: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SuspiciousIndicator {
    pub indicator: String,
    pub severity: String,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub description: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BinaryAnalysisError {
    #[error("Failed to read file: {0}")]
    Io(String),
    #[error("Failed to parse binary: {0}")]
    Parse(String),
    #[error("Unsupported file format")]
    UnsupportedFormat,
}

pub fn analyze_binary<P: AsRef<Path>>(
    path: P,
) -> Result<BinaryAnalysisResult, BinaryAnalysisError> {
    let data = std::fs::read(path.as_ref()).map_err(|e| BinaryAnalysisError::Io(e.to_string()))?;
    analyze_bytes(data, path.as_ref().to_string_lossy().as_ref())
}

pub fn analyze_bytes(
    data: Vec<u8>,
    artifact_name: &str,
) -> Result<BinaryAnalysisResult, BinaryAnalysisError> {
    let hashes = compute_hashes(&data);
    let entropy_all = calculate_entropy(&data);

    let object =
        goblin::Object::parse(&data).map_err(|e| BinaryAnalysisError::Parse(e.to_string()))?;

    let file_format = detect_format(&object);
    let sections = extract_sections(&object);
    let imports = extract_imports(&object);
    let exports = extract_exports(&object);

    let entropy_sections: Vec<SectionEntropy> = sections
        .iter()
        .map(|s| {
            let start = s.virtual_address as usize;
            let end = (start + s.virtual_size as usize).min(data.len());
            let section_data = if start < data.len() && end > start {
                &data[start..end]
            } else {
                &[]
            };
            let ent = calculate_entropy(section_data);
            let suspicious = ent > 7.0 || (s.executable && s.writable);
            SectionEntropy {
                name: s.name.clone(),
                entropy: ent,
                size: s.virtual_size,
                raw_size: s.raw_size,
                suspicious,
            }
        })
        .collect();

    let packed_likelihood = estimate_packed_likelihood(&entropy_sections, &sections);

    let hardening = analyze_hardening(&object, &sections, &data);
    let strings_analysis = analyze_strings(&data, 4);
    let crypto_detection = detect_crypto_constants(&data);
    let packer_detection = detect_packers(&sections, &strings_analysis, packed_likelihood);
    let anti_analysis = detect_anti_analysis(&data, &imports);

    let mut suspicious = Vec::new();
    if entropy_all > 7.5 {
        suspicious.push(SuspiciousIndicator {
            indicator: "High overall entropy".into(),
            severity: "medium".into(),
            detail: format!(
                "Overall entropy {:.2} suggests packing or encryption",
                entropy_all
            ),
        });
    }
    for sec in &entropy_sections {
        if sec.suspicious {
            suspicious.push(SuspiciousIndicator {
                indicator: format!("Suspicious section: {}", sec.name),
                severity: "medium".into(),
                detail: format!("Entropy {:.2}, executable={}", sec.entropy, sec.suspicious),
            });
        }
    }
    if imports.is_empty() && sections.iter().any(|s| s.executable) {
        suspicious.push(SuspiciousIndicator {
            indicator: "Executable sections with no imports".into(),
            severity: "high".into(),
            detail: "May indicate shellcode or heavily obfuscated binary".into(),
        });
    }

    let compile_info = extract_compile_info(&object, &data);

    Ok(BinaryAnalysisResult {
        artifact: artifact_name.to_string(),
        file_format,
        hashes,
        hardening,
        strings_analysis,
        entropy_analysis: EntropyAnalysis {
            overall_entropy: entropy_all,
            sections: entropy_sections,
            packed_likelihood,
        },
        crypto_detection,
        packer_detection,
        anti_analysis,
        imports,
        exports,
        sections,
        compile_info,
        suspicious_indicators: suspicious,
        yara_matches: Vec::new(),
    })
}

fn detect_format(object: &goblin::Object<'_>) -> FileFormat {
    match object {
        goblin::Object::PE(pe) => {
            let subsystem = match pe.header.optional_header {
                Some(ref oh) => format!("{:?}", oh.windows_fields.subsystem),
                None => "unknown".into(),
            };
            let machine = format!("{:?}", pe.header.coff_header.machine);
            let linker = match pe.header.optional_header {
                Some(ref oh) => format!(
                    "{}.{}",
                    oh.standard_fields.major_linker_version,
                    oh.standard_fields.minor_linker_version
                ),
                None => "unknown".into(),
            };
            FileFormat::PE {
                subsystem,
                machine,
                linker_version: linker,
            }
        }
        goblin::Object::Elf(elf) => {
            let bits = if elf.is_64 { 64 } else { 32 };
            let endian = if elf.little_endian {
                "little".into()
            } else {
                "big".into()
            };
            let os_abi_val = if elf.header.e_ident.len() > 7 {
                elf.header.e_ident[7]
            } else {
                0
            };
            let abi_ver = if elf.header.e_ident.len() > 8 {
                elf.header.e_ident[8]
            } else {
                0
            };
            let os_abi = format!("0x{:02x}", os_abi_val);
            FileFormat::ELF {
                bits,
                endian,
                os_abi,
                abi_version: abi_ver,
            }
        }
        goblin::Object::Mach(macho) => {
            let (cputype, cpusubtype, filetype, flags) = match macho {
                goblin::mach::Mach::Binary(macho_o) => {
                    let h = &macho_o.header;
                    (
                        format!("{:?}", h.cputype()),
                        h.cpusubtype(),
                        h.filetype,
                        h.flags,
                    )
                }
                goblin::mach::Mach::Fat(_multi) => ("FAT".into(), 0, 0, 0),
            };
            FileFormat::MachO {
                cputype,
                cpusubtype,
                filetype,
                flags,
            }
        }
        _ => FileFormat::Unknown,
    }
}

fn compute_hashes(data: &[u8]) -> FileHashes {
    let md5_val = {
        let mut hasher = sha1::Sha1::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };
    let sha1_val = {
        let mut hasher = sha1::Sha1::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };
    let sha256_val = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };
    FileHashes {
        md5: md5_val,
        sha1: sha1_val,
        sha256: sha256_val,
        imphash: compute_imphash(data, 10),
        ssdeep: compute_ssdeep_fuzzy(data),
    }
}

fn compute_imphash(data: &[u8], max_imports: usize) -> String {
    let mut hasher = Sha256::new();
    let mut count = 0_usize;
    let haystack = String::from_utf8_lossy(data);
    for word in haystack.split(|c: char| !c.is_ascii_alphanumeric() && c != '.') {
        if !word.is_empty() && count < max_imports {
            hasher.update(word.as_bytes());
            hasher.update(b",");
            count += 1;
        }
    }
    hex::encode(hasher.finalize())
}

fn compute_ssdeep_fuzzy(data: &[u8]) -> String {
    let chunk_size = (data.len() / 64).max(16);
    let mut chunks = Vec::new();
    for chunk in data.chunks(chunk_size) {
        let mut hasher = Sha256::new();
        hasher.update(chunk);
        chunks.push(hex::encode(hasher.finalize()));
    }
    chunks.join(":")
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] = freq[byte as usize].wrapping_add(1);
    }
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn estimate_packed_likelihood(sections: &[SectionEntropy], secs: &[SectionInfo]) -> f64 {
    if sections.is_empty() {
        return 0.0;
    }
    let avg_entropy: f64 = sections.iter().map(|s| s.entropy).sum::<f64>() / sections.len() as f64;
    let high_entropy_count = sections.iter().filter(|s| s.entropy > 7.0).count();
    let high_ratio = high_entropy_count as f64 / sections.len() as f64;
    let exec_writable_count = secs.iter().filter(|s| s.executable && s.writable).count();
    let ep_ratio = exec_writable_count as f64 / secs.len().max(1) as f64;

    (avg_entropy / 8.0) * 0.4 + high_ratio * 0.3 + ep_ratio * 0.3
}

fn analyze_hardening(
    object: &goblin::Object<'_>,
    sections: &[SectionInfo],
    data: &[u8],
) -> HardeningProfile {
    let nx_enabled = sections
        .iter()
        .any(|s| s.characteristics.contains(&"NX".into()))
        || !sections.iter().any(|s| s.executable && s.writable);

    let pie_enabled = match object {
        goblin::Object::Elf(elf) => elf.is_64 && elf.header.e_type == goblin::elf::header::ET_DYN,
        goblin::Object::PE(pe) => pe.header.coff_header.characteristics & 0x2000 != 0,
        _ => false,
    };

    let stack_canary = detect_stack_canary(data);

    let relro = detect_relro(object, sections);

    let rpath_runpath = extract_rpath_runpath(data);

    let fortified = detect_fortified(data);

    let safe_seh = match object {
        goblin::Object::PE(pe) => Some(pe.header.coff_header.characteristics & 0x0400 != 0),
        _ => None,
    };

    let aslr = match object {
        goblin::Object::PE(pe) => pe.header.coff_header.characteristics & 0x0020 != 0,
        goblin::Object::Elf(elf) => elf.header.e_type == goblin::elf::header::ET_DYN,
        _ => false,
    };

    let cfg = match object {
        goblin::Object::PE(_pe) => Some(
            sections
                .iter()
                .any(|s| s.name == ".gfids" || s.name == ".giats"),
        ),
        _ => None,
    };

    let integrity_checks = match object {
        goblin::Object::PE(pe) => Some(pe.header.coff_header.characteristics & 0x8000 != 0),
        _ => None,
    };

    let control_flow_guard = match object {
        goblin::Object::PE(_pe) => Some(sections.iter().any(|s| s.name == ".gfids")),
        _ => None,
    };

    HardeningProfile {
        nx_enabled,
        pie_enabled,
        stack_canary,
        relro,
        rpath_runpath,
        fortified,
        safe_seh,
        aslr,
        cfg,
        integrity_checks,
        control_flow_guard,
    }
}

fn detect_stack_canary(data: &[u8]) -> Option<bool> {
    let canary_patterns: &[&[u8]] = &[
        b"__stack_chk_fail",
        b"__security_cookie",
        b"_stack_protector",
    ];
    let found = canary_patterns
        .iter()
        .any(|p| data.windows(p.len()).any(|w| w == *p));
    Some(found)
}

fn detect_relro(object: &goblin::Object<'_>, sections: &[SectionInfo]) -> RelroKind {
    match object {
        goblin::Object::Elf(_) => {
            if sections.iter().any(|s| s.name == ".got") {
                RelroKind::Full
            } else if sections.iter().any(|s| s.name == ".got.plt") {
                RelroKind::Partial
            } else {
                RelroKind::None
            }
        }
        goblin::Object::PE(pe) => {
            if pe.header.coff_header.characteristics & 0x0100 != 0 {
                RelroKind::Full
            } else {
                RelroKind::Partial
            }
        }
        _ => RelroKind::None,
    }
}

fn extract_rpath_runpath(data: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let text = String::from_utf8_lossy(data);
    for token in text.split(char::is_control) {
        let trimmed = token.trim();
        if trimmed.starts_with("RPATH=") || trimmed.starts_with("RUNPATH=") {
            results.push(trimmed.to_string());
        }
    }
    results
}

fn detect_fortified(data: &[u8]) -> Option<bool> {
    let fortify_patterns: &[&[u8]] = &[
        b"__builtin_",
        b"__memcpy_chk",
        b"__strcpy_chk",
        b"_FORTIFY_SOURCE",
    ];
    let found = fortify_patterns
        .iter()
        .any(|p| data.windows(p.len()).any(|w| w == *p));
    Some(found)
}

fn analyze_strings(data: &[u8], min_length: usize) -> StringsAnalysis {
    let mut urls = Vec::new();
    let mut ips = Vec::new();
    let mut file_paths = Vec::new();
    let mut registry_paths = Vec::new();
    let mut emails = Vec::new();
    let mut encoded = Vec::new();
    let mut high_entropy = Vec::new();

    let text = String::from_utf8_lossy(data);
    let lines: Vec<&str> = text
        .split(|c| c == '\n' || c == '\r' || c == '\0')
        .collect();

    for line in &lines {
        if line.len() < min_length {
            continue;
        }
        let trimmed = line.trim();

        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            if !urls.iter().any(|x: &String| x == trimmed) {
                urls.push(trimmed.to_string());
            }
        }
        if trimmed.starts_with("HKEY_") || trimmed.contains("\\Software\\") {
            if !registry_paths.iter().any(|x: &String| x == trimmed) {
                registry_paths.push(trimmed.to_string());
            }
        }
        if (trimmed.starts_with("C:\\")
            || trimmed.starts_with("D:\\")
            || trimmed.starts_with('/')
            || trimmed.starts_with("./"))
            && trimmed.len() > 5
        {
            if !file_paths.iter().any(|x: &String| x == trimmed) {
                file_paths.push(trimmed.to_string());
            }
        }
        if trimmed.contains('@') && trimmed.contains('.') {
            let parts: Vec<&str> = trimmed.split('@').collect();
            if parts.len() > 1
                && parts[1].contains('.')
                && !emails.iter().any(|x: &String| x == trimmed)
            {
                emails.push(trimmed.to_string());
            }
        }
        if is_base64_like(trimmed) && trimmed.len() > 20 {
            encoded.push(EncodedString {
                encoding: "base64".into(),
                value: trimmed.chars().take(100).collect(),
                decoded: None,
            });
        }
        if trimmed.len() > 20 {
            let ent = calculate_entropy(trimmed.as_bytes());
            if ent > 6.5 {
                high_entropy.push(trimmed.chars().take(100).collect());
            }
        }
    }

    if let Ok(re) = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b") {
        for cap in re.find_iter(&text) {
            let ip = cap.as_str().to_string();
            if !ips.iter().any(|x: &String| x == &ip) {
                ips.push(ip);
            }
        }
    }

    urls.sort();
    urls.dedup();
    ips.sort();
    ips.dedup();
    file_paths.sort();
    file_paths.dedup();
    registry_paths.sort();
    registry_paths.dedup();
    emails.sort();
    emails.dedup();
    high_entropy.sort();
    high_entropy.dedup();

    StringsAnalysis {
        total_count: text.len(),
        urls,
        ip_addresses: ips,
        file_paths,
        registry_paths,
        email_addresses: emails,
        encoded_strings: encoded,
        high_entropy_strings: high_entropy,
    }
}

fn is_base64_like(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let valid_chars = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !valid_chars {
        return false;
    }
    s.chars().filter(|&c| c == '=').count() <= 2
}

fn extract_imports(object: &goblin::Object<'_>) -> Vec<ImportEntry> {
    match object {
        goblin::Object::PE(pe) => extract_pe_imports(pe),
        goblin::Object::Elf(elf) => extract_elf_imports(elf),
        _ => Vec::new(),
    }
}

fn extract_pe_imports(pe: &PE<'_>) -> Vec<ImportEntry> {
    let mut entries: Vec<ImportEntry> = Vec::new();
    for import in &pe.imports {
        let dll = import.dll.to_string();
        let name = &*import.name;
        if !name.is_empty() {
            entries.push(ImportEntry {
                library: dll,
                functions: vec![name.to_string()],
            });
        }
    }
    entries
}

fn extract_elf_imports(elf: &Elf<'_>) -> Vec<ImportEntry> {
    let mut entries = Vec::new();
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            let name_str = name.to_string();
            if !name_str.is_empty()
                && name_str != "_end"
                && name_str != "_start"
                && name_str != "_init"
                && name_str != "_fini"
            {
                entries.push(ImportEntry {
                    library: "dynamic".into(),
                    functions: vec![name_str],
                });
            }
        }
    }
    entries
}

fn extract_exports(object: &goblin::Object<'_>) -> Vec<String> {
    match object {
        goblin::Object::PE(pe) => {
            if let Some(ref export) = pe.export_data {
                let mut names = Vec::new();
                if let Some(ref name) = export.name {
                    names.push(name.to_string());
                }
                names
            } else {
                Vec::new()
            }
        }
        goblin::Object::Elf(elf) => {
            let mut exports = Vec::new();
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    let name_str = name.to_string();
                    if !name_str.is_empty() {
                        exports.push(name_str);
                    }
                }
            }
            exports
        }
        _ => Vec::new(),
    }
}

fn extract_sections(object: &goblin::Object<'_>) -> Vec<SectionInfo> {
    match object {
        goblin::Object::PE(pe) => pe
            .sections
            .iter()
            .map(|sec| {
                let name = sec.name().unwrap_or("?").to_string();
                SectionInfo {
                    name: name.clone(),
                    virtual_address: sec.virtual_address as u64,
                    virtual_size: sec.virtual_size as u64,
                    raw_size: sec.size_of_raw_data as u64,
                    entropy: 0.0,
                    characteristics: section_characteristics(&name, sec.characteristics),
                    executable: sec.characteristics & 0x20000000 != 0,
                    writable: sec.characteristics & 0x80000000 != 0,
                }
            })
            .collect(),
        goblin::Object::Elf(elf) => elf
            .section_headers
            .iter()
            .filter_map(|shdr| {
                elf.shdr_strtab
                    .get_at(shdr.sh_name)
                    .map(|name| SectionInfo {
                        name: name.to_string(),
                        virtual_address: shdr.sh_addr,
                        virtual_size: shdr.sh_size,
                        raw_size: shdr.sh_size,
                        entropy: 0.0,
                        characteristics: elf_section_flags(shdr.sh_flags),
                        executable: shdr.sh_flags & 0x4 != 0,
                        writable: shdr.sh_flags & 0x2 != 0,
                    })
            })
            .collect(),
        goblin::Object::Mach(macho) => extract_macho_sections(macho),
        _ => Vec::new(),
    }
}

fn extract_macho_sections(macho: &goblin::mach::Mach<'_>) -> Vec<SectionInfo> {
    let mut sections = Vec::new();
    if let goblin::mach::Mach::Binary(macho_o) = macho {
        for seg in &macho_o.segments {
            if let Ok(ref secs) = seg.sections() {
                for (section, _data) in secs {
                    let name = section.name().unwrap_or("?").to_string();
                    sections.push(SectionInfo {
                        name,
                        virtual_address: section.addr,
                        virtual_size: section.size,
                        raw_size: seg.filesize as u64,
                        entropy: 0.0,
                        characteristics: Vec::new(),
                        executable: section.flags & 0x80000000 != 0,
                        writable: section.flags & 0x40000000 != 0,
                    });
                }
            }
        }
    }
    sections
}

fn section_characteristics(_name: &str, characteristics: u32) -> Vec<String> {
    let mut flags = Vec::new();
    if characteristics & 0x00000020 != 0 {
        flags.push("CODE".into());
    }
    if characteristics & 0x00000040 != 0 {
        flags.push("INIT_DATA".into());
    }
    if characteristics & 0x00000080 != 0 {
        flags.push("UNINIT_DATA".into());
    }
    if characteristics & 0x02000000 != 0 {
        flags.push("DISCARDABLE".into());
    }
    if characteristics & 0x20000000 != 0 {
        flags.push("EXECUTE".into());
    }
    if characteristics & 0x40000000 != 0 {
        flags.push("READ".into());
    }
    if characteristics & 0x80000000 != 0 {
        flags.push("WRITE".into());
    }
    if characteristics & 0x01000000 != 0 {
        flags.push("SHARED".into());
    }
    if characteristics & 0x10000000 != 0 {
        flags.push("NX".into());
    }
    flags
}

fn elf_section_flags(flags: u64) -> Vec<String> {
    let mut f = Vec::new();
    if flags & 0x1 != 0 {
        f.push("WRITE".into());
    }
    if flags & 0x2 != 0 {
        f.push("ALLOC".into());
    }
    if flags & 0x4 != 0 {
        f.push("EXEC".into());
    }
    if flags & 0x10 != 0 {
        f.push("TLS".into());
    }
    f
}

fn detect_crypto_constants(data: &[u8]) -> Vec<CryptoSignature> {
    let mut results = Vec::new();
    let text = String::from_utf8_lossy(data);

    let crypto_patterns: &[(&str, &str, &str)] = &[
        ("AES", "symmetric", "AES S-box constants"),
        ("RIJNDAEL", "symmetric", "Rijndael/AES"),
        ("SHA256", "hash", "SHA-256"),
        ("SHA512", "hash", "SHA-512"),
        ("MD5", "hash", "MD5"),
        ("SHA1", "hash", "SHA-1"),
        ("RC4", "symmetric", "RC4 key schedule"),
        ("CHACHA20", "symmetric", "ChaCha20"),
        ("SALSA20", "symmetric", "Salsa20"),
        ("BLOWFISH", "symmetric", "Blowfish"),
        ("TWOFISH", "symmetric", "Twofish"),
        ("X509", "asymmetric", "X.509"),
        ("OPENSSH", "asymmetric", "OpenSSH"),
        ("OpenSSL", "asymmetric", "OpenSSL"),
        ("ECC", "asymmetric", "Elliptic curve crypto"),
        ("ED25519", "asymmetric", "Ed25519"),
        ("CURVE25519", "asymmetric", "Curve25519"),
        ("Poly1305", "mac", "Poly1305 MAC"),
        ("HMAC", "mac", "HMAC"),
        ("GCM", "aead", "GCM mode"),
        ("KYBER", "post-quantum", "Kyber KEM"),
        ("DILITHIUM", "post-quantum", "Dilithium"),
        ("FALCON", "post-quantum", "Falcon"),
    ];

    for &(name, algo, desc) in crypto_patterns {
        if text.contains(name) {
            results.push(CryptoSignature {
                name: desc.to_string(),
                algorithm: algo.to_string(),
                location: format!("string match: {}", name),
                confidence: "possible".into(),
            });
        }
    }

    let aes_prefix: &[u8] = &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5];
    if data.windows(aes_prefix.len()).any(|w| w == aes_prefix) {
        results.push(CryptoSignature {
            name: "AES S-box (byte match)".into(),
            algorithm: "symmetric".into(),
            location: "binary constant match".into(),
            confidence: "confirmed".into(),
        });
    }

    results.sort_by(|a, b| a.name.cmp(&b.name));
    results.dedup_by(|a, b| a.name == b.name);
    results
}

fn detect_packers(
    sections: &[SectionInfo],
    strings: &StringsAnalysis,
    packed_likelihood: f64,
) -> Vec<PackerIndicator> {
    let mut indicators = Vec::new();
    let text = strings.high_entropy_strings.join(" ");

    let packer_patterns: &[(&str, &str, &str, &str)] = &[
        ("UPX", "UPX!", "high", "confirmed"),
        ("UPX", "UPX0", "high", "confirmed"),
        ("UPX", "UPX1", "high", "confirmed"),
        ("Themida", ".themida", "high", "confirmed"),
        ("VMProtect", "VMProtect", "high", "confirmed"),
        ("ASPack", "ASPack", "high", "confirmed"),
        ("MPRESS", "MPRESS1", "high", "confirmed"),
        ("Armadillo", "Armadillo", "medium", "possible"),
        ("EXECryptor", "EXECryptor", "high", "confirmed"),
        ("PECompact", "PEC2", "medium", "possible"),
        ("telock", "telock", "medium", "possible"),
        ("ASProtect", "ASProtect", "high", "confirmed"),
        ("Petite", "PETITE", "medium", "possible"),
        ("Confuser", "Confuser", "medium", "possible"),
        ("PyInstaller", "PyInstaller", "low", "confirmed"),
    ];

    for &(name, indicator_str, severity, confidence) in packer_patterns {
        if text.contains(indicator_str) || is_section_name_match(sections, indicator_str) {
            indicators.push(PackerIndicator {
                name: name.to_string(),
                indicator: indicator_str.to_string(),
                severity: severity.to_string(),
                confidence: confidence.to_string(),
            });
        }
    }

    if packed_likelihood > 0.7 {
        indicators.push(PackerIndicator {
            name: "Heuristic packer detection".into(),
            indicator: format!("Packed likelihood: {:.0}%", packed_likelihood * 100.0),
            severity: "medium".into(),
            confidence: "possible".into(),
        });
    }

    if sections
        .iter()
        .any(|s| s.raw_size > 0 && s.virtual_size > s.raw_size * 3)
    {
        indicators.push(PackerIndicator {
            name: "Compressed sections".into(),
            indicator: "Virtual size >> raw size indicates compression".into(),
            severity: "medium".into(),
            confidence: "possible".into(),
        });
    }

    if sections
        .iter()
        .filter(|s| s.executable && s.writable)
        .count()
        > 1
    {
        indicators.push(PackerIndicator {
            name: "Executable+writable sections".into(),
            indicator: "Multiple RWX sections indicate packed/protected binary".into(),
            severity: "high".into(),
            confidence: "possible".into(),
        });
    }

    indicators
}

fn is_section_name_match(sections: &[SectionInfo], pattern: &str) -> bool {
    let lower = pattern.to_lowercase();
    sections
        .iter()
        .any(|s| s.name.to_lowercase().contains(&lower))
}

fn detect_anti_analysis(data: &[u8], imports: &[ImportEntry]) -> AntiAnalysisIndicators {
    let mut anti_debug = Vec::new();
    let mut anti_vm = Vec::new();
    let mut anti_sandbox = Vec::new();
    let mut obfuscation = Vec::new();

    let text = String::from_utf8_lossy(data);

    let debug_patterns: &[(&str, &str)] = &[
        ("IsDebuggerPresent", "kernel32!IsDebuggerPresent"),
        (
            "CheckRemoteDebuggerPresent",
            "kernel32!CheckRemoteDebuggerPresent",
        ),
        (
            "NtQueryInformationProcess",
            "ntdll!NtQueryInformationProcess",
        ),
        ("NtSetInformationThread", "ntdll!NtSetInformationThread"),
        ("OutputDebugString", "kernel32!OutputDebugString"),
        (
            "ZwQueryInformationProcess",
            "ntdll!ZwQueryInformationProcess",
        ),
        ("__debugbreak", "__debugbreak intrinsic"),
        ("DebugBreak", "kernel32!DebugBreak"),
        ("NtGlobalFlag", "PEB!NtGlobalFlag"),
        ("rdtsc", "RDTSC timing check"),
        ("rdtscp", "RDTSCP timing check"),
    ];

    let vm_patterns: &[(&str, &str)] = &[
        ("red pill", "Red Pill VM detection"),
        ("sidt", "SIDT instruction VM detection"),
        ("sgdt", "SGDT instruction VM detection"),
        ("sldt", "SLDT instruction VM detection"),
        ("cpuid", "CPUID hypervisor bit"),
        ("vmware", "VMware detection"),
        ("vbox", "VirtualBox detection"),
        ("qemu", "QEMU detection"),
        ("xen", "Xen detection"),
    ];

    let sandbox_patterns: &[(&str, &str)] = &[
        ("sandboxie", "Sandboxie detection"),
        ("cuckoo", "Cuckoo sandbox detection"),
        ("GetTickCount", "GetTickCount timing"),
        ("QueryPerformanceCounter", "QPC timing check"),
    ];

    let obfuscation_list: &[&str] = &[
        "obfuscator",
        "confuser",
        "control flow",
        "opaque predicate",
        "string encryption",
        "API hashing",
        "GetProcAddress",
        "LoadLibraryA",
        "LdrGetDllHandle",
        "LdrLoadDll",
    ];

    for &(pattern, desc) in debug_patterns {
        if text.contains(pattern) {
            anti_debug.push(desc.to_string());
        }
    }
    for &(pattern, desc) in vm_patterns {
        if text.contains(pattern) {
            anti_vm.push(desc.to_string());
        }
    }
    for &(pattern, desc) in sandbox_patterns {
        if text.contains(pattern) {
            anti_sandbox.push(desc.to_string());
        }
    }
    for pattern in obfuscation_list {
        if text.contains(pattern) {
            obfuscation.push(pattern.to_string());
        }
    }

    for imp in imports {
        for func in &imp.functions {
            for &(pattern, desc) in debug_patterns {
                if func.contains(pattern) && !anti_debug.iter().any(|d| d.contains(desc)) {
                    anti_debug.push(desc.to_string());
                }
            }
        }
    }

    anti_debug.sort();
    anti_debug.dedup();
    anti_vm.sort();
    anti_vm.dedup();
    anti_sandbox.sort();
    anti_sandbox.dedup();
    obfuscation.sort();
    obfuscation.dedup();

    AntiAnalysisIndicators {
        anti_debug,
        anti_vm,
        anti_sandbox,
        obfuscation,
        timestamp_anomaly: None,
    }
}

fn extract_compile_info(object: &goblin::Object<'_>, data: &[u8]) -> CompileInfo {
    let text = String::from_utf8_lossy(data);
    let mut compiler: Option<String> = None;
    let mut compiler_version: Option<String> = None;
    let mut linker_version: Option<String> = None;
    let mut language: Option<String> = None;

    let compiler_patterns: &[(&str, &str, &str)] = &[
        ("GCC:", "GCC", "C"),
        ("clang version", "Clang", "C"),
        ("clang-", "Clang", "C"),
        ("MSVC", "MSVC", "C++"),
        ("Microsoft (R) C/C++", "MSVC", "C++"),
        ("rustc version", "Rustc", "Rust"),
        ("rustc ", "Rustc", "Rust"),
        ("Go build ID:", "Go", "Go"),
        ("go1.", "Go", "Go"),
        ("Python", "Python", "Python"),
        ("javac", "Java", "Java"),
        ("swiftc", "Swift", "Swift"),
        ("Swift ", "Swift", "Swift"),
    ];

    for &(pattern, name, lang) in compiler_patterns {
        if text.contains(pattern) {
            compiler = Some(name.to_string());
            language = Some(lang.to_string());
            for line in text.lines() {
                if line.contains(pattern) && line.contains(char::is_numeric) {
                    compiler_version = Some(line.chars().take(80).collect());
                    break;
                }
            }
            break;
        }
    }

    if let goblin::Object::PE(pe) = object {
        if let Some(ref oh) = pe.header.optional_header {
            linker_version = Some(format!(
                "{}.{}",
                oh.standard_fields.major_linker_version, oh.standard_fields.minor_linker_version
            ));
        }
    }

    let debug_present = text.contains(".debug")
        || text.contains("DWARF")
        || text.contains("PDB ")
        || text.contains(".pdb")
        || text.contains("CodeView")
        || text.contains("NB10");

    CompileInfo {
        compiler,
        compiler_version,
        linker_version,
        compile_timestamp: None,
        debug_info_present: debug_present,
        language,
    }
}

pub fn findings_from_analysis(result: &BinaryAnalysisResult) -> Vec<grym_core::Finding> {
    let mut findings = Vec::new();

    if !result.hardening.nx_enabled {
        findings.push(new_finding(
            "Binary hardening: NX disabled",
            "high",
            format!("{} has NX/XD memory protection disabled", result.artifact),
            "Enable NX/DEP at compile time",
            vec!["SEC-SECURE-DEPLOY".into()],
        ));
    }
    if !result.hardening.pie_enabled {
        findings.push(new_finding(
            "Binary hardening: PIE disabled",
            "medium",
            format!("{} is not position-independent", result.artifact),
            "Compile with -fpie/-fPIE and link with -pie",
            vec!["SEC-SECURE-DEPLOY".into()],
        ));
    }
    if result.hardening.stack_canary == Some(false) {
        findings.push(new_finding(
            "Binary hardening: Stack canary missing",
            "high",
            format!("{} lacks stack canary protection", result.artifact),
            "Compile with -fstack-protector-strong",
            vec!["SEC-SECURE-DEPLOY".into()],
        ));
    }
    if result.hardening.relro == RelroKind::None {
        findings.push(new_finding(
            "Binary hardening: RELRO disabled",
            "medium",
            format!("{} has no RELRO protection", result.artifact),
            "Link with -Wl,-z,relro,-z,now",
            vec!["SEC-SECURE-DEPLOY".into()],
        ));
    }
    if !result.hardening.aslr {
        findings.push(new_finding(
            "Binary hardening: ASLR disabled",
            "high",
            format!("{} has ASLR disabled", result.artifact),
            "Enable ASLR via linker flags",
            vec!["SEC-SECURE-DEPLOY".into()],
        ));
    }
    for indicator in &result.suspicious_indicators {
        findings.push(new_finding(
            &indicator.indicator,
            &indicator.severity,
            indicator.detail.clone(),
            "Review binary for malicious characteristics",
            vec!["SEC-MALWARE-ANALYSIS".into()],
        ));
    }
    for packer in &result.packer_detection {
        findings.push(new_finding(
            &format!("Packer detected: {}", packer.name),
            &packer.severity,
            format!("{}: {}", packer.indicator, packer.confidence),
            "Unpack binary before analysis",
            vec!["SEC-MALWARE-ANALYSIS".into()],
        ));
    }
    if !result.anti_analysis.anti_debug.is_empty() {
        findings.push(new_finding(
            "Anti-debug techniques detected",
            "high",
            format!("Techniques: {}", result.anti_analysis.anti_debug.join(", ")),
            "Bypass anti-debug before dynamic analysis",
            vec!["SEC-MALWARE-ANALYSIS".into()],
        ));
    }
    if !result.anti_analysis.anti_vm.is_empty() {
        findings.push(new_finding(
            "Anti-VM techniques detected",
            "medium",
            format!("Techniques: {}", result.anti_analysis.anti_vm.join(", ")),
            "Modify VM artifacts or use bare metal analysis",
            vec!["SEC-MALWARE-ANALYSIS".into()],
        ));
    }
    if !result.anti_analysis.anti_sandbox.is_empty() {
        findings.push(new_finding(
            "Anti-sandbox techniques detected",
            "medium",
            format!(
                "Techniques: {}",
                result.anti_analysis.anti_sandbox.join(", ")
            ),
            "Bypass sandbox detection for analysis",
            vec!["SEC-MALWARE-ANALYSIS".into()],
        ));
    }
    if !result.entropy_analysis.sections.is_empty() {
        let high_entropy_secs: Vec<&str> = result
            .entropy_analysis
            .sections
            .iter()
            .filter(|s| s.entropy > 7.0)
            .map(|s| s.name.as_str())
            .collect();
        if !high_entropy_secs.is_empty() {
            findings.push(new_finding(
                &format!("High entropy sections: {}", high_entropy_secs.join(", ")),
                "medium",
                format!("Entropy > 7.0 suggests packing/encryption"),
                "Investigate packed/encrypted sections",
                vec!["SEC-MALWARE-ANALYSIS".into()],
            ));
        }
    }
    if result.compile_info.debug_info_present {
        findings.push(new_finding(
            "Debug information present",
            "info",
            "Binary contains PDB/DWARF debug symbols".to_string(),
            "Strip debug symbols for production builds",
            vec!["SEC-SECURE-DEPLOY".into()],
        ));
    }

    findings
}

fn new_finding(
    title: &str,
    severity: &str,
    detail: String,
    remediation: &str,
    categories: Vec<String>,
) -> grym_core::Finding {
    let sev = match severity {
        "critical" => grym_core::Severity::Critical,
        "high" => grym_core::Severity::High,
        "medium" => grym_core::Severity::Medium,
        "low" => grym_core::Severity::Low,
        _ => grym_core::Severity::Info,
    };
    let mut finding = grym_core::Finding::new(
        title.to_string(),
        grym_core::AssetRef {
            identifier: "binary".into(),
            kind: "file".into(),
        },
        sev,
        grym_core::Confidence::Confirmed,
        "grym-binary-analysis",
    );
    finding.categories = categories;
    finding.remediation = remediation.to_string();
    finding.evidence.push(grym_core::Evidence::redacted(
        "binary-analysis",
        &detail,
        &detail,
    ));
    finding
}
