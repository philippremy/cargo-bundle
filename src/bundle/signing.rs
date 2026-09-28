//! Optional platform code-signing helpers.

use crate::Settings;
use anyhow::Context;
use std::path::Path;

/// Sign an Apple bundle or DMG with the pure-Rust `apple-codesign` library.
///
/// dtb-ke-patches: signs unconditionally now, not only when `apple_signing_p12` is configured.
/// `apple_codesign::SigningSettings` already has a real ad-hoc mode (digests only, no cryptographic
/// signature — exactly `codesign --sign -`) whenever `set_signing_key` is never called; upstream's
/// early `return Ok(())` when no p12 was set skipped that entirely, which also silently skipped
/// entitlements/hardened-runtime with it — but those (the App Sandbox, in our case) need to apply on
/// local/CI dev builds that have no paid Developer ID certificate too, same as our previous ad-hoc
/// `codesign` invocation always did.
///
/// dtb-ke-patches: `entitlements`/`hardened_runtime` are now caller-supplied rather than read from
/// one shared `Settings` getter — this function has no way to tell whether it's signing a macOS or an
/// iOS bundle, so `osx_bundle.rs`/`dmg_bundle.rs` pass `Settings::osx_signing_*` and `ios_bundle.rs`
/// passes `Settings::ios_signing_*` (see `OsxSettings::entitlements`'s doc comment for why they must
/// not share one value).
pub fn sign_apple_path(
    settings: &Settings,
    path: &Path,
    entitlements: Option<&Path>,
    hardened_runtime: bool,
) -> crate::Result<()> {
    use apple_codesign::{
        CodeSignatureFlags, SettingsScope, SigningSettings, UnifiedSigner,
        cryptography::{PrivateKey, parse_pfx_data},
    };

    // Loaded into an outer binding (rather than inside the `if let` below) so `private_key` outlives
    // `signing_settings`'s borrow of it all the way to `sign_path_in_place` at the bottom.
    let p12_identity = match settings.apple_signing_p12() {
        Some(p12_path) => {
            let password = match settings.apple_signing_password_env() {
                Some(variable) => std::env::var(variable).with_context(|| {
                    format!(
                        "Apple signing certificate password environment variable `{variable}` is not set"
                    )
                })?,
                // P12 files exported without a password use the empty string.
                None => String::new(),
            };
            let certificate_data = std::fs::read(p12_path).with_context(|| {
                format!("Failed to read Apple signing certificate {p12_path:?}")
            })?;
            Some(parse_pfx_data(&certificate_data, &password).map_err(|error| {
                anyhow::anyhow!("Failed to read Apple signing certificate: {error}")
            })?)
        }
        None => None,
    };

    // dtb-ke-patches: a device build (`--sign` + `--provisioning-profile`, mutually required by
    // clap) takes priority over the p12 path above — it needs a real Apple-issued identity, which a
    // p12 in this project's Cargo.toml metadata was never going to be. The keychain-backed private
    // key (`KeychainCertificate`, below) implements the same `PrivateKey` trait a parsed p12 does, so
    // it plugs into `set_signing_key` identically; only *how* the identity is found differs.
    let keychain_identity = match settings.sign_identity() {
        #[cfg(target_os = "macos")]
        Some(identity) => Some(find_keychain_identity(identity)?),
        #[cfg(not(target_os = "macos"))]
        Some(_) => anyhow::bail!("--sign (keychain-based code signing) is only available on macOS"),
        None => None,
    };

    // The profile's own `Entitlements` are authoritative for a device build — Apple's installer
    // refuses a mismatch between what's signed and what the profile grants, so this overrides
    // whatever `entitlements` (the OSX/iOS metadata's own entitlements file) was passed in.
    let mut profile_entitlements_xml = None;
    if let Some(profile_path) = settings.provisioning_profile() {
        let profile_bytes = std::fs::read(profile_path).with_context(|| {
            format!("Failed to read provisioning profile {profile_path:?}")
        })?;
        std::fs::write(path.join("embedded.mobileprovision"), &profile_bytes).with_context(
            || format!("Failed to embed provisioning profile into {path:?}"),
        )?;
        profile_entitlements_xml = Some(entitlements_xml_from_profile(&profile_bytes)?);
    }

    let mut signing_settings = SigningSettings::default();
    if let Some((certificate, private_key)) = &keychain_identity {
        signing_settings.set_signing_key(private_key.as_key_info_signer(), certificate.clone());
        signing_settings.chain_apple_certificates();
        signing_settings.set_team_id_from_signing_certificate();
    } else if let Some((certificate, private_key)) = &p12_identity {
        signing_settings.set_signing_key(private_key.as_key_info_signer(), certificate.clone());
        signing_settings.chain_apple_certificates();
        signing_settings.set_team_id_from_signing_certificate();
        if let Some(timestamp_url) = settings.apple_signing_timestamp_url() {
            signing_settings
                .set_time_stamp_url(timestamp_url)
                .map_err(|error| anyhow::anyhow!("Invalid Apple signing timestamp URL: {error}"))?;
        }
    }
    if let Some(entitlements_xml) = profile_entitlements_xml {
        signing_settings
            .set_entitlements_xml(SettingsScope::Main, entitlements_xml)
            .map_err(|error| anyhow::anyhow!("Invalid provisioning-profile entitlements: {error}"))?;
    } else if let Some(entitlements_path) = entitlements {
        let entitlements_xml = std::fs::read_to_string(entitlements_path).with_context(|| {
            format!("Failed to read Apple signing entitlements {entitlements_path:?}")
        })?;
        signing_settings
            .set_entitlements_xml(SettingsScope::Main, entitlements_xml)
            .map_err(|error| anyhow::anyhow!("Invalid Apple signing entitlements: {error}"))?;
    }
    if hardened_runtime {
        signing_settings.add_code_signature_flags(SettingsScope::Main, CodeSignatureFlags::RUNTIME);
    }

    UnifiedSigner::new(signing_settings)
        .sign_path_in_place(path)
        .map_err(|error| anyhow::anyhow!("Apple code signing failed: {error}"))
}

/// dtb-ke-patches: finds a code-signing certificate + its keychain-resident private key by
/// (sub)string match against the certificate's subject common name — the same identity string
/// `codesign --sign <identity>` and `security find-identity -v -p codesigning` show. The private key
/// never leaves the keychain/Secure Enclave: signing later goes through `SecKeyCreateSignature` via
/// `KeychainCertificate`'s `Signer`/`PrivateKey` impls, exactly like a real `codesign` invocation.
#[cfg(target_os = "macos")]
fn find_keychain_identity(
    identity: &str,
) -> crate::Result<(
    x509_certificate::CapturedX509Certificate,
    apple_codesign::KeychainCertificate,
)> {
    use apple_codesign::{KeychainDomain, keychain_find_code_signing_certificates};

    let candidates = keychain_find_code_signing_certificates(KeychainDomain::User, None)
        .map_err(|error| anyhow::anyhow!("searching the keychain for {identity:?}: {error}"))?;
    let found = candidates
        .into_iter()
        .find(|cert| {
            cert.as_captured_x509_certificate()
                .subject_common_name()
                .is_some_and(|cn| cn.contains(identity))
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no code-signing certificate in the keychain matches {identity:?} — check `security \
                 find-identity -v -p codesigning`"
            )
        })?;
    let certificate = found.as_captured_x509_certificate();
    Ok((certificate, found))
}

/// dtb-ke-patches: a `.mobileprovision` is a CMS/PKCS#7 `SignedData` structure (Apple-signed) whose
/// encapsulated content is a plain plist with, among other keys, `Entitlements` — the dict a device
/// build must be signed with. Parsed in pure Rust (`cryptographic-message-syntax`, the same crate
/// `apple-codesign` itself already depends on for notarization tickets) rather than shelling out to
/// `security cms -D`, matching this fork's no-external-Apple-binaries approach throughout. Signature
/// verification is skipped deliberately: the profile is Apple's own, freshly downloaded by whoever
/// supplied it, not attacker-controlled input this process needs to distrust.
fn entitlements_xml_from_profile(profile_bytes: &[u8]) -> crate::Result<String> {
    let signed_data = cryptographic_message_syntax::SignedData::parse_ber(profile_bytes)
        .map_err(|error| anyhow::anyhow!("Failed to parse provisioning profile: {error}"))?;
    let plist_bytes = signed_data
        .signed_content()
        .ok_or_else(|| anyhow::anyhow!("Provisioning profile has no embedded content"))?;
    let profile_plist = plist::Value::from_reader(std::io::Cursor::new(plist_bytes))
        .map_err(|error| anyhow::anyhow!("Provisioning profile content is not a plist: {error}"))?;
    let entitlements = profile_plist
        .as_dictionary()
        .and_then(|dict| dict.get("Entitlements"))
        .ok_or_else(|| anyhow::anyhow!("Provisioning profile has no Entitlements dictionary"))?;
    let mut xml = Vec::new();
    entitlements
        .to_writer_xml(&mut xml)
        .map_err(|error| anyhow::anyhow!("Failed to serialize profile entitlements: {error}"))?;
    String::from_utf8(xml)
        .map_err(|error| anyhow::anyhow!("Profile entitlements are not valid UTF-8: {error}"))
}

/// Sign a Windows executable or installer when configured.
///
/// The implementation is deliberately feature-gated: the vendored
/// osslsigncode implementation is GPL-3.0-or-later.
pub fn sign_windows_artifact(settings: &Settings, artifact_path: &Path) -> crate::Result<()> {
    let Some(config) = settings.windows_signing() else {
        return Ok(());
    };

    #[cfg(not(feature = "windows-signing"))]
    {
        let _ = (artifact_path, config);
        anyhow::bail!(
            "Windows Authenticode signing was requested, but cargo-bundle was built without \
             the `windows-signing` feature. Rebuild it with `--features windows-signing`; \
             that feature links GPL-3.0-or-later code."
        );
    }

    #[cfg(feature = "windows-signing")]
    {
        use osslsigncode::{Credential, Digest, Secret, Timestamp, Unsigned};

        let secret = match &config.certificate_password_env {
            Some(variable) => Secret::value(std::env::var(variable).with_context(|| {
                format!(
                    "Windows signing certificate password environment variable `{variable}` is not set"
                )
            })?),
            None => Secret::Prompt,
        };
        let credential = Credential::pkcs12(&config.certificate_path, secret);
        let parent = artifact_path.parent().ok_or_else(|| {
            anyhow::anyhow!("Windows signing artifact has no parent directory: {artifact_path:?}")
        })?;
        let temporary_directory = tempfile::tempdir_in(parent)
            .with_context(|| "Failed to create temporary directory for Windows signing")?;
        let output_path = temporary_directory.path().join(
            artifact_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Windows signing artifact has no file name"))?,
        );

        let mut signing_job = Unsigned::open(artifact_path)
            .map_err(|error| {
                anyhow::anyhow!("Failed to open Windows artifact for signing: {error}")
            })?
            .sign(credential)
            .digest(Digest::Sha256);
        if let Some(timestamp_url) = &config.timestamp_url {
            signing_job = signing_job.timestamp(Timestamp::rfc3161(timestamp_url));
        }
        signing_job
            .output(&output_path)
            .sign()
            .map_err(|error| anyhow::anyhow!("Windows Authenticode signing failed: {error}"))?;

        std::fs::copy(&output_path, artifact_path).with_context(|| {
            format!(
                "Failed to replace unsigned Windows artifact {artifact_path:?} with its signed copy"
            )
        })?;
        Ok(())
    }
}

/// Creates an adjacent Sigstore bundle for every Linux artifact.
pub fn sign_linux_artifacts(
    settings: &Settings,
    artifact_paths: &mut Vec<std::path::PathBuf>,
) -> crate::Result<()> {
    let Some(config) = settings.linux_signing() else {
        return Ok(());
    };

    {
        use sigstore::{bundle::sign::SigningContext, oauth::IdentityToken};

        let token = std::env::var(&config.identity_token_env).with_context(|| {
            format!(
                "Linux Sigstore identity token environment variable `{}` is not set",
                config.identity_token_env
            )
        })?;
        let token = IdentityToken::try_from(token.as_str())
            .map_err(|error| anyhow::anyhow!("Invalid Linux Sigstore identity token: {error}"))?;
        let context = SigningContext::production()
            .map_err(|error| anyhow::anyhow!("Failed to initialize Sigstore: {error}"))?;
        let signer = context.blocking_signer(token).map_err(|error| {
            anyhow::anyhow!("Failed to create Sigstore signing session: {error}")
        })?;

        let signature_paths = artifact_paths
            .iter()
            .map(|artifact_path| sign_linux_artifact(&signer, artifact_path))
            .collect::<crate::Result<Vec<_>>>()?;
        artifact_paths.extend(signature_paths);
        Ok(())
    }
}

fn sign_linux_artifact(
    signer: &sigstore::bundle::sign::blocking::SigningSession<'_>,
    artifact_path: &Path,
) -> crate::Result<std::path::PathBuf> {
    let artifact = std::fs::File::open(artifact_path)
        .with_context(|| format!("Failed to open Linux artifact {artifact_path:?} for signing"))?;
    let bundle = signer
        .sign(artifact)
        .map_err(|error| anyhow::anyhow!("Sigstore signing failed: {error}"))?
        .to_bundle();
    let bundle_path = artifact_path.with_file_name(format!(
        "{}.sigstore.json",
        artifact_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Linux artifact has no file name: {artifact_path:?}"))?
            .to_string_lossy()
    ));
    let bundle_json = serde_json::to_vec_pretty(&bundle)
        .with_context(|| "Failed to serialize Sigstore bundle")?;
    std::fs::write(&bundle_path, bundle_json)
        .with_context(|| format!("Failed to write Sigstore bundle {bundle_path:?}"))?;
    Ok(bundle_path)
}
