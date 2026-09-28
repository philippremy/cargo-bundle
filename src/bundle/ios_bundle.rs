// An iOS package is laid out like:
//
// Foobar.app         # Actually a directory
//     Foobar             # The main binary executable of the app
//     Info.plist         # An XML file containing the app's metadata
//     ...                # Icons and other resource files
//
// See https://developer.apple.com/go/?id=bundle-structure for a full
// explanation.

use super::common::{self, PlistEntryFormatter, read_file};
use super::signing;
use crate::Settings;
use anyhow::Context;
use image::{self, GenericImageView};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn bundle_project(settings: &Settings) -> crate::Result<Vec<PathBuf>> {
    common::print_warning("iOS bundle support is still experimental.")?;

    let app_bundle_name = format!("{}.app", settings.bundle_name());
    common::print_bundling(&app_bundle_name)?;
    let bundle_dir = settings
        .project_out_directory()
        .join("bundle/ios")
        .join(&app_bundle_name);
    if bundle_dir.exists() {
        fs::remove_dir_all(&bundle_dir)
            .with_context(|| format!("Failed to remove old {app_bundle_name}"))?;
    }
    fs::create_dir_all(&bundle_dir)
        .with_context(|| format!("Failed to create bundle directory at {bundle_dir:?}"))?;

    for src in settings.resource_files() {
        let src = src?;
        let dest = bundle_dir.join(common::resource_relpath(&src));
        common::copy_file(&src, &dest)
            .with_context(|| format!("Failed to copy resource file {src:?}"))?;
    }

    // dtb-ke-patches: unlike the loop above, these land flat at the bundle root (basename only) — see
    // `Settings::ios_additional_resources`'s doc comment. Needed for a pre-compiled `Assets.car` (this
    // backend's own `generate_icon_files` below only ever produces loose, unmerged `CFBundleIconFiles`
    // PNGs — no asset-catalog support at all) and any document-type icon files referenced by bare name
    // from an `ios_info_plist_exts` fragment.
    for src in settings.ios_additional_resources() {
        let src = src?;
        let name = src
            .file_name()
            .with_context(|| format!("additional resource {src:?} has no file name"))?;
        let dest = bundle_dir.join(name);
        common::copy_file(&src, &dest)
            .with_context(|| format!("Failed to copy additional resource {src:?}"))?;
    }

    // `-sim`-suffixed and bare `x86_64` triples are always simulator triples (Apple never shipped a
    // 32/64-bit Intel device); everything else is a real device build. Shared between the Info.plist
    // fields below (which need it regardless) and the `.ipa` step at the end (which doesn't apply to
    // a simulator build at all — `simctl install` takes the `.app` directly, never a `.ipa`).
    let is_simulator = settings
        .target_triples()
        .next()
        .is_some_and(|triple| triple.ends_with("-sim") || triple.starts_with("x86_64"));

    let icon_filenames =
        generate_icon_files(&bundle_dir, settings).with_context(|| "Failed to create app icons")?;
    generate_info_plist(&bundle_dir, settings, &icon_filenames, is_simulator)
        .with_context(|| "Failed to create Info.plist")?;
    let bin_path = bundle_dir.join(settings.binary_name());
    common::copy_file(settings.binary_path(), &bin_path)
        .with_context(|| format!("Failed to copy binary from {:?}", settings.binary_path()))?;
    signing::sign_apple_path(
        settings,
        &bundle_dir,
        settings.ios_signing_entitlements(),
        settings.ios_signing_hardened_runtime(),
    )?;

    let mut outputs = vec![bundle_dir.clone()];
    if !is_simulator {
        outputs.push(write_ipa(&bundle_dir, &app_bundle_name)?);
    }
    Ok(outputs)
}

/// dtb-ke-patches: a `.ipa` is nothing more than a zip with the `.app` nested one level down, under
/// a literal `Payload/` directory — that's the entire format (see Apple's own archive layout docs).
/// Device installs (Xcode's Devices window, `ideviceinstaller`, TestFlight) all expect this shape;
/// `simctl install` (the Simulator) takes the `.app` directly and has no use for a `.ipa` at all.
fn write_ipa(bundle_dir: &Path, app_bundle_name: &str) -> crate::Result<PathBuf> {
    let ipa_path = bundle_dir.with_extension("ipa");
    let file = common::create_file(&ipa_path)
        .with_context(|| format!("Failed to create {ipa_path:?}"))?;
    let mut writer = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut entries: Vec<PathBuf> = walkdir::WalkDir::new(bundle_dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.into_path())
        .collect();
    entries.sort();
    for entry in entries {
        let relative = entry
            .strip_prefix(bundle_dir)
            .expect("walked path is always under bundle_dir");
        let zip_path = format!(
            "Payload/{app_bundle_name}/{}",
            relative.to_string_lossy().replace('\\', "/")
        );
        if entry.is_dir() {
            if !relative.as_os_str().is_empty() {
                writer
                    .add_directory(format!("{zip_path}/"), options)
                    .with_context(|| format!("Failed to add {zip_path} to {ipa_path:?}"))?;
            }
            continue;
        }
        writer
            .start_file(&zip_path, options)
            .with_context(|| format!("Failed to add {zip_path} to {ipa_path:?}"))?;
        let bytes = fs::read(&entry).with_context(|| format!("Failed to read {entry:?}"))?;
        writer
            .write_all(&bytes)
            .with_context(|| format!("Failed to write {zip_path} into {ipa_path:?}"))?;
    }
    writer
        .finish()
        .with_context(|| format!("Failed to finish {ipa_path:?}"))?;
    Ok(ipa_path)
}

/// Generate the icon files and store them under the `bundle_dir`.
fn generate_icon_files(bundle_dir: &Path, settings: &Settings) -> crate::Result<Vec<String>> {
    let mut filenames = Vec::new();
    {
        let mut get_dest_path = |width: u32, height: u32, is_retina: bool| {
            let filename = format!(
                "icon_{}x{}{}.png",
                width,
                height,
                if is_retina { "@2x" } else { "" }
            );
            let path = bundle_dir.join(&filename);
            filenames.push(filename);
            path
        };
        let mut sizes = BTreeSet::new();
        // Prefer PNG files.
        for icon_path in settings.icon_files() {
            let icon_path = icon_path?;
            if icon_path.extension() != Some(OsStr::new("png")) {
                continue;
            }
            let img = image::ImageReader::open(&icon_path)?
                .with_guessed_format()?
                .decode()?;
            let (width, height) = img.dimensions();
            let is_retina = common::is_retina(&icon_path);
            if !sizes.contains(&(width, height, is_retina)) {
                sizes.insert((width, height, is_retina));
                let dest_path = get_dest_path(width, height, is_retina);
                common::copy_file(&icon_path, &dest_path)?;
            }
        }
        // Fall back to non-PNG files for any missing sizes.
        for icon_path in settings.icon_files() {
            let icon_path = icon_path?;
            if icon_path.extension() == Some(OsStr::new("png")) {
                continue;
            } else if icon_path.extension() == Some(OsStr::new("icns")) {
                let icon_family = icns::IconFamily::read(File::open(&icon_path)?)?;
                for icon_type in icon_family.available_icons() {
                    let width = icon_type.screen_width();
                    let height = icon_type.screen_height();
                    let is_retina = icon_type.pixel_density() > 1;
                    if !sizes.contains(&(width, height, is_retina)) {
                        sizes.insert((width, height, is_retina));
                        let dest_path = get_dest_path(width, height, is_retina);
                        let icon = icon_family.get_icon_with_type(icon_type)?;
                        icon.write_png(File::create(dest_path)?)?;
                    }
                }
            } else if icon_path.extension() == Some(OsStr::new("svg")) {
                // TODO: convert svg to appropriate format?
            } else {
                let icon = image::open(&icon_path)?;
                let (width, height) = icon.dimensions();
                let is_retina = common::is_retina(&icon_path);
                if !sizes.contains(&(width, height, is_retina)) {
                    sizes.insert((width, height, is_retina));
                    let dest_path = get_dest_path(width, height, is_retina);
                    let mut file = common::create_file(&dest_path)?;
                    icon.write_to(&mut file, image::ImageFormat::Png)?;
                }
            }
        }
    }
    Ok(filenames)
}

fn generate_info_plist(
    bundle_dir: &Path,
    settings: &Settings,
    icon_filenames: &Vec<String>,
    is_simulator: bool,
) -> crate::Result<()> {
    let file = &mut common::create_file(&bundle_dir.join("Info.plist"))?;
    write!(
        file,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
            <!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \
            \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
            <plist version=\"1.0\">\n\
            <dict>\n"
    )?;

    write!(
        file,
        "  <key>CFBundleIdentifier</key>\n  <string>{}</string>\n",
        settings.bundle_identifier()
    )?;
    write!(
        file,
        "  <key>CFBundleDisplayName</key>\n  <string>{}</string>\n",
        // dtb-ke-patches: was `settings.bundle_name()` — see `Settings::ios_display_name`'s doc
        // comment (the home-screen label truncates after ~13 characters, so it needs a shorter
        // override distinct from the full `CFBundleName` right below).
        settings.ios_display_name()
    )?;
    write!(
        file,
        "  <key>CFBundleName</key>\n  <string>{}</string>\n",
        settings.bundle_name()
    )?;
    write!(
        file,
        "  <key>CFBundleExecutable</key>\n  <string>{}</string>\n",
        settings.binary_name()
    )?;
    write!(
        file,
        "  <key>CFBundleVersion</key>\n  <string>{}</string>\n",
        settings.version_string()
    )?;
    write!(
        file,
        "  <key>CFBundleShortVersionString</key>\n  <string>{}</string>\n",
        settings.version_string()
    )?;
    // dtb-ke-patches: was hardcoded "en_US" — this app's own convention is German everywhere else
    // (see the workspace CLAUDE.md: "User-facing strings and domain vocabulary are German"), and the
    // previous dtb-ke-bundle pipeline's iOS Info.plist already used "de" here.
    write!(
        file,
        "  <key>CFBundleDevelopmentRegion</key>\n  <string>de</string>\n"
    )?;
    // dtb-ke-patches: upstream wrote neither of these at all.
    write!(
        file,
        "  <key>CFBundleInfoDictionaryVersion</key>\n  <string>6.0</string>\n"
    )?;
    write!(
        file,
        "  <key>CFBundlePackageType</key>\n  <string>APPL</string>\n"
    )?;
    // dtb-ke-patches: also missing upstream — real values, not a placeholder, since Xcode/Apple's
    // review tooling checks these against the actual SDK/target the binary was built for.
    // `is_simulator` (see bundle_project) is shared with the `.ipa` decision below.
    let (dt_platform_name, supported_platform) = if is_simulator {
        ("iphonesimulator", "iphonesimulator")
    } else {
        ("iphoneos", "iphoneos")
    };
    write!(
        file,
        "  <key>CFBundleSupportedPlatforms</key>\n  <array>\n    <string>{supported_platform}</string>\n  </array>\n"
    )?;
    write!(
        file,
        "  <key>DTPlatformName</key>\n  <string>{dt_platform_name}</string>\n"
    )?;
    // dtb-ke-patches: reuses the same top-level `category` config osx_bundle.rs already reads (the
    // category UTI strings are identical across macOS/iOS — `osx_application_category_type` is just a
    // historical name), rather than leaving this unset on iOS specifically.
    if let Some(category) = settings.app_category() {
        write!(
            file,
            "  <key>LSApplicationCategoryType</key>\n  <string>{}</string>\n",
            category.osx_application_category_type().format_plist_entry()
        )?;
    }
    write!(
        file,
        "  <key>UILaunchStoryboardName</key>\n  <string></string>\n"
    )?;

    if !icon_filenames.is_empty() {
        write!(file, "  <key>CFBundleIconFiles</key>\n  <array>\n")?;
        for filename in icon_filenames {
            writeln!(file, "    <string>{filename}</string>")?;
        }
        writeln!(file, "  </array>")?;
    }
    write!(file, "  <key>LSRequiresIPhoneOS</key>\n  <true/>\n")?;
    // dtb-ke-patches: same splice mechanism as osx_bundle.rs::create_info_plist — see
    // `Settings::ios_info_plist_exts`'s doc comment.
    for plist in settings.ios_info_plist_exts() {
        let plist = plist?;
        let contents = read_file(&plist)?;
        write!(file, "{:}", contents.format_plist_entry())?
    }
    write!(file, "</dict>\n</plist>\n")?;
    file.flush()?;
    Ok(())
}
