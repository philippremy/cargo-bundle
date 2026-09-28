use super::settings::Settings;
use super::signing;
use quick_xml::se::Serializer;
use serde::Serialize;
use std::path::{Path, PathBuf};

// A v4 UUID that was generated specifically for cargo-bundle, to be used as a
// namespace for generating v5 UUIDs from bundle identifier strings.
const UUID_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    0xfd, 0x85, 0x95, 0xa8, 0x17, 0xa3, 0x47, 0x4e, 0xa6, 0x16, 0x76, 0x14, 0x8d, 0xfa, 0x0c, 0x7b,
]);

pub fn bundle_project(settings: &Settings) -> crate::Result<Vec<PathBuf>> {
    crate::bundle::common::print_warning("MSI bundle support by wix is still experimental.")?;

    let base_dir = settings
        .project_out_directory()
        .join("bundle")
        .join("wxsmsi");
    std::fs::create_dir_all(&base_dir)?;

    // Generate .wixproj file
    let wixproj_path = base_dir.join("installer.wixproj");
    std::fs::write(&wixproj_path, generate_wixproj_file(settings))?;

    // Generate .wxs file
    let wxs_path = base_dir.join("installer.wxs");
    generate_wxs_file(&wxs_path, settings)?;

    // Run dotnet build to generate MSI
    // For example: `dotnet build path/to/installer.wixproj -c Release`
    let configuration = match settings.build_profile() {
        "release" => "Release",
        _ => "Debug",
    };
    // Run dotnet build from the directory containing the wixproj file
    let output = std::process::Command::new("dotnet")
        .args(["build", "installer.wixproj", "-c", configuration])
        .current_dir(&base_dir)
        .output()?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "Failed to build MSI.\nWorking directory: {:?}\nStdout: {}\nStderr: {}",
            base_dir,
            stdout,
            stderr
        ));
    }

    let output_name = sanitize_identifier(settings.bundle_name(), '-', true);
    let msi_path = base_dir
        .join("bin")
        .join(configuration)
        .join(format!("{output_name}.msi"));
    signing::sign_windows_artifact(settings, &msi_path)?;
    Ok(vec![msi_path])
}

// dtb-ke-patches: upstream never set an MSBuild `Platform` property at all, so `dotnet build` fell
// back to whatever `WixToolset.Sdk` defaults to (x86) regardless of the actual binary's architecture —
// there was no way to produce a real x64 or arm64 `.msi`. Maps `Settings::binary_arch()` (a Rust
// `target_arch`-style string: "x86_64", "aarch64", "x86") to the WiX/MSBuild platform moniker it
// expects ("x64", "arm64", "x86").
fn wix_platform(arch: &str) -> &'static str {
    match arch {
        "x86_64" => "x64",
        "aarch64" | "arm64" => "arm64",
        _ => "x86",
    }
}

fn generate_wixproj_file(settings: &Settings) -> String {
    let output_name = sanitize_identifier(settings.bundle_name(), '-', true);
    let platform = wix_platform(settings.binary_arch()).to_string();

    let wix_project = WixProject {
        sdk: "WixToolset.Sdk/6.0.2".to_string(),
        property_group: PropertyGroup {
            output_name,
            platform,
        },
        item_group: ItemGroup {
            package_reference: PackageReference {
                include: "WixToolset.UI.wixext".to_string(),
                version: "6.0.2".to_string(),
            },
        },
    };

    // Serialize to XML
    let mut buffer = String::new();
    let mut serializer = Serializer::new(&mut buffer);
    serializer.indent(' ', 2);
    wix_project.serialize(serializer).unwrap();

    buffer
}

fn generate_wxs_file(wxs_path: &Path, settings: &Settings) -> crate::Result<()> {
    let product_name = settings.bundle_name();
    let version = sanitize_version_for_wix(&settings.version_string().to_string());
    let manufacturer = settings
        .authors_comma_separated()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| product_name.to_string());
    let name = product_name.to_string() + manufacturer.as_str();
    let upgrade_code = uuid::Uuid::new_v5(&UUID_NAMESPACE, name.as_bytes())
        .to_string()
        .to_uppercase();

    // Generate dynamic executable ID from binary name
    let exe_id = sanitize_identifier(settings.binary_name(), '_', false);
    let main_icon_id = "main_ico_id";

    // Generate license RTF file
    let license_rtf_path = settings.project_out_directory().join("License.rtf");
    generate_license_rtf(&license_rtf_path, settings)?;

    // Build components from binary and resources
    let mut installfolder_components = Vec::new();
    let mut component_refs = Vec::new();

    // dtb-ke-patches: a distinct icon for the associated file type, if configured — otherwise the
    // ProgId falls back to the main app icon (still set below regardless).
    let doc_icon_id = "doc_ico_id";
    let doc_icon = settings
        .windows_file_association()
        .and_then(|assoc| assoc.icon.as_deref())
        .map(|path| Icon {
            id: doc_icon_id.to_string(),
            source_file: path.to_string_lossy().into_owned(),
        });

    // Main executable component
    if let Some(binary_path) = settings.binary_path().to_str() {
        // dtb-ke-patches: see `Settings::windows_file_association`'s doc comment — WiX's standard
        // ProgId/Extension/Verb trio, registered against `HKCR` (this MSI already installs machine-
        // wide, under ProgramFilesFolder). Lives on the main executable's own component since that
        // already has a real `File/@KeyPath="yes"` to anchor it.
        let prog_id = settings.windows_file_association().map(|assoc| ProgId {
            id: assoc.prog_id.clone(),
            description: assoc.description.clone(),
            icon: Some(if doc_icon.is_some() {
                doc_icon_id.to_string()
            } else {
                main_icon_id.to_string()
            }),
            extension: Extension {
                id: assoc.extension.clone(),
                content_type: assoc.content_type.clone(),
                verb: Verb {
                    id: "open".to_string(),
                    command: "Open".to_string(),
                    target_file: exe_id.clone(),
                    argument: "\"%1\"".to_string(),
                },
            },
        });

        let comp = Component {
            id: Some("MainExecutableComponent".to_string()),
            guid: Some("*".to_string()),
            file: Some(File {
                id: Some(exe_id.clone()),
                source: binary_path.to_string(),
                name: Some(format!("{}.exe", settings.windows_executable_name())),
                key_path: Some("yes".to_string()),
            }),
            prog_id,
            ..Component::default()
        };
        installfolder_components.push(comp);

        // Add main executable component ref
        component_refs.push(ComponentRef {
            id: "MainExecutableComponent".to_string(),
        });
    }

    let bin_dir = settings
        .binary_path()
        .parent()
        .unwrap_or_else(|| Path::new("."));

    // Search for DLL files from binary_path and add them as components
    let dll_components: Vec<Component> = std::fs::read_dir(bin_dir)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|ft| ft.is_file()))
        .filter_map(|entry| {
            let filename = entry.file_name().to_str()?.to_lowercase();
            if filename.ends_with(".dll") {
                let dll_path = entry.path();
                let comp_id = format!("{}_Component", sanitize_identifier(&filename, '_', true));
                let comp = Component {
                    id: Some(comp_id.clone()),
                    guid: Some("*".to_string()),
                    file: Some(File {
                        source: dll_path.to_str()?.to_string(),
                        ..File::default()
                    }),
                    ..Component::default()
                };

                // Add DLL component references to component_refs
                component_refs.push(ComponentRef { id: comp_id });
                Some(comp)
            } else {
                None
            }
        })
        .collect();

    installfolder_components.extend(dll_components.clone());

    let package_dir = settings
        .manifest_path()
        .parent()
        .unwrap_or_else(|| Path::new("."));

    // Build directory structure from resource files
    let mut root_directories = Vec::new();

    for relative_path in settings.resource_files().flatten() {
        let full_path = package_dir.join(&relative_path);

        // Generate component ID based on full relative path with proper capitalization
        let path_str = relative_path.to_str().unwrap_or("");
        let comp_id = generate_component_id_from_path(path_str) + "_Component";

        let comp = Component {
            id: Some(comp_id.clone()),
            guid: Some("*".to_string()),
            file: Some(File {
                source: full_path.to_str().unwrap_or("").to_string(),
                ..File::default()
            }),
            ..Component::default()
        };
        component_refs.push(ComponentRef { id: comp_id });

        // Build directory structure
        build_directory_structure(&mut root_directories, &relative_path, comp);
    }

    let package_id = format!(
        "{}_{}",
        settings
            .authors_comma_separated()
            .unwrap_or_default()
            .to_lowercase(),
        settings.bundle_name()
    );
    let package_id = sanitize_identifier(&package_id, '_', false);

    let icon_path = get_icon_path(settings);

    // ProgramMenuFolder GUID
    let program_menu_folder_guid = uuid::Uuid::new_v5(
        &UUID_NAMESPACE,
        format!("{manufacturer}{product_name}ProgramMenuFolder").as_bytes(),
    );

    // DesktopFolderShortcut GUID
    let desktop_folder_shortcut_guid = uuid::Uuid::new_v5(
        &UUID_NAMESPACE,
        format!("{manufacturer}{product_name}DesktopFolderShortcut").as_bytes(),
    );

    // Build the complete WiX document structure
    let wix_doc = WixDocument {
        xmlns: "http://wixtoolset.org/schemas/v4/wxs".to_string(),
        xmlns_ui: "http://wixtoolset.org/schemas/v4/wxs/ui".to_string(),
        xmlns_util: "http://wixtoolset.org/schemas/v4/wxs/util".to_string(),
        package: Package {
            id: package_id,
            name: product_name.to_string(),
            manufacturer: manufacturer.clone(),
            version: version.to_string(),
            upgrade_code,
            major_upgrade: MajorUpgrade {
                downgrade_error_message: format!(
                    "A newer version of {product_name} is already installed.",
                ),
            },
            media_template: MediaTemplate {
                embed_cab: "yes".to_string(),
            },
            feature: Feature {
                id: "ProductFeature".to_string(),
                title: product_name.to_string(),
                level: "1".to_string(),
                component_group_ref: ComponentGroupRef {
                    id: "ProductComponents".to_string(),
                },
                component_ref: vec![
                    ComponentRef {
                        id: "RegistryComponent".to_string(),
                    },
                    ComponentRef {
                        id: "DesktopFolderShortcut".to_string(),
                    },
                ],
            },
            wix_ui: WixUI {
                id: "WixUI_InstallDir".to_string(),
            },
            properties: vec![
                Property {
                    id: "WIXUI_INSTALLDIR".to_string(),
                    value: "INSTALLFOLDER".to_string(),
                },
                Property {
                    id: "WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT".to_string(),
                    value: format!("Launch {product_name}"),
                },
                Property {
                    id: "WIXUI_EXITDIALOGOPTIONALCHECKBOX".to_string(),
                    value: "1".to_string(),
                },
            ],
            custom_action: CustomAction {
                id: "LaunchApplication".to_string(),
                directory: "INSTALLFOLDER".to_string(),
                exe_command: format!("[#{}]", exe_id),
                execute: "immediate".to_string(),
                return_value: "asyncNoWait".to_string(),
            },
            ui: UI {
                id: "UI".to_string(),
                publish: Publish {
                    dialog: "ExitDialog".to_string(),
                    control: "Finish".to_string(),
                    event: "DoAction".to_string(),
                    value: "LaunchApplication".to_string(),
                    condition: "WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 and NOT Installed".to_string(),
                },
            },
            wix_variable: WixVariable {
                id: "WixUILicenseRtf".to_string(),
                value: license_rtf_path.to_str().unwrap_or("").to_string(),
            },
            icons: {
                let mut icons = vec![Icon {
                    id: main_icon_id.to_string(),
                    source_file: icon_path.to_str().unwrap_or("").to_string(),
                }];
                icons.extend(doc_icon);
                icons
            },
        },
        fragments: vec![
            Fragment {
                standard_directories: Some(vec![
                    StandardDirectory {
                        id: "ProgramFilesFolder".to_string(),
                        directory: Some(Directory {
                            id: "INSTALLFOLDER".to_string(),
                            name: product_name.to_string(),
                            directories: root_directories,
                            components: installfolder_components,
                        }),
                        component: None,
                    },
                    StandardDirectory {
                        id: "ProgramMenuFolder".to_string(),
                        directory: Some(Directory {
                            id: "ApplicationProgramsFolder".to_string(),
                            name: product_name.to_string(),
                            components: vec![Component {
                                id: Some("RegistryComponent".to_string()),
                                guid: Some(program_menu_folder_guid.to_string()),
                                registry_value: Some(RegistryValue {
                                    root: "HKCU".to_string(),
                                    key: format!(
                                        "Software\\{}\\{product_name}",
                                        manufacturer.to_lowercase(),
                                    ),
                                    name: "installed".to_string(),
                                    value_type: "integer".to_string(),
                                    value: "1".to_string(),
                                    key_path: "yes".to_string(),
                                }),
                                shortcut: Some(Shortcut {
                                    id: "ApplicationStartMenuShortcut".to_string(),
                                    name: product_name.to_string(),
                                    description: Some(product_name.to_string()),
                                    target: format!("[#{exe_id}]"),
                                    icon: main_icon_id.to_string(),
                                    working_directory: "INSTALLFOLDER".to_string(),
                                }),
                                remove_folder: Some(RemoveFolder {
                                    id: "RemoveAppProgramsFolder".to_string(),
                                    directory: "ApplicationProgramsFolder".to_string(),
                                    on: "uninstall".to_string(),
                                }),
                                remove_file: Some(RemoveFile {
                                    id: "RemoveAppPrograms".to_string(),
                                    directory: "ApplicationProgramsFolder".to_string(),
                                    name: "*.*".to_string(),
                                    on: "uninstall".to_string(),
                                }),
                                file: None,
                                prog_id: None,
                            }],
                            directories: vec![],
                        }),
                        component: None,
                    },
                    StandardDirectory {
                        id: "DesktopFolder".to_string(),
                        directory: None,
                        component: Some(Component {
                            id: Some("DesktopFolderShortcut".to_string()),
                            guid: Some(desktop_folder_shortcut_guid.to_string()),
                            registry_value: Some(RegistryValue {
                                root: "HKCU".to_string(),
                                key: format!(
                                    "Software\\{}\\{product_name}",
                                    manufacturer.to_lowercase(),
                                ),
                                name: "installed".to_string(),
                                value_type: "integer".to_string(),
                                value: "1".to_string(),
                                key_path: "yes".to_string(),
                            }),
                            shortcut: Some(Shortcut {
                                id: "DesktopShortcut".to_string(),
                                name: product_name.to_string(),
                                description: None,
                                target: format!("[#{exe_id}]"),
                                icon: main_icon_id.to_string(),
                                working_directory: "INSTALLFOLDER".to_string(),
                            }),
                            ..Component::default()
                        }),
                    },
                ]),
                component_group: None,
            },
            Fragment {
                standard_directories: None,
                component_group: Some(ComponentGroup {
                    id: "ProductComponents".to_string(),
                    directory: None,
                    components: vec![],
                    component_refs,
                }),
            },
        ],
    };

    // Serialize to XML
    let mut buffer = String::new();
    let mut serializer = Serializer::new(&mut buffer);
    serializer.indent(' ', 2);
    wix_doc.serialize(serializer)?;

    // Add XML declaration
    let xml_content = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{buffer}");

    std::fs::write(wxs_path, xml_content)?;
    Ok(())
}

// WiX XML structure definitions
#[derive(Serialize)]
#[serde(rename = "Wix")]
struct WixDocument {
    #[serde(rename = "@xmlns")]
    xmlns: String,
    #[serde(rename = "@xmlns:ui")]
    xmlns_ui: String,
    #[serde(rename = "@xmlns:util")]
    xmlns_util: String,
    #[serde(rename = "Package")]
    package: Package,
    #[serde(rename = "Fragment")]
    fragments: Vec<Fragment>,
}

#[derive(Serialize)]
struct Package {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "@Manufacturer")]
    manufacturer: String,
    #[serde(rename = "@Version")]
    version: String,
    #[serde(rename = "@UpgradeCode")]
    upgrade_code: String,
    #[serde(rename = "MajorUpgrade")]
    major_upgrade: MajorUpgrade,
    #[serde(rename = "MediaTemplate")]
    media_template: MediaTemplate,
    #[serde(rename = "Feature")]
    feature: Feature,
    #[serde(rename = "ui:WixUI")]
    wix_ui: WixUI,
    #[serde(rename = "Property")]
    properties: Vec<Property>,
    #[serde(rename = "CustomAction")]
    custom_action: CustomAction,
    #[serde(rename = "UI")]
    ui: UI,
    #[serde(rename = "WixVariable")]
    wix_variable: WixVariable,
    // dtb-ke-patches: was `Option<Icon>` — a distinct file-type icon (`ProgId/@Icon`) needs its own
    // `<Icon>` element alongside the main app one, and WiX allows any number of `Icon` elements as
    // long as each `@Id` is unique.
    #[serde(rename = "Icon", skip_serializing_if = "Vec::is_empty")]
    icons: Vec<Icon>,
}

#[derive(Serialize)]
struct MajorUpgrade {
    #[serde(rename = "@DowngradeErrorMessage")]
    downgrade_error_message: String,
}

#[derive(Serialize)]
struct MediaTemplate {
    #[serde(rename = "@EmbedCab")]
    embed_cab: String,
}

#[derive(Serialize)]
struct Feature {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Title")]
    title: String,
    #[serde(rename = "@Level")]
    level: String,
    #[serde(rename = "ComponentGroupRef")]
    component_group_ref: ComponentGroupRef,
    #[serde(rename = "ComponentRef", skip_serializing_if = "Vec::is_empty")]
    component_ref: Vec<ComponentRef>,
}

#[derive(Serialize)]
struct ComponentGroupRef {
    #[serde(rename = "@Id")]
    id: String,
}

#[derive(Serialize)]
struct ComponentRef {
    #[serde(rename = "@Id")]
    id: String,
}

#[derive(Serialize)]
struct WixUI {
    #[serde(rename = "@Id")]
    id: String,
}

#[derive(Serialize)]
struct Property {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Value")]
    value: String,
}

#[derive(Serialize)]
struct CustomAction {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Directory")]
    directory: String,
    #[serde(rename = "@ExeCommand")]
    exe_command: String,
    #[serde(rename = "@Execute")]
    execute: String,
    #[serde(rename = "@Return")]
    return_value: String,
}

#[derive(Serialize)]
struct UI {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "Publish")]
    publish: Publish,
}

#[derive(Serialize)]
struct Publish {
    #[serde(rename = "@Dialog")]
    dialog: String,
    #[serde(rename = "@Control")]
    control: String,
    #[serde(rename = "@Event")]
    event: String,
    #[serde(rename = "@Value")]
    value: String,
    #[serde(rename = "@Condition")]
    condition: String,
}

#[derive(Serialize)]
struct WixVariable {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Value")]
    value: String,
}

#[derive(Serialize)]
struct Icon {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@SourceFile")]
    source_file: String,
}

// dtb-ke-patches: WiX's standard file-association trio, nested inside the main executable's own
// `Component` (it already has `File/@KeyPath="yes"`, so this needs no GUID/keypath of its own) — see
// `Settings::windows_file_association`'s doc comment for why this didn't exist at all upstream.
#[derive(Clone, Serialize)]
struct ProgId {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Description")]
    description: String,
    #[serde(rename = "@Icon", skip_serializing_if = "Option::is_none")]
    icon: Option<String>,
    #[serde(rename = "Extension")]
    extension: Extension,
}

#[derive(Clone, Serialize)]
struct Extension {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@ContentType", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(rename = "Verb")]
    verb: Verb,
}

#[derive(Clone, Serialize)]
struct Verb {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Command")]
    command: String,
    #[serde(rename = "@TargetFile")]
    target_file: String,
    #[serde(rename = "@Argument")]
    argument: String,
}

#[derive(Serialize)]
struct Fragment {
    #[serde(rename = "StandardDirectory", skip_serializing_if = "Option::is_none")]
    standard_directories: Option<Vec<StandardDirectory>>,
    #[serde(rename = "ComponentGroup", skip_serializing_if = "Option::is_none")]
    component_group: Option<ComponentGroup>,
}

#[derive(Serialize)]
struct StandardDirectory {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "Directory", skip_serializing_if = "Option::is_none")]
    directory: Option<Directory>,
    #[serde(rename = "Component", skip_serializing_if = "Option::is_none")]
    component: Option<Component>,
}

#[derive(Serialize)]
struct Directory {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "Component", skip_serializing_if = "Vec::is_empty")]
    components: Vec<Component>,
    #[serde(rename = "Directory", skip_serializing_if = "Vec::is_empty")]
    directories: Vec<Directory>,
}

#[derive(Default, Clone, Serialize)]
struct Component {
    #[serde(rename = "@Id", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "@Guid", skip_serializing_if = "Option::is_none")]
    guid: Option<String>,
    #[serde(rename = "RegistryValue", skip_serializing_if = "Option::is_none")]
    registry_value: Option<RegistryValue>,
    #[serde(rename = "Shortcut", skip_serializing_if = "Option::is_none")]
    shortcut: Option<Shortcut>,
    #[serde(rename = "RemoveFolder", skip_serializing_if = "Option::is_none")]
    remove_folder: Option<RemoveFolder>,
    #[serde(rename = "RemoveFile", skip_serializing_if = "Option::is_none")]
    remove_file: Option<RemoveFile>,
    #[serde(rename = "File", skip_serializing_if = "Option::is_none")]
    file: Option<File>,
    #[serde(rename = "ProgId", skip_serializing_if = "Option::is_none")]
    prog_id: Option<ProgId>,
}

#[derive(Clone, Serialize)]
struct RegistryValue {
    #[serde(rename = "@Root")]
    root: String,
    #[serde(rename = "@Key")]
    key: String,
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "@Type")]
    value_type: String,
    #[serde(rename = "@Value")]
    value: String,
    #[serde(rename = "@KeyPath")]
    key_path: String,
}

#[derive(Clone, Serialize)]
struct Shortcut {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "@Description", skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "@Target")]
    target: String,
    #[serde(rename = "@Icon")]
    icon: String,
    #[serde(rename = "@WorkingDirectory")]
    working_directory: String,
}

#[derive(Clone, Serialize)]
struct RemoveFolder {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Directory")]
    directory: String,
    #[serde(rename = "@On")]
    on: String,
}

#[derive(Clone, Serialize)]
struct RemoveFile {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Directory")]
    directory: String,
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "@On")]
    on: String,
}

#[derive(Default, Serialize)]
struct ComponentGroup {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "@Directory", skip_serializing_if = "Option::is_none")]
    directory: Option<String>,
    #[serde(rename = "Component", skip_serializing_if = "Vec::is_empty")]
    components: Vec<Component>,
    #[serde(rename = "ComponentRef", skip_serializing_if = "Vec::is_empty")]
    component_refs: Vec<ComponentRef>,
}

#[derive(Clone, Default, Serialize)]
struct File {
    #[serde(rename = "@Id", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "@Source")]
    source: String,
    // dtb-ke-patches: WiX defaults the *installed* file name to `@Source`'s own basename when this
    // is absent — which was always the raw Cargo binary name, with no way to install it under a
    // different one (see `Settings::windows_executable_name`'s doc comment). Only the main
    // executable's `File` sets this; every other component (DLLs, resources) keeps its own name.
    #[serde(rename = "@Name", skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "@KeyPath", skip_serializing_if = "Option::is_none")]
    key_path: Option<String>,
}

// WiX Project XML structure definitions
#[derive(Serialize)]
#[serde(rename = "Project")]
struct WixProject {
    #[serde(rename = "@Sdk")]
    sdk: String,
    #[serde(rename = "PropertyGroup")]
    property_group: PropertyGroup,
    #[serde(rename = "ItemGroup")]
    item_group: ItemGroup,
}

#[derive(Serialize)]
struct PropertyGroup {
    #[serde(rename = "OutputName")]
    output_name: String,
    // dtb-ke-patches: see `wix_platform`'s doc comment — without this, every build produced an x86
    // MSI (or possibly failed outright) regardless of the actual target architecture.
    #[serde(rename = "Platform")]
    platform: String,
}

#[derive(Serialize)]
struct ItemGroup {
    #[serde(rename = "PackageReference")]
    package_reference: PackageReference,
}

#[derive(Serialize)]
struct PackageReference {
    #[serde(rename = "@Include")]
    include: String,
    #[serde(rename = "@Version")]
    version: String,
}

fn rtf_safe_content(origin_content: &str) -> String {
    let rtf_safe_content = origin_content
        .replace('\\', "\\\\")
        .replace('{', "\\{")
        .replace('}', "\\}")
        .replace('\n', "\\par\n");
    let rtf_output = format!(
        r#"{{\rtf1\ansi\deff0
{{\fonttbl{{\f0 Arial;}}}}
\fs20
{rtf_safe_content}
}}"#
    );
    rtf_output
}

// Converts a version string to WiX-compatible format (a.b.c.d where a, b, c, d are integers).
// WiX requires: major.minor.build.revision format with all numeric parts.
// Pre-release tags like "-beta1" or "+build" are stripped.
fn sanitize_version_for_wix(version: &str) -> String {
    // Strip pre-release and build metadata (anything after - or +)
    let version = version.split(['-', '+']).next().unwrap_or(version);

    // Split into parts and take first 4
    let parts: Vec<&str> = version.split('.').take(4).collect();

    // Parse each part as a number, defaulting to 0 if invalid
    let major = parts
        .first()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .get(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let build = parts
        .get(2)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let revision = parts
        .get(3)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    format!("{}.{}.{}.{}", major, minor, build, revision)
}

fn sanitize_identifier(input: &str, replacement: char, to_lowercase: bool) -> String {
    let result: String = input
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { replacement })
        .collect();
    if to_lowercase {
        result.to_lowercase()
    } else {
        result
    }
}

fn generate_component_id_from_path(path_str: &str) -> String {
    path_str
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

fn generate_license_rtf(rtf_path: &Path, settings: &Settings) -> crate::Result<()> {
    let license_content = settings
        .license_content()
        .or_else(find_default_license)
        .unwrap_or_else(|| "This software is licensed under the MIT License.".to_string());

    let rtf_content = rtf_safe_content(&license_content);
    std::fs::write(rtf_path, rtf_content)?;
    Ok(())
}

fn find_default_license() -> Option<String> {
    [
        "License_MIT.md",
        "License_Apache.md",
        "LICENSE",
        "LICENSE_MIT",
        "LICENSE_APACHE",
        "LICENSE.txt",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "COPYING",
    ]
    .iter()
    .find_map(|&filename| std::fs::read_to_string(filename).ok())
}

fn get_icon_path(settings: &Settings) -> PathBuf {
    // dtb-ke-patches: this used to look at only `icon_files().next()` — the *first* entry in `icon =
    // [...]`, whatever format it happened to be — and, on top of that, re-joined it (already resolved:
    // `icon_files()`/`ResourcePaths` glob paths relative to the process's cwd, only ever yielding paths
    // that already matched a real file) against `settings.manifest_path()`'s *parent*, the crate's own
    // manifest directory rather than the cwd, which silently corrupted an already-correct path into
    // one that never exists — so `full_path.exists()` always failed and this fell straight through to
    // "use the executable itself as the icon" unconditionally, regardless of what `icon = [...]`
    // actually listed.
    //
    // Fixed to (1) not re-resolve an already-resolved path, and (2) search the *whole* `icon = [...]`
    // list in two passes — an already-`.ico`/`.exe`/`.dll` entry needs no conversion and wins outright
    // over one earlier in the list that would; a `.icns`/`.svg` entry is skipped in the conversion pass
    // since `image::open` (which `convert_to_ico` uses) can't decode either.
    let icons: Vec<PathBuf> = settings
        .icon_files()
        .filter_map(Result::ok)
        .filter(|path| path.exists())
        .collect();

    for path in &icons {
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();
        if matches!(extension.as_str(), "ico" | "exe" | "dll") {
            return path.clone();
        }
    }

    for path in &icons {
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();
        if matches!(extension.as_str(), "svg" | "icns") {
            continue;
        }
        let out_dir = settings.project_out_directory();
        let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("icon");
        let ico_path = out_dir.join(format!("{file_stem}-generated.ico"));
        if convert_to_ico(path, &ico_path).is_ok() {
            return ico_path;
        }
    }

    // Fallback: use the executable file itself as the icon source
    // EXE files can be used directly as icon sources in WiX
    settings.binary_path().to_path_buf()
}

// Try to convert other formats to ICO
fn convert_to_ico(input_path: &Path, ico_path: &Path) -> crate::Result<()> {
    // Ensure output directory exists
    std::fs::create_dir_all(ico_path.parent().ok_or(anyhow::anyhow!("Parent dir"))?)?;

    // Load the image
    let img = image::open(input_path)?;

    // Convert and save as ICO
    // ICO format typically uses 256x256, 128x128, 64x64, 32x32, 16x16 sizes
    // We'll resize to 256x256 as the primary size
    let resized = img.resize(256, 256, image::imageops::FilterType::Lanczos3);
    resized.save_with_format(ico_path, image::ImageFormat::Ico)?;

    Ok(())
}

fn build_directory_structure(directories: &mut Vec<Directory>, path: &Path, component: Component) {
    let dir_path = path.parent().unwrap_or(Path::new(""));

    if dir_path.components().count() == 0 {
        // No directories, component goes to root level
        return;
    }

    // Get all directory components from the path
    let mut dir_parts = Vec::new();
    for component in dir_path.components() {
        if let std::path::Component::Normal(name) = component
            && let Some(name_str) = name.to_str()
        {
            dir_parts.push(name_str.to_string());
        }
    }

    if dir_parts.is_empty() {
        return;
    }

    // Build directory structure and add component to final directory
    add_component_to_directory(directories, &dir_parts, component, 0);
}

fn add_component_to_directory(
    directories: &mut Vec<Directory>,
    dir_parts: &[String],
    component: Component,
    depth: usize,
) {
    if depth >= dir_parts.len() {
        return;
    }

    // Build the full path up to this directory
    let full_path = dir_parts[..=depth].join("/");

    // Generate directory ID
    let dir_id = generate_component_id_from_path(&full_path) + "_Dir";

    // Find existing directory or create new one
    let dir_idx = match directories.iter().position(|d| d.id == dir_id) {
        Some(idx) => idx,
        None => {
            let new_dir = Directory {
                id: dir_id,
                name: dir_parts[depth].clone(),
                directories: vec![],
                components: vec![],
            };
            directories.push(new_dir);
            directories.len() - 1
        }
    };

    // If this is the final directory, add the component
    if depth == dir_parts.len() - 1 {
        directories[dir_idx].components.push(component);
    } else {
        // Continue with next level
        add_component_to_directory(
            &mut directories[dir_idx].directories,
            dir_parts,
            component,
            depth + 1,
        );
    }
}
