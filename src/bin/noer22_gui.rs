#![cfg(feature = "gui")]

use eframe::{egui, NativeOptions};
use noer22::cli::{ChecksumChoice, CipherChoice, PackArgs, UnpackArgs, VerifyArgs};
use noer22::{pack, unpack};
use rfd::FileDialog;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size(egui::vec2(640.0, 760.0))
        .with_min_inner_size(egui::vec2(500.0, 620.0));
    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let native = NativeOptions {
        centered: true,
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "noer22",
        native,
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    )
}

fn load_app_icon() -> Option<egui::IconData> {
    let bytes = include_bytes!("../../neor22.ico");
    let image = image::load_from_memory(bytes).ok()?.into_rgba8();
    Some(egui::IconData {
        width: image.width(),
        height: image.height(),
        rgba: image.into_raw(),
    })
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Mode {
    #[default]
    Pack,
    Unpack,
    List,
    Verify,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum PackAuthMode {
    #[default]
    PasswordKeyfile,
    AgeRecipients,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum ArchiveAuthMode {
    #[default]
    PasswordKeyfile,
    AgeIdentities,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StatusKind {
    Idle,
    Warning,
    Running,
    Success,
    Error,
}

#[derive(Clone)]
struct StatusState {
    message: String,
    kind: StatusKind,
}

impl StatusState {
    fn new(message: impl Into<String>, kind: StatusKind) -> Self {
        Self {
            message: message.into(),
            kind,
        }
    }
}

struct GuiApp {
    mode: Mode,
    pack_auth_mode: PackAuthMode,
    archive_auth_mode: ArchiveAuthMode,
    inputs: Vec<PathBuf>,
    pack_output: Option<PathBuf>,
    archive: Option<PathBuf>,
    unpack_output: Option<PathBuf>,
    keyfile: Option<PathBuf>,
    age_recipients_text: String,
    age_identities: Vec<PathBuf>,
    password: String,
    confirm_password: String,
    show_password: bool,
    level: i32,
    cipher: CipherChoice,
    kdf_mem: u32,
    kdf_iters: u32,
    kdf_parallelism: u32,
    threads: usize,
    parallel_crypto: bool,
    incremental_index: Option<PathBuf>,
    pack_checksum: Option<ChecksumChoice>,
    pack_checksum_output: Option<PathBuf>,
    unpack_checksum_file: Option<PathBuf>,
    unpack_checksum_algo: Option<ChecksumChoice>,
    verify_checksum_file: Option<PathBuf>,
    verify_checksum_algo: Option<ChecksumChoice>,
    status: Arc<Mutex<StatusState>>,
    running: Arc<AtomicBool>,
    total_input: u64,
    input_files: usize,
    est_output: u64,
    archive_size: u64,
    list_long: bool,
    list_filter: String,
    inspect_result: Arc<Mutex<Option<unpack::ArchiveOverview>>>,
    last_dir: Option<PathBuf>,
    gold_particles: Vec<Particle>,
    crimson_particles: Vec<Particle>,
    noise: Vec<NoiseDot>,
    last_status_kind: StatusKind,
    error_flash: Option<Instant>,
    job_started: Option<Instant>,
}

impl GuiApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }
}

impl Default for GuiApp {
    fn default() -> Self {
        Self {
            mode: Mode::Pack,
            pack_auth_mode: PackAuthMode::PasswordKeyfile,
            archive_auth_mode: ArchiveAuthMode::PasswordKeyfile,
            inputs: Vec::new(),
            pack_output: None,
            archive: None,
            unpack_output: None,
            keyfile: None,
            age_recipients_text: String::new(),
            age_identities: Vec::new(),
            password: String::new(),
            confirm_password: String::new(),
            show_password: false,
            level: 8,
            cipher: CipherChoice::ChaCha20Poly1305,
            kdf_mem: 64,
            kdf_iters: 3,
            kdf_parallelism: 4,
            threads: 0,
            parallel_crypto: false,
            incremental_index: None,
            pack_checksum: None,
            pack_checksum_output: None,
            unpack_checksum_file: None,
            unpack_checksum_algo: None,
            verify_checksum_file: None,
            verify_checksum_algo: None,
            status: Arc::new(Mutex::new(StatusState::new("Ready", StatusKind::Idle))),
            running: Arc::new(AtomicBool::new(false)),
            total_input: 0,
            input_files: 0,
            est_output: 0,
            archive_size: 0,
            list_long: false,
            list_filter: String::new(),
            inspect_result: Arc::new(Mutex::new(None)),
            last_dir: None,
            gold_particles: make_particles(42, 0xCAFE_BABE, 1.0, 2.6, 0.008, 0.03, 24, 44),
            crimson_particles: make_particles(28, 0xFEED_FACE, 1.8, 3.8, 0.012, 0.05, 36, 80),
            noise: make_noise(140, 0x0BADC0DE),
            last_status_kind: StatusKind::Idle,
            error_flash: None,
            job_started: None,
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_theme(ctx);
        self.handle_drops(ctx);

        let status = self.status.lock().unwrap().clone();
        if status.kind != self.last_status_kind {
            if status.kind == StatusKind::Error {
                self.error_flash = Some(Instant::now());
            }
            self.last_status_kind = status.kind;
            if status.kind != StatusKind::Running {
                self.job_started = None;
            }
        }

        self.paint_background(ctx, status.kind);

        let animate =
            self.running() || matches!(status.kind, StatusKind::Error | StatusKind::Running);
        ctx.request_repaint_after(Duration::from_millis(if animate { 33 } else { 120 }));

        let margin = 16.0;
        let rect = ctx.screen_rect();
        let pos = rect.min + egui::vec2(margin, margin);
        let size = rect.size() - egui::vec2(margin * 2.0, margin * 2.0);

        egui::Area::new(egui::Id::new("main_ui"))
            .order(egui::Order::Foreground)
            .fixed_pos(pos)
            .movable(false)
            .show(ctx, |ui: &mut egui::Ui| {
                ui.set_min_size(size);
                ui.set_max_width(size.x);
                ui.set_max_height(size.y);
                egui::Frame::none()
                    .fill(rgba(6, 8, 14, 235))
                    .rounding(egui::Rounding::same(14.0))
                    .inner_margin(egui::Margin::same(16.0))
                    .stroke(egui::Stroke::new(1.2, rgb(191, 164, 111)))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false; 2])
                            .show(ui, |ui| {
                                self.header(ui);

                                ui.add_space(6.0);
                                self.metrics_row(ui);
                                ui.add_space(8.0);

                                mode_switch(ui, &mut self.mode);
                                ui.add_space(6.0);

                                match self.mode {
                                    Mode::Pack => self.pack_ui(ui),
                                    Mode::Unpack => self.unpack_ui(ui),
                                    Mode::List => self.list_ui(ui),
                                    Mode::Verify => self.verify_ui(ui),
                                }

                                ui.add_space(8.0);
                                self.status_card(ui, &status);
                            });
                    });
            });
    }
}

impl GuiApp {
    fn header(&self, ui: &mut egui::Ui) {
        let desired = egui::vec2(ui.available_width(), 112.0);
        let (rect, _) = ui.allocate_exact_size(desired, egui::Sense::hover());
        let painter = ui.painter_at(rect);

        painter.rect_filled(rect, 10.0, rgba(12, 14, 22, 200));

        let glow_rect = rect.shrink(6.0);
        painter.rect_stroke(
            glow_rect,
            10.0,
            egui::Stroke::new(1.0, rgba(212, 175, 55, 40)),
        );

        let icon_rect =
            egui::Rect::from_min_size(rect.min + egui::vec2(12.0, 14.0), egui::vec2(72.0, 72.0));
        paint_vault_icon(&painter, icon_rect);

        let title_pos = egui::pos2(icon_rect.max.x + 16.0, rect.min.y + 20.0);
        paint_glow_text(
            &painter,
            title_pos,
            egui::Align2::LEFT_TOP,
            "noer22",
            egui::FontId::proportional(34.0),
            rgb(212, 175, 55),
            rgba(212, 175, 55, 80),
        );

        let tag_pos = egui::pos2(icon_rect.max.x + 16.0, rect.min.y + 58.0);
        painter.text(
            tag_pos,
            egui::Align2::LEFT_TOP,
            "Chiaroscuro compression + AEAD secrecy",
            egui::FontId::proportional(13.0),
            rgb(209, 213, 219),
        );

        let halo_pos = egui::pos2(rect.max.x - 14.0, rect.center().y + 6.0);
        paint_glow_text(
            &painter,
            halo_pos,
            egui::Align2::RIGHT_CENTER,
            "22",
            egui::FontId::proportional(86.0),
            rgba(212, 175, 55, 56),
            rgba(212, 175, 55, 18),
        );

        ui.add_space(8.0);
    }

    fn metrics_row(&self, ui: &mut egui::Ui) {
        let accent = rgb(212, 175, 55);
        let inspection = self.inspect_result.lock().unwrap().clone();
        ui.horizontal(|ui| match self.mode {
            Mode::Pack => {
                metric_card(ui, "Input", &human_bytes(self.total_input), accent);
                metric_card(ui, "Files", &format!("{}", self.input_files), accent);
                metric_card(ui, "Estimated .noer", &human_bytes(self.est_output), accent);
            }
            Mode::Unpack => {
                metric_card(ui, "Archive", &human_bytes(self.archive_size), accent);
                let output = self.effective_unpack_output().display().to_string();
                metric_card(ui, "Output", &output, accent);
                let count = inspection
                    .as_ref()
                    .map(|info| info.total_entries.to_string())
                    .unwrap_or_else(|| "-".into());
                metric_card(ui, "Entries", &count, accent);
            }
            Mode::List | Mode::Verify => {
                metric_card(ui, "Archive", &human_bytes(self.archive_size), accent);
                let entries = inspection
                    .as_ref()
                    .map(|info| info.total_entries.to_string())
                    .unwrap_or_else(|| "-".into());
                metric_card(ui, "Entries", &entries, accent);
                let payload = inspection
                    .as_ref()
                    .map(|info| human_bytes(info.total_bytes))
                    .unwrap_or_else(|| "-".into());
                metric_card(ui, "Payload", &payload, accent);
            }
        });
    }

    fn pack_ui(&mut self, ui: &mut egui::Ui) {
        card(ui, "Purpose", |ui| {
            ui.label("Pack files and folders into a single encrypted .noer archive.");
            ui.label("Compression: Zstd | Encryption: AEAD");
        });

        card(ui, "Inputs", |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.add(gold_button("Add Files")).clicked() {
                    if let Some(paths) = self.new_dialog().pick_files() {
                        self.add_input_paths(paths);
                    }
                }
                if ui.add(gold_button("Add Folder")).clicked() {
                    if let Some(path) = self.new_dialog().pick_folder() {
                        self.add_input_paths([path]);
                    }
                }
                if ui.add(dark_button("Clear")).clicked() {
                    self.inputs.clear();
                    self.recompute_estimates();
                }
            });

            ui.add_space(6.0);
            let drop_rect = ui
                .allocate_exact_size(egui::vec2(ui.available_width(), 50.0), egui::Sense::hover())
                .0;
            let drop_painter = ui.painter_at(drop_rect);
            drop_painter.rect_filled(drop_rect, 8.0, rgba(12, 14, 22, 180));
            drop_painter.rect_stroke(
                drop_rect,
                8.0,
                egui::Stroke::new(1.0, rgba(212, 175, 55, 80)),
            );
            drop_painter.text(
                drop_rect.center(),
                egui::Align2::CENTER_CENTER,
                "Drag and drop files/folders here",
                egui::FontId::proportional(12.0),
                rgb(191, 164, 111),
            );

            ui.add_space(6.0);
            if self.inputs.is_empty() {
                ui.label("No inputs selected.");
            } else {
                let mut remove_idx: Option<usize> = None;
                egui::ScrollArea::vertical()
                    .max_height(110.0)
                    .show(ui, |ui| {
                        for (idx, p) in self.inputs.iter().enumerate() {
                            ui.horizontal(|ui| {
                                if ui.add(dark_button("x")).clicked() {
                                    remove_idx = Some(idx);
                                }
                                ui.label(p.display().to_string());
                            });
                        }
                    });
                if let Some(idx) = remove_idx {
                    self.inputs.remove(idx);
                    self.recompute_estimates();
                }
            }

            if self.total_input > 0 {
                ui.label(format!(
                    "Input size: {}  |  Estimated .noer: {}",
                    human_bytes(self.total_input),
                    human_bytes(self.est_output)
                ));
            }
        });

        card(ui, "Output & Authentication", |ui| {
            ui.horizontal(|ui| {
                if ui.add(gold_button("Choose Output")).clicked() {
                    let suggested = self.effective_pack_output();
                    let mut dialog = self.new_dialog();
                    if let Some(parent) = suggested.parent() {
                        dialog = dialog.set_directory(parent);
                    }
                    if let Some(name) = suggested.file_name().and_then(|v| v.to_str()) {
                        dialog = dialog.set_file_name(name);
                    }
                    if let Some(path) = dialog.save_file() {
                        self.remember_path(&path);
                        self.pack_output = Some(path);
                    }
                }
                ui.label(
                    self.pack_output
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| self.effective_pack_output().display().to_string()),
                );
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("Auth mode");
                ui.selectable_value(
                    &mut self.pack_auth_mode,
                    PackAuthMode::PasswordKeyfile,
                    "Password/Keyfile",
                );
                ui.selectable_value(
                    &mut self.pack_auth_mode,
                    PackAuthMode::AgeRecipients,
                    "Age recipients",
                );
            });

            match self.pack_auth_mode {
                PackAuthMode::PasswordKeyfile => {
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.add(dark_button("Choose Keyfile")).clicked() {
                            if let Some(path) = self.new_dialog().pick_file() {
                                self.remember_path(&path);
                                self.keyfile = Some(path);
                            }
                        }
                        if self.keyfile.is_some() && ui.add(dark_button("Clear Keyfile")).clicked()
                        {
                            self.keyfile = None;
                        }
                        ui.label(
                            self.keyfile
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "No keyfile".into()),
                        );
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Password");
                        ui.checkbox(&mut self.show_password, "show");
                    });
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(!self.show_password)
                            .hint_text("minimum 8 characters"),
                    );
                    ui.add_space(4.0);
                    ui.label("Confirm password");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.confirm_password)
                            .password(!self.show_password)
                            .hint_text("repeat password"),
                    );

                    let (strength, label, color) = password_strength(&self.password);
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.colored_label(color, format!("Strength: {label}"));
                        ui.add(
                            egui::ProgressBar::new(strength)
                                .desired_width(140.0)
                                .fill(color),
                        );
                    });

                    if !self.password.is_empty()
                        && !self.confirm_password.is_empty()
                        && self.password != self.confirm_password
                    {
                        ui.colored_label(rgb(120, 30, 22), "Passwords do not match.");
                    }
                    if self.password.is_empty() && self.keyfile.is_none() {
                        ui.colored_label(
                            rgb(191, 164, 111),
                            "Use at least one auth material: password or keyfile.",
                        );
                    }
                }
                PackAuthMode::AgeRecipients => {
                    ui.add_space(8.0);
                    ui.label("Age recipients (one per line or separated by comma/space):");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.age_recipients_text)
                            .desired_rows(4)
                            .hint_text("age1...\nage1..."),
                    );
                    ui.horizontal_wrapped(|ui| {
                        if ui.add(dark_button("Load Recipients File")).clicked() {
                            if let Some(path) = self.new_dialog().pick_file() {
                                self.remember_path(&path);
                                match fs::read_to_string(&path) {
                                    Ok(content) => {
                                        if !self.age_recipients_text.trim().is_empty() {
                                            self.age_recipients_text.push('\n');
                                        }
                                        self.age_recipients_text.push_str(content.trim());
                                    }
                                    Err(err) => set_status(
                                        &self.status,
                                        StatusKind::Warning,
                                        &format!("Could not read recipients file: {err}"),
                                    ),
                                }
                            }
                        }
                        if ui.add(dark_button("Clear Recipients")).clicked() {
                            self.age_recipients_text.clear();
                        }
                    });

                    let count = parse_age_recipients(&self.age_recipients_text).len();
                    ui.label(format!("Recipients detected: {count}"));
                    if count == 0 {
                        ui.colored_label(
                            rgb(191, 164, 111),
                            "Add at least one valid age recipient (age1...).",
                        );
                    }
                }
            }
        });

        card(ui, "Settings", |ui| {
            let level_changed = ui
                .add(
                    egui::Slider::new(&mut self.level, -22..=22)
                        .text("Zstd Level")
                        .show_value(true),
                )
                .changed();
            if level_changed {
                self.recompute_estimates();
            }

            ui.horizontal(|ui| {
                ui.label("Cipher (AEAD)");
                ui.selectable_value(
                    &mut self.cipher,
                    CipherChoice::ChaCha20Poly1305,
                    "ChaCha20-Poly1305",
                );
                ui.selectable_value(&mut self.cipher, CipherChoice::Aes256Gcm, "AES-256-GCM");
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Quick Profiles");
                if ui.add(dark_button("Fast")).clicked() {
                    self.apply_preset(Preset::Fast);
                }
                if ui.add(dark_button("Balanced")).clicked() {
                    self.apply_preset(Preset::Balanced);
                }
                if ui.add(dark_button("Secure")).clicked() {
                    self.apply_preset(Preset::Secure);
                }
            });

            ui.add_space(6.0);
            ui.checkbox(
                &mut self.parallel_crypto,
                "Parallel Crypto (experimental deterministic pipeline)",
            );

            ui.add_space(6.0);
            ui.label("Incremental index (.json, optional)");
            ui.horizontal_wrapped(|ui| {
                if ui.add(dark_button("Choose Index")).clicked() {
                    if let Some(path) = self.new_dialog().set_file_name("index.json").save_file() {
                        self.remember_path(&path);
                        self.incremental_index = Some(path);
                    }
                }
                if self.incremental_index.is_some() && ui.add(dark_button("Clear Index")).clicked()
                {
                    self.incremental_index = None;
                }
                ui.label(
                    self.incremental_index
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Disabled".into()),
                );
            });

            ui.add_space(6.0);
            ui.label("Checksum sidecar (optional)");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.pack_checksum, None, "None");
                ui.selectable_value(
                    &mut self.pack_checksum,
                    Some(ChecksumChoice::Sha256),
                    "SHA-256",
                );
                ui.selectable_value(
                    &mut self.pack_checksum,
                    Some(ChecksumChoice::Blake3),
                    "BLAKE3",
                );
            });
            if self.pack_checksum.is_some() {
                ui.horizontal_wrapped(|ui| {
                    if ui.add(dark_button("Choose Checksum Output")).clicked() {
                        let suggested = self.effective_pack_checksum_output();
                        let mut dialog = self.new_dialog();
                        if let Some(parent) = suggested.parent() {
                            dialog = dialog.set_directory(parent);
                        }
                        if let Some(name) = suggested.file_name().and_then(|n| n.to_str()) {
                            dialog = dialog.set_file_name(name);
                        }
                        if let Some(path) = dialog.save_file() {
                            self.remember_path(&path);
                            self.pack_checksum_output = Some(path);
                        }
                    }
                    if self.pack_checksum_output.is_some()
                        && ui.add(dark_button("Clear Checksum Output")).clicked()
                    {
                        self.pack_checksum_output = None;
                    }
                });
                ui.label(
                    self.pack_checksum_output
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| {
                            self.effective_pack_checksum_output().display().to_string()
                        }),
                );
            }

            egui::CollapsingHeader::new("Advanced Settings")
                .default_open(false)
                .show(ui, |ui| {
                    ui.add(
                        egui::DragValue::new(&mut self.kdf_mem)
                            .prefix("Argon2 memory MiB ")
                            .speed(1),
                    );
                    ui.add(
                        egui::DragValue::new(&mut self.kdf_iters)
                            .prefix("iterations ")
                            .speed(1),
                    );
                    ui.add(
                        egui::DragValue::new(&mut self.kdf_parallelism)
                            .prefix("parallelism ")
                            .speed(1),
                    );
                    ui.add(
                        egui::DragValue::new(&mut self.threads)
                            .prefix("zstd threads (0=auto) ")
                            .speed(1),
                    );
                });
        });

        let can_pack = self.can_pack();
        if !can_pack {
            let msg = match self.pack_auth_mode {
                PackAuthMode::PasswordKeyfile => {
                    "Select inputs and provide password (with confirmation) or keyfile."
                }
                PackAuthMode::AgeRecipients => {
                    "Select inputs and provide at least one age recipient."
                }
            };
            ui.colored_label(rgb(191, 164, 111), msg);
        }

        if ui
            .add_enabled(!self.running() && can_pack, gold_button("Pack Archive"))
            .clicked()
        {
            self.run_pack();
        }
    }

    fn unpack_ui(&mut self, ui: &mut egui::Ui) {
        card(ui, "Purpose", |ui| {
            ui.label("Extract and decrypt a .noer archive.");
            ui.label("Restores folders, files and metadata.");
        });

        card(ui, "Archive (.noer)", |ui| {
            ui.horizontal(|ui| {
                if ui.add(gold_button("Choose .noer")).clicked() {
                    if let Some(path) = self.new_dialog().add_filter("noer", &["noer"]).pick_file()
                    {
                        self.set_archive_path(path);
                    }
                }
                ui.label(
                    self.archive
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Not selected".into()),
                );
            });

            if self.archive_size > 0 {
                ui.label(format!("Archive size: {}", human_bytes(self.archive_size)));
            }
        });

        card(ui, "Output & Authentication", |ui| {
            if ui.add(gold_button("Select Output Folder")).clicked() {
                if let Some(path) = self.new_dialog().pick_folder() {
                    self.remember_path(&path);
                    self.unpack_output = Some(path);
                }
            }
            if self.unpack_output.is_some() && ui.add(dark_button("Clear Output Folder")).clicked()
            {
                self.unpack_output = None;
            }
            ui.label(
                self.unpack_output
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| self.effective_unpack_output().display().to_string()),
            );
            ui.add_space(6.0);
            self.show_archive_auth_ui(ui, true);
            ui.add_space(8.0);
            ui.label("Checksum pre-check (optional)");
            ui.horizontal_wrapped(|ui| {
                if ui.add(dark_button("Choose Checksum File")).clicked() {
                    if let Some(path) = self.new_dialog().pick_file() {
                        self.remember_path(&path);
                        self.unpack_checksum_file = Some(path);
                    }
                }
                if self.unpack_checksum_file.is_some()
                    && ui.add(dark_button("Clear Checksum File")).clicked()
                {
                    self.unpack_checksum_file = None;
                    self.unpack_checksum_algo = None;
                }
                ui.label(
                    self.unpack_checksum_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Disabled".into()),
                );
            });
            if self.unpack_checksum_file.is_some() {
                ui.horizontal(|ui| {
                    ui.label("Checksum algorithm");
                    ui.selectable_value(&mut self.unpack_checksum_algo, None, "Auto");
                    ui.selectable_value(
                        &mut self.unpack_checksum_algo,
                        Some(ChecksumChoice::Sha256),
                        "SHA-256",
                    );
                    ui.selectable_value(
                        &mut self.unpack_checksum_algo,
                        Some(ChecksumChoice::Blake3),
                        "BLAKE3",
                    );
                });
            }
        });

        let can_unpack = self.can_unpack();
        if !can_unpack {
            ui.colored_label(
                rgb(191, 164, 111),
                "Select a .noer file and provide matching auth material.",
            );
        }

        if ui
            .add_enabled(
                !self.running() && can_unpack,
                gold_button("Extract Archive"),
            )
            .clicked()
        {
            self.run_unpack();
        }
    }

    fn list_ui(&mut self, ui: &mut egui::Ui) {
        card(ui, "Purpose", |ui| {
            ui.label("Inspect archive contents without extracting files.");
            ui.label("Useful for auditing backups before restore.");
        });

        card(ui, "Archive (.noer)", |ui| {
            ui.horizontal(|ui| {
                if ui.add(gold_button("Choose .noer")).clicked() {
                    if let Some(path) = self.new_dialog().add_filter("noer", &["noer"]).pick_file()
                    {
                        self.set_archive_path(path);
                    }
                }
                ui.label(
                    self.archive
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Not selected".into()),
                );
            });

            if self.archive_size > 0 {
                ui.label(format!("Archive size: {}", human_bytes(self.archive_size)));
            }
        });

        card(ui, "Authentication", |ui| {
            self.show_archive_auth_ui(ui, true);
            ui.add_space(6.0);
            ui.checkbox(&mut self.list_long, "Detailed listing");
            ui.add(
                egui::TextEdit::singleline(&mut self.list_filter)
                    .hint_text("Filter entries by path (optional)"),
            );
        });

        let can_list = self.can_list();
        if !can_list {
            ui.colored_label(
                rgb(191, 164, 111),
                "Select a .noer file and provide matching auth material.",
            );
        }

        if ui
            .add_enabled(!self.running() && can_list, gold_button("Inspect Archive"))
            .clicked()
        {
            self.run_list();
        }

        if let Some(info) = self.inspect_result.lock().unwrap().clone() {
            card(ui, "Archive Index", |ui| {
                ui.label(format!(
                    "{} entries ({} files, {} directories) | payload {}",
                    info.total_entries,
                    info.file_count,
                    info.dir_count,
                    human_bytes(info.total_bytes)
                ));
                ui.label(format!(
                    "Cipher: {} | Argon2id: {} MiB, iters {}, parallel {}",
                    info.crypto_name, info.kdf_mem_mib, info.kdf_iters, info.kdf_parallelism
                ));

                let filter = self.list_filter.trim().to_lowercase();
                let shown = info
                    .entries
                    .iter()
                    .filter(|entry| {
                        filter.is_empty() || entry.path.to_lowercase().contains(&filter)
                    })
                    .count();
                ui.label(format!("Visible entries: {shown}"));

                ui.add_space(6.0);
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .show(ui, |ui| {
                        if self.list_long {
                            ui.monospace("TYPE  SIZE         MODIFIED    MODE   PATH");
                        }
                        let mut rendered = 0usize;
                        for entry in &info.entries {
                            if !filter.is_empty() && !entry.path.to_lowercase().contains(&filter) {
                                continue;
                            }
                            rendered += 1;
                            if self.list_long {
                                let kind = if entry.is_dir { "dir " } else { "file" };
                                let size = if entry.is_dir {
                                    "-".to_string()
                                } else {
                                    human_bytes(entry.size)
                                };
                                ui.monospace(format!(
                                    "{kind:<4}  {size:<11}  {:<10}  {:>04o}  {}",
                                    entry.modified, entry.mode, entry.path
                                ));
                            } else if entry.is_dir {
                                ui.label(format!("[DIR]  {}", entry.path));
                            } else {
                                ui.label(format!(
                                    "[FILE] {} ({})",
                                    entry.path,
                                    human_bytes(entry.size)
                                ));
                            }
                        }
                        if rendered == 0 {
                            ui.label("No entries match the current filter.");
                        }
                    });
            });
        }
    }

    fn verify_ui(&mut self, ui: &mut egui::Ui) {
        card(ui, "Purpose", |ui| {
            ui.label("Verify password and full archive integrity.");
            ui.label("Reads and authenticates every encrypted chunk.");
        });

        card(ui, "Archive (.noer)", |ui| {
            ui.horizontal(|ui| {
                if ui.add(gold_button("Choose .noer")).clicked() {
                    if let Some(path) = self.new_dialog().add_filter("noer", &["noer"]).pick_file()
                    {
                        self.set_archive_path(path);
                    }
                }
                ui.label(
                    self.archive
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Not selected".into()),
                );
            });

            if self.archive_size > 0 {
                ui.label(format!("Archive size: {}", human_bytes(self.archive_size)));
            }
        });

        card(ui, "Authentication", |ui| {
            self.show_archive_auth_ui(ui, false);
            ui.add_space(8.0);
            ui.label("Checksum sidecar (optional, enables checksum-only verify)");
            ui.horizontal_wrapped(|ui| {
                if ui.add(dark_button("Choose Checksum File")).clicked() {
                    if let Some(path) = self.new_dialog().pick_file() {
                        self.remember_path(&path);
                        self.verify_checksum_file = Some(path);
                    }
                }
                if self.verify_checksum_file.is_some()
                    && ui.add(dark_button("Clear Checksum File")).clicked()
                {
                    self.verify_checksum_file = None;
                    self.verify_checksum_algo = None;
                }
                ui.label(
                    self.verify_checksum_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Disabled".into()),
                );
            });
            if self.verify_checksum_file.is_some() {
                ui.horizontal(|ui| {
                    ui.label("Checksum algorithm");
                    ui.selectable_value(&mut self.verify_checksum_algo, None, "Auto");
                    ui.selectable_value(
                        &mut self.verify_checksum_algo,
                        Some(ChecksumChoice::Sha256),
                        "SHA-256",
                    );
                    ui.selectable_value(
                        &mut self.verify_checksum_algo,
                        Some(ChecksumChoice::Blake3),
                        "BLAKE3",
                    );
                });
            }
        });

        let can_verify = self.can_verify();
        if !can_verify {
            ui.colored_label(
                rgb(191, 164, 111),
                "Select a .noer file and provide auth material or checksum file.",
            );
        }

        if ui
            .add_enabled(
                !self.running() && can_verify,
                gold_button("Verify Integrity"),
            )
            .clicked()
        {
            self.run_verify();
        }
    }

    fn status_card(&self, ui: &mut egui::Ui, status: &StatusState) {
        card(ui, "Status", |ui| {
            let color = status_color(status.kind);
            ui.horizontal(|ui| {
                ui.colored_label(color, status_label(status.kind));
                ui.label(&status.message);
                if ui.add(dark_button("Copy")).clicked() {
                    ui.ctx().copy_text(status.message.clone());
                }
                if status.kind == StatusKind::Running {
                    ui.add(egui::Spinner::new());
                }
            });

            if let Some(started) = self.job_started {
                let elapsed = started.elapsed();
                ui.label(format!("Elapsed: {}s", elapsed.as_secs()));
            }
        });
    }

    fn running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn can_pack(&self) -> bool {
        !self.inputs.is_empty() && self.has_pack_auth_material()
    }

    fn can_unpack(&self) -> bool {
        self.archive.is_some() && self.has_archive_auth_material()
    }

    fn can_list(&self) -> bool {
        self.archive.is_some() && self.has_archive_auth_material()
    }

    fn can_verify(&self) -> bool {
        self.archive.is_some()
            && (self.has_archive_auth_material() || self.verify_checksum_file.is_some())
    }

    fn has_pack_auth_material(&self) -> bool {
        match self.pack_auth_mode {
            PackAuthMode::PasswordKeyfile => {
                if self.password.is_empty() {
                    self.keyfile.is_some()
                } else {
                    self.password == self.confirm_password
                }
            }
            PackAuthMode::AgeRecipients => {
                !parse_age_recipients(&self.age_recipients_text).is_empty()
            }
        }
    }

    fn has_archive_auth_material(&self) -> bool {
        match self.archive_auth_mode {
            ArchiveAuthMode::PasswordKeyfile => !self.password.is_empty() || self.keyfile.is_some(),
            ArchiveAuthMode::AgeIdentities => !self.age_identities.is_empty(),
        }
    }

    fn show_archive_auth_ui(&mut self, ui: &mut egui::Ui, auth_required: bool) {
        ui.horizontal(|ui| {
            ui.label("Auth mode");
            ui.selectable_value(
                &mut self.archive_auth_mode,
                ArchiveAuthMode::PasswordKeyfile,
                "Password/Keyfile",
            );
            ui.selectable_value(
                &mut self.archive_auth_mode,
                ArchiveAuthMode::AgeIdentities,
                "Age identities",
            );
        });
        ui.add_space(6.0);

        match self.archive_auth_mode {
            ArchiveAuthMode::PasswordKeyfile => {
                ui.horizontal_wrapped(|ui| {
                    if ui.add(dark_button("Choose Keyfile")).clicked() {
                        if let Some(path) = self.new_dialog().pick_file() {
                            self.remember_path(&path);
                            self.keyfile = Some(path);
                        }
                    }
                    if self.keyfile.is_some() && ui.add(dark_button("Clear Keyfile")).clicked() {
                        self.keyfile = None;
                    }
                    ui.label(
                        self.keyfile
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "No keyfile".into()),
                    );
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Password");
                    ui.checkbox(&mut self.show_password, "show");
                });
                ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .password(!self.show_password)
                        .hint_text("archive password"),
                );
            }
            ArchiveAuthMode::AgeIdentities => {
                ui.horizontal_wrapped(|ui| {
                    if ui.add(gold_button("Add Identity Files")).clicked() {
                        if let Some(paths) = self.new_dialog().pick_files() {
                            self.add_identity_paths(paths);
                        }
                    }
                    if ui.add(dark_button("Clear Identities")).clicked() {
                        self.age_identities.clear();
                    }
                    ui.label(format!("Loaded: {}", self.age_identities.len()));
                });
                if self.age_identities.is_empty() {
                    if auth_required {
                        ui.colored_label(rgb(191, 164, 111), "Add one or more age identity files.");
                    } else {
                        ui.label("No identity loaded (OK for checksum-only verify).");
                    }
                } else {
                    egui::ScrollArea::vertical()
                        .max_height(88.0)
                        .show(ui, |ui| {
                            let mut remove_idx: Option<usize> = None;
                            for (idx, path) in self.age_identities.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    if ui.add(dark_button("x")).clicked() {
                                        remove_idx = Some(idx);
                                    }
                                    ui.label(path.display().to_string());
                                });
                            }
                            if let Some(idx) = remove_idx {
                                self.age_identities.remove(idx);
                            }
                        });
                }
            }
        }
    }

    fn add_identity_paths<I>(&mut self, paths: I)
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut seen: HashSet<String> = self.age_identities.iter().map(|p| path_key(p)).collect();
        for path in paths {
            if !path.is_file() {
                continue;
            }
            let key = path_key(&path);
            if seen.insert(key) {
                self.remember_path(&path);
                self.age_identities.push(path);
            }
        }
    }

    fn new_dialog(&self) -> FileDialog {
        let dir = self
            .last_dir
            .as_ref()
            .filter(|p| p.exists())
            .cloned()
            .unwrap_or_else(default_user_dir);
        FileDialog::new().set_directory(dir)
    }

    fn remember_path(&mut self, path: &Path) {
        let dir = if path.is_dir() {
            Some(path.to_path_buf())
        } else {
            path.parent().map(Path::to_path_buf)
        };
        if let Some(dir) = dir {
            self.last_dir = Some(dir);
        }
    }

    fn add_input_paths<I>(&mut self, paths: I)
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut seen: HashSet<String> = self.inputs.iter().map(|p| path_key(p)).collect();
        for path in paths {
            if !path.exists() {
                continue;
            }
            let key = path_key(&path);
            if seen.insert(key) {
                self.remember_path(&path);
                self.inputs.push(path);
            }
        }
        self.recompute_estimates();
    }

    fn set_archive_path(&mut self, path: PathBuf) {
        if !is_noer_file(&path) {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Select a valid .noer archive file.",
            );
            return;
        }
        self.remember_path(&path);
        self.archive = Some(path);
        self.refresh_archive_meta();
    }

    fn effective_pack_output(&self) -> PathBuf {
        if let Some(path) = self.pack_output.as_ref() {
            return path.clone();
        }
        let base = self
            .inputs
            .first()
            .and_then(|p| {
                if p.is_dir() {
                    Some(p.clone())
                } else {
                    p.parent().map(Path::to_path_buf)
                }
            })
            .unwrap_or_else(default_user_dir);
        let stem = self
            .inputs
            .first()
            .and_then(|p| p.file_stem().or_else(|| p.file_name()))
            .and_then(|s| s.to_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("archive");
        base.join(format!("{stem}.noer"))
    }

    fn effective_pack_checksum_output(&self) -> PathBuf {
        let suffix = match self.pack_checksum.unwrap_or(ChecksumChoice::Sha256) {
            ChecksumChoice::Sha256 => "sha256",
            ChecksumChoice::Blake3 => "blake3",
        };
        append_path_suffix(&self.effective_pack_output(), suffix)
    }

    fn effective_unpack_output(&self) -> PathBuf {
        if let Some(path) = self.unpack_output.as_ref() {
            return path.clone();
        }
        if let Some(archive) = self.archive.as_ref() {
            let base = archive
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(default_user_dir);
            let stem = archive
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("archive");
            return base.join(format!("{stem}_out"));
        }
        default_user_dir().join("noer22_out")
    }

    fn recompute_estimates(&mut self) {
        let (total, files) = compute_total(&self.inputs);
        self.total_input = total;
        self.input_files = files;
        self.est_output = estimate_size(total, files, self.level);
    }

    fn refresh_archive_meta(&mut self) {
        self.archive_size = self
            .archive
            .as_ref()
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0);
        *self.inspect_result.lock().unwrap() = None;
    }

    fn apply_preset(&mut self, preset: Preset) {
        match preset {
            Preset::Fast => {
                self.level = 3;
                self.kdf_mem = 32;
                self.kdf_iters = 2;
                self.kdf_parallelism = 2;
            }
            Preset::Balanced => {
                self.level = 8;
                self.kdf_mem = 64;
                self.kdf_iters = 3;
                self.kdf_parallelism = 4;
            }
            Preset::Secure => {
                self.level = 12;
                self.kdf_mem = 128;
                self.kdf_iters = 4;
                self.kdf_parallelism = 4;
            }
        }
        self.recompute_estimates();
    }

    fn run_pack(&mut self) {
        if self.inputs.is_empty() {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Select at least one input file or folder.",
            );
            return;
        }

        let use_age = self.pack_auth_mode == PackAuthMode::AgeRecipients;
        let age_recipients = parse_age_recipients(&self.age_recipients_text);

        if use_age && age_recipients.is_empty() {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Add at least one age recipient.",
            );
            return;
        }
        if !use_age && self.password.is_empty() && self.keyfile.is_none() {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Provide a password or keyfile.",
            );
            return;
        }
        if !use_age && !self.password.is_empty() && self.password != self.confirm_password {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Confirm password does not match.",
            );
            return;
        }

        let inputs = self.inputs.clone();
        let target_path = self.effective_pack_output();
        let password = if use_age || self.password.is_empty() {
            None
        } else {
            Some(self.password.clone())
        };
        let keyfile = if use_age { None } else { self.keyfile.clone() };
        let cipher = self.cipher;
        let level = self.level;
        let kdf_mem = self.kdf_mem;
        let kdf_iters = self.kdf_iters;
        let kdf_parallelism = self.kdf_parallelism;
        let threads = self.threads;
        let parallel_crypto = self.parallel_crypto;
        let incremental_index = self.incremental_index.clone();
        let checksum = self.pack_checksum;
        let checksum_output = if checksum.is_some() {
            Some(
                self.pack_checksum_output
                    .clone()
                    .unwrap_or_else(|| self.effective_pack_checksum_output()),
            )
        } else {
            None
        };
        let status = self.status.clone();
        let running = self.running.clone();
        self.job_started = Some(Instant::now());
        running.store(true, Ordering::Relaxed);
        set_status(&status, StatusKind::Running, "Packing archive...");
        thread::spawn(move || {
            let result = std::panic::catch_unwind(|| {
                pack::pack(PackArgs {
                    inputs,
                    output: target_path.clone(),
                    password,
                    keyfile,
                    age_recipients,
                    level,
                    cipher,
                    kdf_mem,
                    kdf_iters,
                    kdf_parallelism,
                    threads: if threads == 0 { None } else { Some(threads) },
                    parallel_crypto,
                    incremental_index,
                    checksum,
                    checksum_output,
                })
            });
            match result {
                Ok(Ok(())) => set_status(
                    &status,
                    StatusKind::Success,
                    &format!("Completed: {}", target_path.display()),
                ),
                Ok(Err(e)) => set_status(&status, StatusKind::Error, &format!("Error: {e}")),
                Err(_) => set_status(
                    &status,
                    StatusKind::Error,
                    "Internal error while packing archive.",
                ),
            }
            running.store(false, Ordering::Relaxed);
        });
    }

    fn run_unpack(&mut self) {
        let archive = match self.archive.clone() {
            Some(path) => path,
            None => {
                set_status(
                    &self.status,
                    StatusKind::Warning,
                    "Select a .noer archive file.",
                );
                return;
            }
        };
        let using_age = self.archive_auth_mode == ArchiveAuthMode::AgeIdentities;
        if using_age && self.age_identities.is_empty() {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Add at least one age identity file.",
            );
            return;
        }
        if !using_age && self.password.is_empty() && self.keyfile.is_none() {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Provide password or keyfile.",
            );
            return;
        }
        let output = Some(self.effective_unpack_output());
        let password = if using_age || self.password.is_empty() {
            None
        } else {
            Some(self.password.clone())
        };
        let keyfile = if using_age {
            None
        } else {
            self.keyfile.clone()
        };
        let age_identities = if using_age {
            self.age_identities.clone()
        } else {
            Vec::new()
        };
        let checksum_file = self.unpack_checksum_file.clone();
        let checksum_algo = self.unpack_checksum_algo;
        let status = self.status.clone();
        let running = self.running.clone();
        self.job_started = Some(Instant::now());
        running.store(true, Ordering::Relaxed);
        set_status(&status, StatusKind::Running, "Extracting archive...");
        thread::spawn(move || {
            let result = std::panic::catch_unwind(|| {
                unpack::unpack(UnpackArgs {
                    archive,
                    password,
                    keyfile,
                    age_identities,
                    output,
                    checksum_file,
                    checksum_algo,
                })
            });
            match result {
                Ok(Ok(())) => set_status(&status, StatusKind::Success, "Completed"),
                Ok(Err(e)) => set_status(&status, StatusKind::Error, &format!("Error: {e}")),
                Err(_) => set_status(
                    &status,
                    StatusKind::Error,
                    "Internal error while extracting.",
                ),
            }
            running.store(false, Ordering::Relaxed);
        });
    }

    fn run_list(&mut self) {
        let archive_path = match self.archive.clone() {
            Some(path) => path,
            None => {
                set_status(
                    &self.status,
                    StatusKind::Warning,
                    "Select a .noer archive file.",
                );
                return;
            }
        };
        let using_age = self.archive_auth_mode == ArchiveAuthMode::AgeIdentities;
        if using_age && self.age_identities.is_empty() {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Add at least one age identity file.",
            );
            return;
        }
        if !using_age && self.password.is_empty() && self.keyfile.is_none() {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Provide password or keyfile.",
            );
            return;
        }
        let password = if using_age || self.password.is_empty() {
            None
        } else {
            Some(self.password.clone())
        };
        let keyfile = if using_age {
            None
        } else {
            self.keyfile.clone()
        };
        let age_identities = if using_age {
            self.age_identities.clone()
        } else {
            Vec::new()
        };
        let detailed = self.list_long;
        let status = self.status.clone();
        let running = self.running.clone();
        let inspect_result = self.inspect_result.clone();
        self.job_started = Some(Instant::now());
        running.store(true, Ordering::Relaxed);
        *inspect_result.lock().unwrap() = None;
        set_status(&status, StatusKind::Running, "Inspecting archive...");

        thread::spawn(move || {
            let result = std::panic::catch_unwind(|| {
                unpack::inspect_archive_with_auth(
                    &archive_path,
                    password.as_deref(),
                    keyfile.as_deref(),
                    &age_identities,
                )
                .map(|info| {
                    if detailed {
                        info
                    } else {
                        let mut compact = info;
                        compact.entries.sort_by(|a, b| a.path.cmp(&b.path));
                        compact
                    }
                })
            });

            match result {
                Ok(Ok(info)) => {
                    *inspect_result.lock().unwrap() = Some(info);
                    set_status(
                        &status,
                        StatusKind::Success,
                        "Inspection completed. Review entries below.",
                    );
                }
                Ok(Err(e)) => set_status(&status, StatusKind::Error, &format!("Error: {e}")),
                Err(_) => set_status(
                    &status,
                    StatusKind::Error,
                    "Internal error while inspecting.",
                ),
            }
            running.store(false, Ordering::Relaxed);
        });
    }

    fn run_verify(&mut self) {
        let archive_path = match self.archive.clone() {
            Some(path) => path,
            None => {
                set_status(
                    &self.status,
                    StatusKind::Warning,
                    "Select a .noer archive file.",
                );
                return;
            }
        };
        let using_age = self.archive_auth_mode == ArchiveAuthMode::AgeIdentities;
        let has_checksum = self.verify_checksum_file.is_some();
        let has_auth = if using_age {
            !self.age_identities.is_empty()
        } else {
            !self.password.is_empty() || self.keyfile.is_some()
        };
        if !has_checksum && !has_auth {
            set_status(
                &self.status,
                StatusKind::Warning,
                "Provide auth material or checksum file.",
            );
            return;
        }
        let password = if using_age || self.password.is_empty() {
            None
        } else {
            Some(self.password.clone())
        };
        let keyfile = if using_age {
            None
        } else {
            self.keyfile.clone()
        };
        let age_identities = if using_age {
            self.age_identities.clone()
        } else {
            Vec::new()
        };
        let checksum_file = self.verify_checksum_file.clone();
        let checksum_algo = self.verify_checksum_algo;
        let status = self.status.clone();
        let running = self.running.clone();
        self.job_started = Some(Instant::now());
        running.store(true, Ordering::Relaxed);
        set_status(
            &status,
            StatusKind::Running,
            "Verifying archive integrity...",
        );

        thread::spawn(move || {
            let result = std::panic::catch_unwind(|| {
                unpack::verify(VerifyArgs {
                    archive: archive_path,
                    password,
                    keyfile,
                    age_identities,
                    checksum_file,
                    checksum_algo,
                })
            });
            match result {
                Ok(Ok(())) => {
                    set_status(&status, StatusKind::Success, "Integrity check passed.");
                }
                Ok(Err(e)) => set_status(&status, StatusKind::Error, &format!("Error: {e}")),
                Err(_) => set_status(
                    &status,
                    StatusKind::Error,
                    "Internal error while verifying.",
                ),
            }
            running.store(false, Ordering::Relaxed);
        });
    }

    fn apply_theme(&self, ctx: &egui::Context) {
        use egui::{style::Selection, Shadow, Visuals};
        let mut style = (*ctx.style()).clone();
        style.visuals = Visuals::dark();
        style.visuals.override_text_color = Some(rgb(209, 213, 219));
        style.visuals.panel_fill = rgb(10, 10, 10);
        style.visuals.extreme_bg_color = rgb(12, 15, 26);
        style.visuals.widgets.noninteractive.fg_stroke.color = rgb(209, 213, 219);
        style.visuals.widgets.inactive.bg_fill = rgb(18, 20, 32);
        style.visuals.widgets.inactive.fg_stroke.color = rgb(223, 205, 152);
        style.visuals.widgets.hovered.bg_fill = rgb(28, 30, 45);
        style.visuals.widgets.hovered.fg_stroke.color = rgb(230, 210, 150);
        style.visuals.widgets.active.bg_fill = rgb(45, 40, 25);
        style.visuals.widgets.active.fg_stroke.color = rgb(212, 175, 55);
        style.visuals.selection = Selection {
            bg_fill: rgb(100, 30, 22),
            stroke: egui::Stroke::new(1.5, rgb(212, 175, 55)),
        };
        style.visuals.window_shadow = Shadow {
            offset: egui::vec2(0.0, 6.0),
            blur: 24.0,
            spread: 0.0,
            color: rgba(0, 0, 0, 180),
        };
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(12.0, 8.0);
        style
            .text_styles
            .insert(egui::TextStyle::Heading, egui::FontId::proportional(30.0));
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        ctx.set_style(style);
    }

    fn paint_background(&self, ctx: &egui::Context, status: StatusKind) {
        use egui::{Color32, Id, LayerId, Order, Pos2, Shape, Stroke};
        let rect = ctx.screen_rect();
        let painter = ctx.layer_painter(LayerId::new(Order::Background, Id::new("bg")));

        painter.rect_filled(rect, 0.0, rgb(10, 10, 10));

        for i in 0..7 {
            let inset = 8.0 * i as f32;
            let alpha = 24u8.saturating_sub(i * 3);
            let glow = Color32::from_rgba_unmultiplied(15, 23, 42, alpha);
            let r = rect.shrink(inset);
            painter.add(Shape::rect_filled(r, 0.0, glow));
        }

        let beam = vec![
            Pos2::new(rect.min.x - rect.width() * 0.15, rect.min.y),
            Pos2::new(rect.min.x + rect.width() * 0.55, rect.min.y),
            Pos2::new(rect.min.x + rect.width() * 0.25, rect.max.y),
        ];
        painter.add(Shape::convex_polygon(
            beam,
            rgba(212, 175, 55, 14),
            Stroke::NONE,
        ));

        let beam2 = vec![
            Pos2::new(rect.min.x + rect.width() * 0.35, rect.min.y),
            Pos2::new(rect.max.x + rect.width() * 0.05, rect.min.y),
            Pos2::new(rect.min.x + rect.width() * 0.75, rect.max.y),
        ];
        painter.add(Shape::convex_polygon(
            beam2,
            rgba(212, 175, 55, 10),
            Stroke::NONE,
        ));

        for dot in &self.noise {
            let x = rect.min.x + dot.x * rect.width();
            let y = rect.min.y + dot.y * rect.height();
            painter.add(Shape::circle_filled(
                Pos2::new(x, y),
                dot.radius,
                rgba(20, 20, 28, dot.alpha),
            ));
        }

        let time = ctx.input(|i| i.time) as f32;
        for p in &self.gold_particles {
            let x = rect.min.x + wrap01(p.x + (time * p.drift).sin() * 0.01) * rect.width();
            let y = rect.min.y + wrap01(p.y + time * p.speed) * rect.height();
            let color = Color32::from_rgba_unmultiplied(212, 175, 55, p.alpha);
            painter.add(Shape::circle_filled(Pos2::new(x, y), p.radius, color));
        }

        if status == StatusKind::Error {
            for p in &self.crimson_particles {
                let x = rect.min.x + wrap01(p.x + (time * p.drift).sin() * 0.02) * rect.width();
                let y = rect.min.y + wrap01(p.y + time * p.speed) * rect.height();
                let color = Color32::from_rgba_unmultiplied(100, 30, 22, p.alpha);
                painter.add(Shape::circle_filled(Pos2::new(x, y), p.radius, color));
            }
        }

        let border = rect.shrink(6.0);
        painter.add(Shape::rect_stroke(
            border,
            8.0,
            Stroke::new(1.1, rgb(191, 164, 111)),
        ));

        paint_corner_ornaments(&painter, border, rgb(191, 164, 111));
    }

    fn handle_drops(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }
        match self.mode {
            Mode::Pack => {
                let paths: Vec<PathBuf> = dropped.into_iter().filter_map(|f| f.path).collect();
                self.add_input_paths(paths);
            }
            Mode::Unpack | Mode::List | Mode::Verify => {
                let mut selected = false;
                for file in dropped {
                    if let Some(path) = file.path {
                        if is_noer_file(&path) {
                            self.set_archive_path(path);
                            selected = true;
                            break;
                        }
                    }
                }
                if !selected {
                    set_status(
                        &self.status,
                        StatusKind::Warning,
                        "Drop a .noer file to select an archive.",
                    );
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Preset {
    Fast,
    Balanced,
    Secure,
}

fn card(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    let frame = egui::Frame::none()
        .fill(rgb(14, 16, 26))
        .stroke(egui::Stroke::new(1.0, rgb(191, 164, 111)))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(12.0));
    frame.show(ui, |ui| {
        ui.label(egui::RichText::new(title).strong().color(rgb(212, 175, 55)));
        ui.add_space(4.0);
        add(ui);
    });
    ui.add_space(8.0);
}

fn metric_card(ui: &mut egui::Ui, label: &str, value: &str, accent: egui::Color32) {
    let frame = egui::Frame::none()
        .fill(rgba(18, 20, 32, 200))
        .stroke(egui::Stroke::new(1.0, rgba(212, 175, 55, 60)))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::symmetric(10.0, 8.0));
    frame.show(ui, |ui| {
        ui.label(egui::RichText::new(label).color(rgb(191, 164, 111)));
        ui.label(egui::RichText::new(value).strong().color(accent));
    });
}

fn mode_switch(ui: &mut egui::Ui, mode: &mut Mode) {
    ui.horizontal(|ui| {
        ui.selectable_value(mode, Mode::Pack, "Pack");
        ui.selectable_value(mode, Mode::Unpack, "Extract");
        ui.selectable_value(mode, Mode::List, "List");
        ui.selectable_value(mode, Mode::Verify, "Verify");
    });
    ui.separator();
}

fn gold_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(text).color(rgb(20, 16, 10)))
        .fill(rgb(212, 175, 55))
        .stroke(egui::Stroke::new(1.0, rgb(191, 164, 111)))
        .rounding(6.0)
}

fn dark_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(text).color(rgb(209, 213, 219)))
        .fill(rgba(18, 20, 32, 180))
        .stroke(egui::Stroke::new(1.0, rgba(212, 175, 55, 60)))
        .rounding(6.0)
}

fn set_status(state: &Arc<Mutex<StatusState>>, kind: StatusKind, msg: &str) {
    let mut guard = state.lock().unwrap();
    guard.message = msg.to_string();
    guard.kind = kind;
}

fn status_color(kind: StatusKind) -> egui::Color32 {
    match kind {
        StatusKind::Idle => rgb(209, 213, 219),
        StatusKind::Warning => rgb(191, 164, 111),
        StatusKind::Running => rgb(212, 175, 55),
        StatusKind::Success => rgb(224, 200, 110),
        StatusKind::Error => rgb(120, 30, 22),
    }
}

fn status_label(kind: StatusKind) -> &'static str {
    match kind {
        StatusKind::Idle => "Ready",
        StatusKind::Warning => "Warning",
        StatusKind::Running => "Running",
        StatusKind::Success => "Success",
        StatusKind::Error => "Error",
    }
}

fn password_strength(password: &str) -> (f32, &'static str, egui::Color32) {
    if password.is_empty() {
        return (0.0, "empty", rgb(100, 30, 22));
    }
    let mut score = 0;
    let len = password.chars().count();
    if len >= 8 {
        score += 1;
    }
    if len >= 12 {
        score += 1;
    }
    if password.chars().any(|c| c.is_lowercase()) && password.chars().any(|c| c.is_uppercase()) {
        score += 1;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        score += 1;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        score += 1;
    }
    let strength = (score as f32) / 5.0;
    match score {
        0 | 1 => (strength, "weak", rgb(120, 30, 22)),
        2 | 3 => (strength, "fair", rgb(191, 164, 111)),
        4 => (strength, "strong", rgb(212, 175, 55)),
        _ => (strength, "excellent", rgb(240, 214, 140)),
    }
}

fn compute_total(paths: &[PathBuf]) -> (u64, usize) {
    let mut total = 0;
    let mut files = 0;
    for p in paths {
        if let Ok(meta) = fs::metadata(p) {
            if meta.is_file() {
                total += meta.len();
                files += 1;
            } else if meta.is_dir() {
                for entry in walkdir::WalkDir::new(p).into_iter().flatten() {
                    if entry.file_type().is_file() {
                        if let Ok(m) = entry.metadata() {
                            total += m.len();
                            files += 1;
                        }
                    }
                }
            }
        }
    }
    (total, files)
}

fn estimate_size(total_input: u64, file_count: usize, level: i32) -> u64 {
    if total_input == 0 {
        return 0;
    }
    let ratio = if level <= 0 {
        0.95
    } else if level <= 5 {
        0.70
    } else if level <= 10 {
        0.58
    } else if level <= 15 {
        0.48
    } else {
        0.40
    };
    let meta_est = 64 + (file_count as u64) * 192 + 1024;
    ((total_input as f64 * ratio) as u64) + meta_est
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut idx = 0;
    while v >= 1024.0 && idx < UNITS.len() - 1 {
        v /= 1024.0;
        idx += 1;
    }
    format!("{:.2} {}", v, UNITS[idx])
}

fn default_user_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    if let Some(home) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(home);
    }

    #[cfg(not(target_os = "windows"))]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home);
    }

    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn is_noer_file(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("noer"))
            .unwrap_or(false)
}

fn path_key(path: &Path) -> String {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let key = canonical.to_string_lossy().replace('\\', "/");
    #[cfg(target_os = "windows")]
    {
        key.to_lowercase()
    }
    #[cfg(not(target_os = "windows"))]
    {
        key
    }
}

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut rendered = path.as_os_str().to_os_string();
    rendered.push(".");
    rendered.push(suffix);
    PathBuf::from(rendered)
}

fn parse_age_recipients(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in text
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        if !raw.starts_with("age1") {
            continue;
        }
        let value = raw.to_string();
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

struct Particle {
    x: f32,
    y: f32,
    radius: f32,
    alpha: u8,
    speed: f32,
    drift: f32,
}

struct NoiseDot {
    x: f32,
    y: f32,
    radius: f32,
    alpha: u8,
}

#[allow(clippy::too_many_arguments)]
fn make_particles(
    count: usize,
    seed: u32,
    min_radius: f32,
    max_radius: f32,
    min_speed: f32,
    max_speed: f32,
    min_alpha: u8,
    max_alpha: u8,
) -> Vec<Particle> {
    let mut seed = seed;
    let mut next = || {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        (seed as f32 / u32::MAX as f32).clamp(0.0, 1.0)
    };
    let mut particles = Vec::new();
    for _ in 0..count {
        let x = next();
        let y = next();
        let radius = min_radius + next() * (max_radius - min_radius);
        let alpha = (min_alpha as f32 + next() * (max_alpha - min_alpha) as f32) as u8;
        let speed = min_speed + next() * (max_speed - min_speed);
        let drift = 0.3 + next() * 0.9;
        particles.push(Particle {
            x,
            y,
            radius,
            alpha,
            speed,
            drift,
        });
    }
    particles
}

fn make_noise(count: usize, seed: u32) -> Vec<NoiseDot> {
    let mut seed = seed;
    let mut next = || {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        (seed as f32 / u32::MAX as f32).clamp(0.0, 1.0)
    };
    let mut dots = Vec::new();
    for _ in 0..count {
        let x = next();
        let y = next();
        let radius = 0.4 + next() * 1.2;
        let alpha = (10.0 + next() * 18.0) as u8;
        dots.push(NoiseDot {
            x,
            y,
            radius,
            alpha,
        });
    }
    dots
}

fn wrap01(value: f32) -> f32 {
    value.rem_euclid(1.0)
}

fn paint_glow_text(
    painter: &egui::Painter,
    pos: egui::Pos2,
    align: egui::Align2,
    text: &str,
    font: egui::FontId,
    color: egui::Color32,
    glow: egui::Color32,
) {
    let offsets = [
        egui::vec2(1.0, 0.0),
        egui::vec2(-1.0, 0.0),
        egui::vec2(0.0, 1.0),
        egui::vec2(0.0, -1.0),
    ];
    for offset in offsets {
        painter.text(pos + offset, align, text, font.clone(), glow);
    }
    painter.text(pos, align, text, font, color);
}

fn paint_vault_icon(painter: &egui::Painter, rect: egui::Rect) {
    let center = rect.center();
    let radius = rect.width().min(rect.height()) * 0.38;

    painter.circle_filled(center, radius, rgba(18, 18, 24, 220));
    painter.circle_stroke(center, radius, egui::Stroke::new(2.0, rgb(212, 175, 55)));

    let shackle_rect = egui::Rect::from_center_size(
        center + egui::vec2(0.0, -radius * 0.75),
        egui::vec2(radius * 1.2, radius * 1.0),
    );
    painter.rect_stroke(
        shackle_rect,
        egui::Rounding::same(radius * 0.5),
        egui::Stroke::new(2.0, rgb(191, 164, 111)),
    );

    painter.circle_filled(center, radius * 0.18, rgba(4, 4, 6, 200));
    painter.rect_filled(
        egui::Rect::from_center_size(
            center + egui::vec2(0.0, radius * 0.25),
            egui::vec2(radius * 0.2, radius * 0.35),
        ),
        1.0,
        rgba(4, 4, 6, 200),
    );

    let highlight = egui::Rect::from_min_max(
        egui::pos2(center.x + radius * 0.1, center.y - radius * 0.6),
        egui::pos2(center.x + radius * 0.55, center.y + radius * 0.4),
    );
    painter.rect_filled(highlight, 4.0, rgba(212, 175, 55, 22));
}

fn paint_corner_ornaments(painter: &egui::Painter, rect: egui::Rect, color: egui::Color32) {
    let stroke = egui::Stroke::new(1.0, color);
    let radius = 18.0;
    let inner = 10.0;

    paint_arc(
        painter,
        rect.left_top() + egui::vec2(radius, radius),
        radius,
        180.0,
        270.0,
        stroke,
    );
    paint_arc(
        painter,
        rect.left_top() + egui::vec2(radius, radius),
        inner,
        200.0,
        270.0,
        stroke,
    );

    paint_arc(
        painter,
        rect.right_top() + egui::vec2(-radius, radius),
        radius,
        270.0,
        360.0,
        stroke,
    );
    paint_arc(
        painter,
        rect.right_top() + egui::vec2(-radius, radius),
        inner,
        270.0,
        340.0,
        stroke,
    );

    paint_arc(
        painter,
        rect.right_bottom() + egui::vec2(-radius, -radius),
        radius,
        0.0,
        90.0,
        stroke,
    );
    paint_arc(
        painter,
        rect.right_bottom() + egui::vec2(-radius, -radius),
        inner,
        20.0,
        90.0,
        stroke,
    );

    paint_arc(
        painter,
        rect.left_bottom() + egui::vec2(radius, -radius),
        radius,
        90.0,
        180.0,
        stroke,
    );
    paint_arc(
        painter,
        rect.left_bottom() + egui::vec2(radius, -radius),
        inner,
        90.0,
        160.0,
        stroke,
    );
}

fn paint_arc(
    painter: &egui::Painter,
    center: egui::Pos2,
    radius: f32,
    start_deg: f32,
    end_deg: f32,
    stroke: egui::Stroke,
) {
    let steps = 10;
    let start = start_deg.to_radians();
    let end = end_deg.to_radians();
    let mut points = Vec::with_capacity(steps + 1);
    for i in 0..=steps {
        let t = i as f32 / steps as f32;
        let angle = start + (end - start) * t;
        points.push(egui::pos2(
            center.x + angle.cos() * radius,
            center.y + angle.sin() * radius,
        ));
    }
    painter.add(egui::Shape::line(points, stroke));
}

fn rgb(r: u8, g: u8, b: u8) -> egui::Color32 {
    egui::Color32::from_rgb(r, g, b)
}

fn rgba(r: u8, g: u8, b: u8, a: u8) -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(r, g, b, a)
}
