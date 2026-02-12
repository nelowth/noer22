use crate::cli::{ChecksumChoice, CipherChoice, ListArgs, PackArgs, UnpackArgs, VerifyArgs};
use crate::error::{NoerError, Result};
use crate::{pack, unpack};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;
use ratatui::widgets::*;
use std::io;
use std::path::PathBuf;
use std::time::Duration;
use zxcvbn::{zxcvbn, Score};

pub fn run() -> Result<()> {
    let mut stdout = io::stdout();
    enable_raw_mode().map_err(io_to_err)?;
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture, Hide).map_err(io_to_err)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(io_to_err)?;

    let mut app = App::default();
    let loop_result = run_loop(&mut terminal, &mut app);

    let mut cleanup_error = None;
    if let Err(err) = disable_raw_mode().map_err(io_to_err) {
        cleanup_error = Some(err);
    }
    if let Err(err) = execute!(
        terminal.backend_mut(),
        Show,
        DisableMouseCapture,
        LeaveAlternateScreen
    )
    .map_err(io_to_err)
    {
        cleanup_error = Some(err);
    }
    if let Err(err) = terminal.show_cursor().map_err(io_to_err) {
        cleanup_error = Some(err);
    }

    loop_result?;
    if let Some(err) = cleanup_error {
        return Err(err);
    }
    Ok(())
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal
            .draw(|frame| render(frame, app))
            .map_err(io_to_err)?;

        if event::poll(Duration::from_millis(200)).map_err(io_to_err)? {
            if let Event::Key(key) = event::read().map_err(io_to_err)? {
                if key.kind == event::KeyEventKind::Press && app.handle_key(key, terminal)? {
                    return Ok(());
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Pack,
    Unpack,
    List,
    Verify,
}

impl Mode {
    fn title(self) -> &'static str {
        match self {
            Mode::Pack => "Pack",
            Mode::Unpack => "Unpack",
            Mode::List => "List",
            Mode::Verify => "Verify",
        }
    }
}

struct App {
    mode: Mode,
    cursor: usize,
    status: String,
    pack: PackForm,
    unpack: UnpackForm,
    list: ListForm,
    verify: VerifyForm,
}

impl Default for App {
    fn default() -> Self {
        Self {
            mode: Mode::Pack,
            cursor: 0,
            status: "Ready. F1-F4 to switch modes, Tab to move, Enter to run, q to quit.".into(),
            pack: PackForm::default(),
            unpack: UnpackForm::default(),
            list: ListForm::default(),
            verify: VerifyForm::default(),
        }
    }
}

impl App {
    fn field_count(&self) -> usize {
        match self.mode {
            Mode::Pack => PACK_FIELDS,
            Mode::Unpack => UNPACK_FIELDS,
            Mode::List => LIST_FIELDS,
            Mode::Verify => VERIFY_FIELDS,
        }
    }

    fn next_field(&mut self) {
        self.cursor = (self.cursor + 1) % self.field_count();
    }

    fn prev_field(&mut self) {
        if self.cursor == 0 {
            self.cursor = self.field_count() - 1;
        } else {
            self.cursor -= 1;
        }
    }

    fn switch_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.cursor = 0;
    }

    fn handle_key(
        &mut self,
        key: KeyEvent,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::F(1) | KeyCode::Char('1') => {
                self.switch_mode(Mode::Pack);
                return Ok(false);
            }
            KeyCode::F(2) | KeyCode::Char('2') => {
                self.switch_mode(Mode::Unpack);
                return Ok(false);
            }
            KeyCode::F(3) | KeyCode::Char('3') => {
                self.switch_mode(Mode::List);
                return Ok(false);
            }
            KeyCode::F(4) | KeyCode::Char('4') => {
                self.switch_mode(Mode::Verify);
                return Ok(false);
            }
            KeyCode::Tab | KeyCode::Down => {
                self.next_field();
                return Ok(false);
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.prev_field();
                return Ok(false);
            }
            _ => {}
        }

        match self.mode {
            Mode::Pack => self.handle_pack_key(key, terminal)?,
            Mode::Unpack => self.handle_unpack_key(key, terminal)?,
            Mode::List => self.handle_list_key(key, terminal)?,
            Mode::Verify => self.handle_verify_key(key, terminal)?,
        }
        Ok(false)
    }

    fn handle_pack_key(
        &mut self,
        key: KeyEvent,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<()> {
        match self.cursor {
            8 => handle_choice_key(key, &mut self.pack.checksum_choice, 3),
            10 => handle_toggle_key(key, &mut self.pack.parallel_crypto),
            11 => {
                if key.code == KeyCode::Enter {
                    let args = match self.pack.to_args() {
                        Ok(args) => args,
                        Err(err) => {
                            self.status = format!("Pack args error: {err}");
                            return Ok(());
                        }
                    };
                    self.run_with_suspend(terminal, || pack::pack(args), "Pack completed")?;
                }
            }
            _ => {
                if let Some(field) = self.pack_text_mut(self.cursor) {
                    edit_text_field(key, field);
                } else {
                    self.status = format!("Internal UI error: invalid pack field {}", self.cursor);
                }
            }
        }
        Ok(())
    }

    fn handle_unpack_key(
        &mut self,
        key: KeyEvent,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<()> {
        match self.cursor {
            6 => handle_choice_key(key, &mut self.unpack.checksum_algo_choice, 3),
            7 => {
                if key.code == KeyCode::Enter {
                    let args = match self.unpack.to_args() {
                        Ok(args) => args,
                        Err(err) => {
                            self.status = format!("Unpack args error: {err}");
                            return Ok(());
                        }
                    };
                    self.run_with_suspend(terminal, || unpack::unpack(args), "Unpack completed")?;
                }
            }
            _ => {
                if let Some(field) = self.unpack_text_mut(self.cursor) {
                    edit_text_field(key, field);
                } else {
                    self.status =
                        format!("Internal UI error: invalid unpack field {}", self.cursor);
                }
            }
        }
        Ok(())
    }

    fn handle_list_key(
        &mut self,
        key: KeyEvent,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<()> {
        match self.cursor {
            4 => handle_toggle_key(key, &mut self.list.long),
            5 => {
                if key.code == KeyCode::Enter {
                    let args = match self.list.to_args() {
                        Ok(args) => args,
                        Err(err) => {
                            self.status = format!("List args error: {err}");
                            return Ok(());
                        }
                    };
                    self.run_with_suspend(terminal, || unpack::list(args), "List completed")?;
                }
            }
            _ => {
                if let Some(field) = self.list_text_mut(self.cursor) {
                    edit_text_field(key, field);
                } else {
                    self.status = format!("Internal UI error: invalid list field {}", self.cursor);
                }
            }
        }
        Ok(())
    }

    fn handle_verify_key(
        &mut self,
        key: KeyEvent,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<()> {
        match self.cursor {
            5 => handle_choice_key(key, &mut self.verify.checksum_algo_choice, 3),
            6 => {
                if key.code == KeyCode::Enter {
                    let args = match self.verify.to_args() {
                        Ok(args) => args,
                        Err(err) => {
                            self.status = format!("Verify args error: {err}");
                            return Ok(());
                        }
                    };
                    self.run_with_suspend(terminal, || unpack::verify(args), "Verify completed")?;
                }
            }
            _ => {
                if let Some(field) = self.verify_text_mut(self.cursor) {
                    edit_text_field(key, field);
                } else {
                    self.status =
                        format!("Internal UI error: invalid verify field {}", self.cursor);
                }
            }
        }
        Ok(())
    }

    fn run_with_suspend<F>(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
        op: F,
        success: &str,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        suspend_terminal(terminal)?;
        let result = op();
        resume_terminal(terminal)?;
        terminal.clear().map_err(io_to_err)?;
        match result {
            Ok(()) => self.status = success.to_string(),
            Err(err) => self.status = format!("Error: {err}"),
        }
        Ok(())
    }

    fn pack_text_mut(&mut self, idx: usize) -> Option<&mut String> {
        match idx {
            0 => Some(&mut self.pack.inputs),
            1 => Some(&mut self.pack.output),
            2 => Some(&mut self.pack.password),
            3 => Some(&mut self.pack.keyfile),
            4 => Some(&mut self.pack.age_recipients),
            5 => Some(&mut self.pack.level),
            6 => Some(&mut self.pack.threads),
            7 => Some(&mut self.pack.incremental_index),
            9 => Some(&mut self.pack.checksum_output),
            _ => None,
        }
    }

    fn unpack_text_mut(&mut self, idx: usize) -> Option<&mut String> {
        match idx {
            0 => Some(&mut self.unpack.archive),
            1 => Some(&mut self.unpack.password),
            2 => Some(&mut self.unpack.keyfile),
            3 => Some(&mut self.unpack.age_identities),
            4 => Some(&mut self.unpack.output),
            5 => Some(&mut self.unpack.checksum_file),
            _ => None,
        }
    }

    fn list_text_mut(&mut self, idx: usize) -> Option<&mut String> {
        match idx {
            0 => Some(&mut self.list.archive),
            1 => Some(&mut self.list.password),
            2 => Some(&mut self.list.keyfile),
            3 => Some(&mut self.list.age_identities),
            _ => None,
        }
    }

    fn verify_text_mut(&mut self, idx: usize) -> Option<&mut String> {
        match idx {
            0 => Some(&mut self.verify.archive),
            1 => Some(&mut self.verify.password),
            2 => Some(&mut self.verify.keyfile),
            3 => Some(&mut self.verify.age_identities),
            4 => Some(&mut self.verify.checksum_file),
            _ => None,
        }
    }
}

#[derive(Default)]
struct PackForm {
    inputs: String,
    output: String,
    password: String,
    keyfile: String,
    age_recipients: String,
    level: String,
    threads: String,
    incremental_index: String,
    checksum_choice: usize,
    checksum_output: String,
    parallel_crypto: bool,
}

impl PackForm {
    fn to_args(&self) -> Result<PackArgs> {
        let inputs = parse_paths_csv(&self.inputs);
        if inputs.is_empty() {
            return Err(NoerError::InvalidFormat(
                "provide at least one input path".into(),
            ));
        }

        let output = path_required(&self.output, "output path")?;
        let level = parse_i32_default(&self.level, 6, "level")?;
        let threads = parse_usize_default(&self.threads, 0, "threads")?;

        Ok(PackArgs {
            inputs,
            output,
            password: opt_string(&self.password),
            keyfile: opt_path(&self.keyfile),
            age_recipients: parse_csv_strings(&self.age_recipients),
            level,
            cipher: CipherChoice::ChaCha20Poly1305,
            kdf_mem: 64,
            kdf_iters: 3,
            kdf_parallelism: 4,
            threads: if threads == 0 { None } else { Some(threads) },
            parallel_crypto: self.parallel_crypto,
            incremental_index: opt_path(&self.incremental_index),
            checksum: choice_to_checksum(self.checksum_choice),
            checksum_output: opt_path(&self.checksum_output),
        })
    }
}

#[derive(Default)]
struct UnpackForm {
    archive: String,
    password: String,
    keyfile: String,
    age_identities: String,
    output: String,
    checksum_file: String,
    checksum_algo_choice: usize,
}

impl UnpackForm {
    fn to_args(&self) -> Result<UnpackArgs> {
        Ok(UnpackArgs {
            archive: path_required(&self.archive, "archive path")?,
            password: opt_string(&self.password),
            keyfile: opt_path(&self.keyfile),
            age_identities: parse_paths_csv(&self.age_identities),
            output: opt_path(&self.output),
            checksum_file: opt_path(&self.checksum_file),
            checksum_algo: choice_to_checksum_algo(self.checksum_algo_choice),
        })
    }
}

#[derive(Default)]
struct ListForm {
    archive: String,
    password: String,
    keyfile: String,
    age_identities: String,
    long: bool,
}

impl ListForm {
    fn to_args(&self) -> Result<ListArgs> {
        Ok(ListArgs {
            archive: path_required(&self.archive, "archive path")?,
            password: opt_string(&self.password),
            keyfile: opt_path(&self.keyfile),
            age_identities: parse_paths_csv(&self.age_identities),
            long: self.long,
        })
    }
}

#[derive(Default)]
struct VerifyForm {
    archive: String,
    password: String,
    keyfile: String,
    age_identities: String,
    checksum_file: String,
    checksum_algo_choice: usize,
}

impl VerifyForm {
    fn to_args(&self) -> Result<VerifyArgs> {
        Ok(VerifyArgs {
            archive: path_required(&self.archive, "archive path")?,
            password: opt_string(&self.password),
            keyfile: opt_path(&self.keyfile),
            age_identities: parse_paths_csv(&self.age_identities),
            checksum_file: opt_path(&self.checksum_file),
            checksum_algo: choice_to_checksum_algo(self.checksum_algo_choice),
        })
    }
}

const PACK_FIELDS: usize = 12;
const UNPACK_FIELDS: usize = 8;
const LIST_FIELDS: usize = 6;
const VERIFY_FIELDS: usize = 7;

fn render(frame: &mut Frame<'_>, app: &App) {
    let outer = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Min(10),
        Constraint::Length(3),
    ])
    .split(frame.area());

    let title = Paragraph::new("noer22 TUI :: F1 Pack | F2 Unpack | F3 List | F4 Verify | q Quit")
        .style(Style::default().fg(Color::Yellow));
    frame.render_widget(title, outer[0]);

    let tabs = Tabs::new(["Pack", "Unpack", "List", "Verify"]).select(match app.mode {
        Mode::Pack => 0,
        Mode::Unpack => 1,
        Mode::List => 2,
        Mode::Verify => 3,
    });
    frame.render_widget(tabs.block(Block::bordered().title("Mode")), outer[1]);

    let lines = match app.mode {
        Mode::Pack => pack_lines(app),
        Mode::Unpack => unpack_lines(app),
        Mode::List => list_lines(app),
        Mode::Verify => verify_lines(app),
    };

    let items: Vec<ListItem> = lines
        .iter()
        .enumerate()
        .map(|(idx, text)| {
            let style = if idx == app.cursor {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(text.clone()).style(style)
        })
        .collect();

    frame.render_widget(
        List::new(items).block(Block::bordered().title(app.mode.title())),
        outer[2],
    );

    frame.render_widget(
        Paragraph::new(app.status.clone()).block(Block::bordered().title("Status")),
        outer[3],
    );
}

fn pack_lines(app: &App) -> Vec<String> {
    vec![
        format!("inputs (csv): {}", app.pack.inputs),
        format!("output: {}", app.pack.output),
        format!(
            "password: {} ({})",
            mask(&app.pack.password),
            password_strength_label(&app.pack.password)
        ),
        format!("keyfile: {}", app.pack.keyfile),
        format!("age recipients (csv): {}", app.pack.age_recipients),
        format!("level: {}", default_display(&app.pack.level, "6")),
        format!(
            "threads (0=auto): {}",
            default_display(&app.pack.threads, "0")
        ),
        format!("incremental index: {}", app.pack.incremental_index),
        format!(
            "checksum: {}",
            checksum_choice_label(app.pack.checksum_choice)
        ),
        format!("checksum output: {}", app.pack.checksum_output),
        format!(
            "parallel crypto (exp): {}",
            bool_label(app.pack.parallel_crypto)
        ),
        "[ Enter ] Run Pack".into(),
    ]
}

fn unpack_lines(app: &App) -> Vec<String> {
    vec![
        format!("archive: {}", app.unpack.archive),
        format!("password: {}", mask(&app.unpack.password)),
        format!("keyfile: {}", app.unpack.keyfile),
        format!("age identities (csv): {}", app.unpack.age_identities),
        format!("output dir (optional): {}", app.unpack.output),
        format!("checksum file: {}", app.unpack.checksum_file),
        format!(
            "checksum algo: {}",
            checksum_algo_label(app.unpack.checksum_algo_choice)
        ),
        "[ Enter ] Run Unpack".into(),
    ]
}

fn list_lines(app: &App) -> Vec<String> {
    vec![
        format!("archive: {}", app.list.archive),
        format!("password: {}", mask(&app.list.password)),
        format!("keyfile: {}", app.list.keyfile),
        format!("age identities (csv): {}", app.list.age_identities),
        format!("detailed (--long): {}", bool_label(app.list.long)),
        "[ Enter ] Run List".into(),
    ]
}

fn verify_lines(app: &App) -> Vec<String> {
    vec![
        format!("archive: {}", app.verify.archive),
        format!("password: {}", mask(&app.verify.password)),
        format!("keyfile: {}", app.verify.keyfile),
        format!("age identities (csv): {}", app.verify.age_identities),
        format!("checksum file: {}", app.verify.checksum_file),
        format!(
            "checksum algo: {}",
            checksum_algo_label(app.verify.checksum_algo_choice)
        ),
        "[ Enter ] Run Verify".into(),
    ]
}

fn edit_text_field(key: KeyEvent, target: &mut String) {
    match key.code {
        KeyCode::Backspace => {
            target.pop();
        }
        KeyCode::Char(c) => {
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                if c == 'u' {
                    target.clear();
                }
            } else {
                target.push(c);
            }
        }
        _ => {}
    }
}

fn handle_choice_key(key: KeyEvent, value: &mut usize, max: usize) {
    match key.code {
        KeyCode::Left => {
            if *value == 0 {
                *value = max - 1;
            } else {
                *value -= 1;
            }
        }
        KeyCode::Right | KeyCode::Enter | KeyCode::Char(' ') => {
            *value = (*value + 1) % max;
        }
        _ => {}
    }
}

fn handle_toggle_key(key: KeyEvent, value: &mut bool) {
    match key.code {
        KeyCode::Left | KeyCode::Right | KeyCode::Enter | KeyCode::Char(' ') => {
            *value = !*value;
        }
        _ => {}
    }
}

fn suspend_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode().map_err(io_to_err)?;
    execute!(
        terminal.backend_mut(),
        Show,
        DisableMouseCapture,
        LeaveAlternateScreen
    )
    .map_err(io_to_err)?;
    Ok(())
}

fn resume_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    enable_raw_mode().map_err(io_to_err)?;
    execute!(
        terminal.backend_mut(),
        EnterAlternateScreen,
        EnableMouseCapture,
        Hide
    )
    .map_err(io_to_err)?;
    Ok(())
}

fn parse_paths_csv(value: &str) -> Vec<PathBuf> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn parse_csv_strings(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn parse_i32_default(value: &str, default: i32, name: &str) -> Result<i32> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    trimmed
        .parse::<i32>()
        .map_err(|_| NoerError::InvalidFormat(format!("invalid {name}")))
}

fn parse_usize_default(value: &str, default: usize, name: &str) -> Result<usize> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    trimmed
        .parse::<usize>()
        .map_err(|_| NoerError::InvalidFormat(format!("invalid {name}")))
}

fn opt_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn opt_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn path_required(value: &str, label: &str) -> Result<PathBuf> {
    opt_path(value).ok_or_else(|| NoerError::InvalidFormat(format!("missing {label}")))
}

fn choice_to_checksum(choice: usize) -> Option<ChecksumChoice> {
    match choice {
        1 => Some(ChecksumChoice::Sha256),
        2 => Some(ChecksumChoice::Blake3),
        _ => None,
    }
}

fn choice_to_checksum_algo(choice: usize) -> Option<ChecksumChoice> {
    choice_to_checksum(choice)
}

fn checksum_choice_label(choice: usize) -> &'static str {
    match choice {
        1 => "sha256",
        2 => "blake3",
        _ => "none",
    }
}

fn checksum_algo_label(choice: usize) -> &'static str {
    match choice {
        1 => "sha256",
        2 => "blake3",
        _ => "auto",
    }
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

fn mask(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        "*".repeat(value.chars().count())
    }
}

fn default_display(value: &str, default: &str) -> String {
    if value.trim().is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}

fn password_strength_label(password: &str) -> &'static str {
    if password.is_empty() {
        return "empty";
    }
    let score = zxcvbn(password, &[]).score();
    match score {
        Score::Zero | Score::One => "weak",
        Score::Two => "fair",
        Score::Three => "good",
        Score::Four => "strong",
        _ => "strong",
    }
}

fn io_to_err(err: io::Error) -> NoerError {
    NoerError::Io(err)
}
