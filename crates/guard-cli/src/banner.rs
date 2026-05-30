//! Bare CLI banner assets rendered with chafa 1.18.2.
//! Logo:
//! `chafa --format symbols --symbols ascii --colors none --size 64x22 docs/assets/logo.svg`.
//! Title:
//! `Screenshot 2026-05-30 at 10.10.15.png` with the dark background keyed out,
//! title-cropped, then
//! `chafa --format symbols --symbols braille --colors none --size 96x8`.

use crate::cli::Cli;
use clap::CommandFactory;
use std::io::{self, Write};

const LOGO: &str = r#"          _>==F~7^r-
         < y ly[ F
          L#JF_L__
        iykywZ_=*q`
        /`gM yZ~F==- L__   `
        ,g@@W@@F        `~   '
         $$@W@Ex ___~ <.   .
        ^`=R@^`  `_  _ ~. ` 4
       '    $ y_ARgsEwf`   /  .
         a@d$__@@@F 4 $       1
        ~r3E` _y@@r 4LE
        'l @FT_ZF@L  l$    t
         H ?a~___4'  $]  ,_/
         'L 9@@RP~   @  _='
         ,%  `       ByF'   _
         ~d  ,)      ~ , y=_u-r
            4l @   . wEa@=_yw==r
             '$~ v"y@P1*f~`
           /  Fv^yPD=~.
           7b  ,F` yr~
                 wF
                ^"#;

const TITLE: &str = r"   ⢠⡎  ⢸  ⢰                ⢰               ⠛                  ⣴⠋  ⠈⡇                       ⣿
   ⠘⢷⣄⡀  ⠒⣿⠒⠂ ⡠⠂⠐⣄ ⠠⣴⠠⠐⢶⡄ ⠒⣿⠒⠂ ⡠⠂⠐⢤⡀ ⢤⡆ ⢶⠄⠠⣶  ⣤ ⠲⣄  ⢴⡆⠔⠲⣦    ⢸⡏      ⢠⡆  ⢴⡆ ⢠⠆⠐⣦  ⢤⡆ ⢶⠄⢀⡴⠒ ⣿
     ⠉⠻⣦  ⣿  ⢸⡧⠤⠤⠿  ⣿  ⢸⡇  ⣿  ⢸⡇  ⢸⡧ ⢸⡇    ⣿  ⠁⡀ ⣿  ⢸⡇  ⣿    ⢸⡇   ⢰⡆ ⢸⡇  ⢸⠁ ⠈⡀⠠⣿  ⢸⡗   ⣿⠁  ⣿
   ⢠   ⣸  ⣿  ⠸⣧  ⢀  ⣿  ⢸⡇  ⣿  ⠸⣇  ⢸⠇ ⢸⡇    ⣿ ⢠⣏  ⣿  ⢸⡇  ⣿    ⠈⢿⡀  ⢸⡇ ⢸⣇  ⢼⠄ ⣾  ⣿  ⢸⡇   ⢿⡄  ⣿
   ⠈ ⠒⠂⠁  ⠉⠃⠁ ⠈⠙⠉⠁  ⠉  ⠈⠁  ⠉⠃⠁ ⠈⠐⠂⠁  ⠈⠉    ⠉  ⠉⠃⠁⠉  ⠈⠁  ⠉      ⠉⠐⠒⠈⠁  ⠉⠋⠁⠈⠁ ⠉⠋⠁⠈⠁ ⠈⠁    ⠉⠃⠁⠙";
const SUBTITLE: &str = "Default-deny outbound network enforcement for shell commands";

/// Print the zero-argument banner and command help.
///
/// # Errors
///
/// Returns an error if writing to stdout fails.
pub fn print_bare_invocation() -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    let columns = terminal_columns().unwrap_or_else(banner_width);

    write_centered_block(&mut stdout, LOGO, columns)?;
    writeln!(stdout)?;
    write_centered_block(&mut stdout, TITLE, columns)?;
    writeln!(stdout)?;
    write_centered_line(&mut stdout, SUBTITLE, columns)?;
    writeln!(stdout)?;

    let mut command = Cli::command()
        .about(None::<&'static str>)
        .long_about(None::<&'static str>);
    command.write_help(&mut stdout)?;
    writeln!(stdout)?;

    Ok(())
}

fn write_centered_line(mut writer: impl Write, line: &str, columns: usize) -> io::Result<()> {
    let width = line.chars().count();
    let padding = columns.saturating_sub(width) / 2;

    writeln!(writer, "{:padding$}{line}", "")
}

fn write_centered_block(mut writer: impl Write, block: &str, columns: usize) -> io::Result<()> {
    let normalized_lines = normalized_block_lines(block);
    let width = normalized_lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    let padding = columns.saturating_sub(width) / 2;

    for line in normalized_lines {
        if line.is_empty() {
            writeln!(writer)?;
            continue;
        }

        write!(writer, "{:padding$}", "")?;
        writeln!(writer, "{line}")?;
    }

    Ok(())
}

fn block_width(block: &str) -> usize {
    normalized_block_lines(block)
        .into_iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0)
}

fn normalized_block_lines(block: &str) -> Vec<&str> {
    let lines: Vec<&str> = block.lines().map(str::trim_end).collect();
    let common_indent = lines
        .iter()
        .filter(|line| !line.is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);

    lines
        .into_iter()
        .map(|line| line.get(common_indent..).unwrap_or(line))
        .collect()
}

fn banner_width() -> usize {
    block_width(LOGO)
        .max(block_width(TITLE))
        .max(SUBTITLE.chars().count())
}

fn terminal_columns() -> Option<usize> {
    stdout_terminal_columns().or_else(env_columns)
}

fn stdout_terminal_columns() -> Option<usize> {
    let mut window_size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    // SAFETY: `window_size` is a valid writable `winsize`, and `ioctl` only
    // observes stdout's terminal metadata. Failure falls back to `COLUMNS`.
    let result = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut window_size) };
    if result == 0 && window_size.ws_col > 0 {
        return Some(usize::from(window_size.ws_col));
    }

    None
}

fn env_columns() -> Option<usize> {
    std::env::var("COLUMNS")
        .ok()?
        .parse()
        .ok()
        .filter(|columns| *columns > 0)
}
