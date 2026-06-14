//! Icon rasteriser — programmatic RGBA circle dots.
//!
//! Implements `specs/wp10-tray.md` §1 "build four state dots programmatically".
//!
//! No binary assets are embedded.  Each icon is a small RGBA image with a
//! filled circle rasterised in pure Rust (no external image crate needed).
//! `tray_icon::Icon::from_rgba` accepts `Vec<u8>` + dimensions directly.

#[cfg(any(target_os = "macos", target_os = "windows"))]
use thiserror::Error;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use tray_icon::Icon;

use crate::state::DotState;

/// Errors from icon construction.
///
/// Only on macOS/Windows — the tray UI deps are target-scoped (Linux tray is
/// deferred: the Linux audience is headless-first, and tray-icon's Linux
/// dependency chain pulls MPL-2.0 `option-ext`, which the license policy bans).
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug, Error)]
pub enum IconError {
    /// `tray_icon` rejected the RGBA buffer (size mismatch).
    #[error("failed to create tray icon from RGBA buffer: {0}")]
    BadIcon(#[from] tray_icon::BadIcon),
}

/// Icon side length in pixels.
///
/// 22 × 22 is the canonical macOS menu-bar icon size.
pub const ICON_SIZE: u32 = 22;

/// RGBA colour for each dot state (R, G, B, A).
///
/// macOS dark/light mode: the menu bar adapts automatically when the icon
/// has a transparent background.  We use solid coloured dots on a transparent
/// field — the OS renders them correctly in both modes.
const GREEN: [u8; 4] = [0x34, 0xC7, 0x59, 0xFF]; // system green
const AMBER: [u8; 4] = [0xFF, 0xC0, 0x00, 0xFF]; // system amber / yellow
const GREY: [u8; 4] = [0x8E, 0x8E, 0x93, 0xFF]; // system grey
const RED: [u8; 4] = [0xFF, 0x3B, 0x30, 0xFF]; // system red

/// Pick the RGBA colour tuple for a [`DotState`].
pub fn colour_for(state: DotState) -> [u8; 4] {
    match state {
        DotState::Filtering => GREEN,
        DotState::Snoozed => AMBER,
        DotState::StandingBy => GREY,
        DotState::Attention => RED,
    }
}

/// Rasterise a filled circle into an RGBA buffer.
///
/// - `size` × `size` pixels, RGBA format.
/// - Circle radius is `size / 2 - 1` (1-px transparent margin).
/// - Pixels outside the circle are fully transparent (0, 0, 0, 0).
/// - Anti-aliasing is intentionally omitted — small icons at retina scale
///   look fine without it and this keeps the code dependency-free.
///
/// # Invariants
///
/// `size` must be at least 3 (margin + centre pixel).  At the ICON_SIZE of 22
/// this is always satisfied.
pub fn rasterise_circle(size: u32, colour: [u8; 4]) -> Vec<u8> {
    let mut buf = vec![0u8; (size * size * 4) as usize];
    let centre = (size as f32 - 1.0) / 2.0;
    // Radius shrunk by 1 px to leave a transparent border.
    let radius = centre - 1.0;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - centre;
            let dy = y as f32 - centre;
            if dx * dx + dy * dy <= radius * radius {
                let base = ((y * size + x) * 4) as usize;
                buf[base] = colour[0];
                buf[base + 1] = colour[1];
                buf[base + 2] = colour[2];
                buf[base + 3] = colour[3];
            }
            // else: remains 0,0,0,0 — transparent
        }
    }
    buf
}

/// Build a `tray_icon::Icon` for the given [`DotState`].
///
/// Called once per state change; the resulting `Icon` is handed to
/// `TrayIcon::set_icon`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn icon_for_state(state: DotState) -> Result<Icon, IconError> {
    let colour = colour_for(state);
    let buf = rasterise_circle(ICON_SIZE, colour);
    let icon = Icon::from_rgba(buf, ICON_SIZE, ICON_SIZE)?;
    Ok(icon)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // ── Buffer dimensions ────────────────────────────────────────────────────

    #[test]
    fn buffer_has_correct_byte_length() {
        let buf = rasterise_circle(ICON_SIZE, GREEN);
        assert_eq!(buf.len() as u32, ICON_SIZE * ICON_SIZE * 4);
    }

    #[test]
    fn buffer_len_is_divisible_by_4() {
        let buf = rasterise_circle(ICON_SIZE, AMBER);
        assert_eq!(buf.len() % 4, 0);
    }

    // ── Centre pixel is coloured ─────────────────────────────────────────────

    #[test]
    fn centre_pixel_is_coloured_green() {
        let buf = rasterise_circle(ICON_SIZE, GREEN);
        let cx = (ICON_SIZE / 2) as usize;
        let cy = (ICON_SIZE / 2) as usize;
        let base = (cy * ICON_SIZE as usize + cx) * 4;
        // Alpha must be 0xFF (opaque).
        assert_eq!(buf[base + 3], 0xFF, "centre pixel must be opaque");
        // Red channel must match GREEN.
        assert_eq!(buf[base], GREEN[0]);
    }

    #[test]
    fn centre_pixel_is_coloured_red() {
        let buf = rasterise_circle(ICON_SIZE, RED);
        let cx = (ICON_SIZE / 2) as usize;
        let cy = (ICON_SIZE / 2) as usize;
        let base = (cy * ICON_SIZE as usize + cx) * 4;
        assert_eq!(buf[base + 3], 0xFF);
        assert_eq!(buf[base], RED[0]);
    }

    // ── Corner pixels are transparent ────────────────────────────────────────

    #[test]
    fn corner_pixels_are_transparent() {
        let buf = rasterise_circle(ICON_SIZE, GREEN);
        let corners = [
            (0usize, 0usize),
            (0, (ICON_SIZE - 1) as usize),
            ((ICON_SIZE - 1) as usize, 0),
            ((ICON_SIZE - 1) as usize, (ICON_SIZE - 1) as usize),
        ];
        for (x, y) in corners {
            let base = (y * ICON_SIZE as usize + x) * 4;
            assert_eq!(
                buf[base + 3],
                0,
                "corner ({x},{y}) must be transparent (alpha=0)"
            );
        }
    }

    // ── All four dot states produce correct dimensions ───────────────────────

    #[test]
    fn all_states_produce_correct_buffer() {
        for state in [
            DotState::Filtering,
            DotState::Snoozed,
            DotState::StandingBy,
            DotState::Attention,
        ] {
            let colour = colour_for(state);
            let buf = rasterise_circle(ICON_SIZE, colour);
            assert_eq!(
                buf.len() as u32,
                ICON_SIZE * ICON_SIZE * 4,
                "wrong buffer length for {state:?}"
            );
            // Centre must be opaque.
            let cx = (ICON_SIZE / 2) as usize;
            let cy = (ICON_SIZE / 2) as usize;
            let base = (cy * ICON_SIZE as usize + cx) * 4;
            assert_eq!(buf[base + 3], 0xFF, "centre not opaque for {state:?}");
        }
    }

    // ── Non-standard sizes ────────────────────────────────────────────────────

    #[test]
    fn small_icon_size_produces_valid_buffer() {
        let buf = rasterise_circle(10, GREY);
        assert_eq!(buf.len(), 10 * 10 * 4);
        // Centre should be coloured.
        let base = (5 * 10 + 5) * 4;
        assert_eq!(buf[base + 3], 0xFF);
    }

    // ── icon_for_state succeeds for all dot states ───────────────────────────
    //
    // tray_icon::Icon::from_rgba validates the buffer; if this passes we know
    // our rasteriser emits geometrically valid RGBA data.

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn icon_for_state_succeeds_for_all_states() {
        for state in [
            DotState::Filtering,
            DotState::Snoozed,
            DotState::StandingBy,
            DotState::Attention,
        ] {
            let result = icon_for_state(state);
            assert!(
                result.is_ok(),
                "icon_for_state({state:?}) must succeed; got: {:?}",
                result.err()
            );
        }
    }
}
