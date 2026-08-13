use tower_lsp::lsp_types::{Position, Range};

#[derive(Clone, Debug)]
pub struct Document {
    pub text: String,
    pub version: i32,
}

pub fn position_to_offset(text: &str, position: Position) -> Option<usize> {
    let line_start = if position.line == 0 {
        0
    } else {
        text.match_indices('\n')
            .nth(position.line as usize - 1)
            .map(|(offset, _)| offset + 1)?
    };
    let line = text[line_start..]
        .split_once('\n')
        .map_or(&text[line_start..], |v| v.0);
    let mut utf16_units = 0_u32;
    for (byte_offset, character) in line.char_indices() {
        if utf16_units == position.character {
            return Some(line_start + byte_offset);
        }
        utf16_units += character.len_utf16() as u32;
        if utf16_units > position.character {
            return None;
        }
    }
    (utf16_units == position.character).then_some(line_start + line.len())
}

pub fn offset_to_position(text: &str, offset: usize) -> Position {
    let safe_offset = offset.min(text.len());
    let prefix = &text[..safe_offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() as u32;
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let character = text[line_start..safe_offset].encode_utf16().count() as u32;
    Position::new(line, character)
}

pub fn byte_range_to_lsp(text: &str, start: usize, end: usize) -> Range {
    Range::new(
        offset_to_position(text, start),
        offset_to_position(text, end),
    )
}

pub fn lsp_range_to_bytes(text: &str, range: Range) -> Option<(usize, usize)> {
    Some((
        position_to_offset(text, range.start)?,
        position_to_offset(text, range.end)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_utf16_positions() {
        let text = "a😀b\nvalue";
        assert_eq!(position_to_offset(text, Position::new(0, 3)), Some(5));
        assert_eq!(offset_to_position(text, 5), Position::new(0, 3));
    }
}
