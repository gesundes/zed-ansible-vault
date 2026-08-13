use crate::document::byte_range_to_lsp;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, NumberOrString, Range, TextEdit};

pub const DIAGNOSTIC_SOURCE: &str = "ansible-vault";
pub const INVALID_MARKER_CODE: &str = "ansible-vault.invalid-marker";

const VAULT_MARKER: &str = "$ANSIBLE_VAULT";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationIssue {
    pub diagnostic: Diagnostic,
    pub fix: Option<TextEdit>,
}

#[derive(Clone, Copy)]
struct Line<'a> {
    start: usize,
    content: &'a str,
}

impl Line<'_> {
    fn indent(self) -> usize {
        self.content
            .as_bytes()
            .iter()
            .take_while(|byte| **byte == b' ')
            .count()
    }
}

pub fn validate_vault_document(text: &str) -> Vec<ValidationIssue> {
    let lines = lines(text);
    if lines.is_empty() {
        return Vec::new();
    }

    if full_file_candidate(lines[0].content) {
        return validate_full_file(text, &lines);
    }

    validate_inline_blocks(text, &lines)
}

pub fn is_vault_file_candidate(text: &str) -> bool {
    lines(text)
        .first()
        .is_some_and(|line| full_file_candidate(line.content))
}

fn validate_full_file(text: &str, lines: &[Line<'_>]) -> Vec<ValidationIssue> {
    let header = trimmed_line(lines[0]);
    let payload: Vec<_> = lines
        .iter()
        .skip(1)
        .copied()
        .filter(|line| !line.content.trim().is_empty())
        .map(trimmed_line)
        .collect();
    validate_block(text, header, &payload)
}

fn validate_inline_blocks(text: &str, lines: &[Line<'_>]) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if vault_tag_column(line.content).is_none() {
            index += 1;
            continue;
        }

        let tag_indent = line.indent();
        let mut next = index + 1;
        while next < lines.len() && lines[next].content.trim().is_empty() {
            next += 1;
        }

        if next >= lines.len() || lines[next].indent() <= tag_indent {
            let tag = vault_tag_column(line.content).expect("vault tag column");
            issues.push(issue(
                text,
                line.start + tag,
                line.start + line.content.len(),
                "ansible-vault.missing-header",
                "The !vault value has no Ansible Vault header",
                None,
            ));
            index += 1;
            continue;
        }

        let payload_indent = lines[next].indent();
        let header = trimmed_line(lines[next]);
        next += 1;
        let mut payload = Vec::new();
        while next < lines.len() {
            let candidate = lines[next];
            if candidate.content.trim().is_empty() || candidate.indent() < payload_indent {
                break;
            }
            payload.push(trimmed_line(candidate));
            next += 1;
        }
        issues.extend(validate_block(text, header, &payload));
        index = next.max(index + 1);
    }
    issues
}

fn validate_block(
    text: &str,
    header: (&str, usize, usize),
    payload: &[(&str, usize, usize)],
) -> Vec<ValidationIssue> {
    let (header_text, header_start, header_end) = header;
    let mut issues = Vec::new();
    let fields = fields(header_text);
    let marker = fields.first().map_or("", |field| field.0);
    let header_fix = canonical_header(header_text)
        .filter(|canonical| canonical != header_text)
        .map(|canonical| (header_start, header_end, canonical));

    if marker != VAULT_MARKER {
        let marker_end = header_start + marker.len().max(1).min(header_text.len());
        issues.push(issue(
            text,
            header_start,
            marker_end,
            INVALID_MARKER_CODE,
            "Invalid Ansible Vault marker; expected $ANSIBLE_VAULT",
            header_fix.clone(),
        ));
    }

    let version = fields.get(1).map(|field| field.0);
    match version {
        Some("1.1" | "1.2") => {}
        Some(_) => {
            let (_, start, end) = fields[1];
            issues.push(issue(
                text,
                header_start + start,
                header_start + end,
                "ansible-vault.unsupported-version",
                "Unsupported Ansible Vault version; expected 1.1 or 1.2",
                header_fix.clone(),
            ));
        }
        None => issues.push(issue(
            text,
            header_start,
            header_end,
            "ansible-vault.invalid-header",
            "Invalid Ansible Vault header; the version is missing",
            header_fix.clone(),
        )),
    }

    match fields.get(2) {
        Some(("AES256", _, _)) => {}
        Some((_, start, end)) => issues.push(issue(
            text,
            header_start + start,
            header_start + end,
            "ansible-vault.unsupported-cipher",
            "Unsupported Ansible Vault cipher; expected AES256",
            header_fix.clone(),
        )),
        None => issues.push(issue(
            text,
            header_start,
            header_end,
            "ansible-vault.invalid-header",
            "Invalid Ansible Vault header; the cipher is missing",
            header_fix.clone(),
        )),
    }

    match version {
        Some("1.1") if fields.len() != 3 => issues.push(issue(
            text,
            header_start,
            header_end,
            "ansible-vault.invalid-header",
            "Vault 1.1 headers must contain exactly marker, version, and cipher",
            header_fix.clone(),
        )),
        Some("1.2") if fields.len() != 4 || fields[3].0.is_empty() => issues.push(issue(
            text,
            header_start,
            header_end,
            "ansible-vault.missing-vault-id",
            "Vault 1.2 headers require a non-empty Vault ID",
            header_fix,
        )),
        _ => {}
    }

    if payload.is_empty() {
        issues.push(issue(
            text,
            header_start,
            header_end,
            "ansible-vault.empty-payload",
            "The Ansible Vault payload is empty",
            None,
        ));
    } else {
        for (line, start, end) in payload {
            if line.is_empty()
                || line.len() % 2 != 0
                || !line.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                issues.push(issue(
                    text,
                    *start,
                    *end,
                    "ansible-vault.invalid-payload",
                    "Ansible Vault payload lines must contain an even number of hexadecimal characters",
                    None,
                ));
            }
        }
    }

    issues
}

fn issue(
    text: &str,
    start: usize,
    end: usize,
    code: &str,
    message: &str,
    fix: Option<(usize, usize, String)>,
) -> ValidationIssue {
    ValidationIssue {
        diagnostic: Diagnostic::new(
            byte_range_to_lsp(text, start, end.max(start + 1).min(text.len())),
            Some(DiagnosticSeverity::ERROR),
            Some(NumberOrString::String(code.to_string())),
            Some(DIAGNOSTIC_SOURCE.to_string()),
            message.to_string(),
            None,
            None,
        ),
        fix: fix.map(|(fix_start, fix_end, replacement)| TextEdit {
            range: byte_range_to_lsp(text, fix_start, fix_end),
            new_text: replacement,
        }),
    }
}

fn lines(text: &str) -> Vec<Line<'_>> {
    let mut offset = 0;
    text.split_inclusive('\n')
        .map(|line| {
            let content = line.trim_end_matches(['\r', '\n']);
            let result = Line {
                start: offset,
                content,
            };
            offset += line.len();
            result
        })
        .collect()
}

fn trimmed_line(line: Line<'_>) -> (&str, usize, usize) {
    let leading = line.content.len() - line.content.trim_start().len();
    let trimmed = line.content.trim();
    let start = line.start + leading;
    (trimmed, start, start + trimmed.len())
}

fn fields(header: &str) -> Vec<(&str, usize, usize)> {
    let mut starts = vec![0];
    starts.extend(header.match_indices(';').map(|(index, _)| index + 1));
    starts
        .iter()
        .enumerate()
        .map(|(index, start)| {
            let end = starts.get(index + 1).map_or(header.len(), |next| next - 1);
            (&header[*start..end], *start, end)
        })
        .collect()
}

fn full_file_candidate(line: &str) -> bool {
    let header = line.trim();
    let marker = repair_fields(header).first().copied().unwrap_or_default();
    marker == VAULT_MARKER
        || safely_fixable_marker(marker)
        || ((marker.starts_with('$') || resembles_marker(marker))
            && canonical_header(header).is_some())
}

fn safely_fixable_marker(marker: &str) -> bool {
    marker.eq_ignore_ascii_case(VAULT_MARKER)
        || one_edit_apart(marker.as_bytes(), VAULT_MARKER.as_bytes())
}

pub(crate) fn canonical_header(header: &str) -> Option<String> {
    let fields = repair_fields(header);
    if !matches!(fields.len(), 3 | 4) {
        return None;
    }

    let marker_confident = resembles_marker(fields[0]);
    let version = version_hint(fields[1]);
    let version_confident = version.is_some();
    let cipher_confident = resembles_cipher(fields[2]);
    if [marker_confident, version_confident, cipher_confident]
        .into_iter()
        .filter(|confident| *confident)
        .count()
        < 2
    {
        return None;
    }

    if fields.len() == 4 {
        let vault_id = fields[3].trim();
        if vault_id.is_empty() {
            return None;
        }
        return Some(format!("{VAULT_MARKER};1.2;AES256;{vault_id}"));
    }

    if version == Some(VaultVersion::V12) {
        return None;
    }
    Some(format!("{VAULT_MARKER};1.1;AES256"))
}

fn repair_fields(header: &str) -> Vec<&str> {
    let header = header.trim();
    let semicolons = header.bytes().filter(|byte| *byte == b';').count();
    let fields: Vec<&str> = if semicolons >= 2 {
        let mut fields: Vec<&str> = header.split(';').collect();
        if fields.len() == 3 {
            if let Some((cipher, vault_id)) = fields[2].split_once([':', '|']) {
                if resembles_cipher(cipher) && !vault_id.trim().is_empty() {
                    fields[2] = cipher;
                    fields.push(vault_id);
                }
            }
        }
        fields
    } else if header
        .bytes()
        .any(|byte| matches!(byte, b';' | b':' | b'|'))
    {
        header.split([';', ':', '|']).collect()
    } else {
        header.split_whitespace().collect()
    };
    fields.into_iter().map(str::trim).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VaultVersion {
    V11,
    V12,
}

fn version_hint(value: &str) -> Option<VaultVersion> {
    let digits: String = value
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect();
    match digits.as_str() {
        "11" => Some(VaultVersion::V11),
        "12" => Some(VaultVersion::V12),
        _ => None,
    }
}

fn resembles_marker(value: &str) -> bool {
    let compact = compact_token(value);
    edit_distance_at_most(&compact, "ANSIBLEVAULT", 2)
}

fn resembles_cipher(value: &str) -> bool {
    let compact = compact_token(value);
    edit_distance_at_most(&compact, "AES256", 2)
}

fn compact_token(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect()
}

fn edit_distance_at_most(actual: &str, expected: &str, maximum: usize) -> bool {
    if actual.len().abs_diff(expected.len()) > maximum {
        return false;
    }
    let mut previous: Vec<usize> = (0..=expected.len()).collect();
    for (row, actual_byte) in actual.bytes().enumerate() {
        let mut current = Vec::with_capacity(expected.len() + 1);
        current.push(row + 1);
        for (column, expected_byte) in expected.bytes().enumerate() {
            let substitution = previous[column] + usize::from(actual_byte != expected_byte);
            let insertion = current[column] + 1;
            let deletion = previous[column + 1] + 1;
            current.push(substitution.min(insertion).min(deletion));
        }
        if current.iter().copied().min().unwrap_or(maximum + 1) > maximum {
            return false;
        }
        previous = current;
    }
    previous[expected.len()] <= maximum
}

fn one_edit_apart(actual: &[u8], expected: &[u8]) -> bool {
    if actual == expected {
        return false;
    }
    if actual.len() == expected.len() {
        return actual
            .iter()
            .zip(expected)
            .filter(|(left, right)| left != right)
            .count()
            == 1;
    }
    let (shorter, longer) = if actual.len() + 1 == expected.len() {
        (actual, expected)
    } else if expected.len() + 1 == actual.len() {
        (expected, actual)
    } else {
        return false;
    };
    let mut short = 0;
    let mut long = 0;
    let mut skipped = false;
    while short < shorter.len() && long < longer.len() {
        if shorter[short] == longer[long] {
            short += 1;
            long += 1;
        } else if skipped {
            return false;
        } else {
            skipped = true;
            long += 1;
        }
    }
    true
}

fn vault_tag_column(line: &str) -> Option<usize> {
    if line.trim_start().starts_with('#') {
        return None;
    }
    let marker = line.find("!vault")?;
    let structural_prefix = line[..marker].trim_end();
    if !structural_prefix.is_empty()
        && !structural_prefix.ends_with(':')
        && !structural_prefix.ends_with('-')
    {
        return None;
    }
    line[marker + "!vault".len()..]
        .trim_start()
        .starts_with('|')
        .then_some(marker)
}

pub fn range_touches(selection: Range, diagnostic: Range) -> bool {
    if selection.start == selection.end {
        selection.start >= diagnostic.start && selection.start <= diagnostic.end
    } else {
        selection.start < diagnostic.end && selection.end > diagnostic.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(text: &str) -> Vec<String> {
        validate_vault_document(text)
            .into_iter()
            .filter_map(|issue| match issue.diagnostic.code {
                Some(NumberOrString::String(code)) => Some(code),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn accepts_valid_full_and_inline_vaults() {
        assert!(validate_vault_document("$ANSIBLE_VAULT;1.1;AES256\n616263\n646566\n").is_empty());
        assert!(validate_vault_document(concat!(
            "secret: !vault |\n",
            "  $ANSIBLE_VAULT;1.2;AES256;dev\n",
            "  616263\n",
            "next: value\n"
        ))
        .is_empty());
    }

    #[test]
    fn reports_and_fixes_a_single_character_marker_typo() {
        let text = concat!(
            "secret: !vault |\n",
            "  $sANSIBLE_VAULT;1.1;AES256\n",
            "  616263\n"
        );
        let issues = validate_vault_document(text);
        assert_eq!(codes(text), vec![INVALID_MARKER_CODE]);
        let fix = issues[0].fix.as_ref().expect("safe marker fix");
        assert_eq!(fix.new_text, "$ANSIBLE_VAULT;1.1;AES256");
        assert_eq!(fix.range.start.line, 1);
        assert_eq!(fix.range.start.character, 2);
        assert_eq!(fix.range.end.character, 28);
    }

    #[test]
    fn normalizes_confident_header_errors_in_any_field() {
        for malformed in [
            "$sANSIBLE_VAULT;1.1;AES256",
            "$ANSIBLE_VAULT:1.1:AES256",
            "$ANSIBLE_VAULT;1,1;AES-256",
            "$ansible_vault;1.1;aes256",
            "$ANSIBLE_VAULT;9.9;AES256",
            "$ANSIBLE_VAULT;1.1;BROKEN",
            "BROKEN;1.1;AES256",
        ] {
            assert_eq!(
                canonical_header(malformed).as_deref(),
                Some("$ANSIBLE_VAULT;1.1;AES256"),
                "failed to normalize {malformed}"
            );
        }
    }

    #[test]
    fn preserves_a_vault_1_2_id_while_normalizing_the_header() {
        assert_eq!(
            canonical_header("$ANSIBLE_VAULT;1,2;ASE-256;production").as_deref(),
            Some("$ANSIBLE_VAULT;1.2;AES256;production")
        );
        assert_eq!(
            canonical_header("$ANSIBLE_VAULT;1.2;AES-256:production").as_deref(),
            Some("$ANSIBLE_VAULT;1.2;AES256;production")
        );
    }

    #[test]
    fn refuses_to_invent_a_missing_vault_id_or_repair_unrelated_text() {
        assert_eq!(canonical_header("$ANSIBLE_VAULT;1.2;AES256"), None);
        assert_eq!(canonical_header("completely unrelated text"), None);
        assert_eq!(canonical_header("BROKEN;BROKEN;BROKEN"), None);
    }

    #[test]
    fn reports_unsupported_header_fields_and_invalid_payload() {
        let codes = codes("$ANSIBLE_VAULT;9.9;BROKEN\nxyz\n");
        assert!(codes.contains(&"ansible-vault.unsupported-version".to_string()));
        assert!(codes.contains(&"ansible-vault.unsupported-cipher".to_string()));
        assert!(codes.contains(&"ansible-vault.invalid-payload".to_string()));
    }

    #[test]
    fn reports_missing_id_and_payload() {
        assert_eq!(
            codes("$ANSIBLE_VAULT;1.2;AES256\n"),
            vec![
                "ansible-vault.missing-vault-id",
                "ansible-vault.empty-payload"
            ]
        );
    }

    #[test]
    fn validates_each_nested_block_without_consuming_sibling_fields() {
        let text = concat!(
            "users:\n",
            "  - name: !vault |\n",
            "          $sANSIBLE_VAULT;1.1;AES256\n",
            "          616263\n",
            "    password: !vault |\n",
            "              $ANSIBLE_VAULT;1.1;AES256\n",
            "              not-hex\n",
            "    uid: 1001\n"
        );
        assert_eq!(
            codes(text),
            vec![INVALID_MARKER_CODE, "ansible-vault.invalid-payload"]
        );
    }

    #[test]
    fn ignores_vault_examples_inside_yaml_comments() {
        assert!(validate_vault_document(concat!(
            "# secret: !vault |\n",
            "#   $sANSIBLE_VAULT;1.1;AES256\n",
            "#   not-hex\n"
        ))
        .is_empty());
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_utf8_never_panics_during_vault_validation(text in proptest::prelude::any::<String>()) {
            let _ = validate_vault_document(&text);
            if let Some(first_line) = text.lines().next() {
                let _ = canonical_header(first_line);
            }
        }
    }
}
