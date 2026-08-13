use crate::document::lsp_range_to_bytes;
use crate::error::{AppError, AppResult};
use tower_lsp::lsp_types::Range;
use tree_sitter::{Node, Parser};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalarTarget {
    pub start: usize,
    pub end: usize,
    pub plaintext: String,
    pub continuation_indent: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultTarget {
    pub start: usize,
    pub end: usize,
    pub vault_text: String,
    pub continuation_indent: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueContext {
    Plaintext,
    Vault,
}

pub fn classify_value(text: &str, range: Range) -> Option<ValueContext> {
    if find_vault(text, range).is_ok() {
        Some(ValueContext::Vault)
    } else if find_scalar(text, range).is_ok() {
        Some(ValueContext::Plaintext)
    } else {
        None
    }
}

pub fn find_scalar(text: &str, range: Range) -> AppResult<ScalarTarget> {
    let (selection_start, selection_end) = lsp_range_to_bytes(text, range)
        .ok_or_else(|| AppError::user("The selection is outside the current document"))?;
    let tree = parse(text)?;
    if tree.root_node().has_error() {
        return Err(AppError::user(
            "Fix YAML syntax errors before encrypting a scalar value",
        ));
    }
    let node = if selection_start != selection_end {
        scalar_at_range(tree.root_node(), text, selection_start, selection_end).ok_or_else(
            || AppError::user("The selection must contain exactly one YAML scalar value"),
        )?
    } else {
        scalar_at_range(tree.root_node(), text, selection_start, selection_end)
            .filter(|node| !is_mapping_key(*node))
            .or_else(|| {
                mapping_value_for_cursor(
                    tree.root_node(),
                    selection_start,
                    range.start.line as usize,
                )
            })
            .ok_or_else(|| {
                AppError::user("Place the cursor on a YAML key or inside its scalar value")
            })?
    };
    if is_mapping_key(node) {
        return Err(AppError::user(
            "Ansible Vault can encrypt YAML values, not mapping keys",
        ));
    }
    if has_flow_collection_ancestor(node) {
        return Err(AppError::user(
            "Block-style !vault values cannot be inserted into a flow-style YAML collection",
        ));
    }

    if selection_start != selection_end {
        let selected = &text[selection_start..selection_end];
        let left_trim = selected.len() - selected.trim_start().len();
        let right_trimmed = selected.trim_end().len();
        if selection_start + left_trim != node.start_byte()
            || selection_start + right_trimmed != node.end_byte()
        {
            return Err(AppError::user(
                "The selection must contain exactly one YAML scalar value",
            ));
        }
    }

    let raw = &text[node.byte_range()];
    let plaintext = decode_scalar(node.kind(), raw)?;
    Ok(ScalarTarget {
        start: node.start_byte(),
        end: node.end_byte(),
        plaintext,
        continuation_indent: child_indent(text, node.start_byte()),
    })
}

pub fn find_vault(text: &str, range: Range) -> AppResult<VaultTarget> {
    // Refuse malformed YAML before doing the line-oriented extraction. Tree-sitter is
    // deliberately used as the syntax gate; line scanning then preserves exact byte offsets.
    let tree = parse(text)?;
    if tree.root_node().has_error() {
        return Err(AppError::user(
            "Fix YAML syntax errors before decrypting a !vault value",
        ));
    }
    let (selection_start, selection_end) = lsp_range_to_bytes(text, range)
        .ok_or_else(|| AppError::user("The selection is outside the current document"))?;
    let mut matches = Vec::new();
    let mut offset = 0_usize;
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut index = 0_usize;
    while index < lines.len() {
        let line = lines[index];
        if let Some(tag_column) = vault_tag_column(line) {
            let line_indent = leading_width(line);
            let context_start = offset;
            let start = offset + tag_column;
            let mut end = offset + line.trim_end_matches(['\r', '\n']).len();
            let mut payload = Vec::new();
            let mut payload_indent = None;
            let mut next_offset = offset + line.len();
            let mut next = index + 1;
            while next < lines.len() {
                let candidate = lines[next];
                let content = candidate.trim_end_matches(['\r', '\n']);
                if content.trim().is_empty() {
                    break;
                }
                let indentation = leading_width(candidate);
                let required_indent = match payload_indent {
                    Some(required_indent) => required_indent,
                    None if indentation > line_indent => {
                        payload_indent = Some(indentation);
                        indentation
                    }
                    None => break,
                };
                if indentation < required_indent {
                    break;
                }
                payload.push(content[required_indent..].to_string());
                end = next_offset + content.len();
                next_offset += candidate.len();
                next += 1;
            }
            let overlaps = if selection_start == selection_end {
                selection_start >= context_start && selection_start <= end
            } else {
                selection_start < end && selection_end > context_start
            };
            if overlaps {
                matches.push(VaultTarget {
                    start,
                    end,
                    vault_text: format!("{}\n", payload.join("\n")),
                    continuation_indent: " ".repeat(payload_indent.unwrap_or(line_indent + 2)),
                });
            }
            index = next;
            offset = next_offset;
            continue;
        }
        offset += line.len();
        index += 1;
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(AppError::user(
            "Place the cursor inside exactly one !vault block",
        )),
        _ => Err(AppError::user(
            "The selection intersects more than one !vault block",
        )),
    }
}

pub fn format_encrypted_value(vault_text: &str, indent: &str) -> AppResult<String> {
    let lines: Vec<&str> = vault_text.trim_end_matches(['\r', '\n']).lines().collect();
    if !lines
        .first()
        .is_some_and(|line| line.starts_with("$ANSIBLE_VAULT;"))
    {
        return Err(AppError::user(
            "ansible-vault returned an invalid encrypted value",
        ));
    }
    Ok(format!(
        "!vault |\n{indent}{}",
        lines.join(&format!("\n{indent}"))
    ))
}

pub fn format_plaintext_value(plaintext: &str, indent: &str) -> String {
    let without_final_newline = plaintext.strip_suffix('\n').unwrap_or(plaintext);
    let without_final_newline = without_final_newline
        .strip_suffix('\r')
        .unwrap_or(without_final_newline);
    if !without_final_newline.contains('\n') {
        return yaml_safe_scalar(without_final_newline);
    }
    let has_final_newline = plaintext.ends_with('\n');
    let body = plaintext.strip_suffix('\n').unwrap_or(plaintext);
    let marker = if has_final_newline { "|" } else { "|-" };
    format!(
        "{marker}\n{indent}{}",
        body.split('\n')
            .collect::<Vec<_>>()
            .join(&format!("\n{indent}"))
    )
}

fn parse(text: &str) -> AppResult<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error)))?;
    parser
        .parse(text, None)
        .ok_or_else(|| AppError::user("Unable to parse the YAML document"))
}

fn is_scalar(kind: &str) -> bool {
    matches!(
        kind,
        "plain_scalar" | "single_quote_scalar" | "double_quote_scalar" | "block_scalar"
    )
}

fn scalar_at_range<'tree>(
    root: Node<'tree>,
    text: &str,
    selection_start: usize,
    selection_end: usize,
) -> Option<Node<'tree>> {
    if text.is_empty() {
        return None;
    }
    let probe_start = selection_start.min(text.len().saturating_sub(1));
    let probe_end = selection_end
        .max(probe_start.saturating_add(1))
        .min(text.len());
    let mut node = root.descendant_for_byte_range(probe_start, probe_end)?;
    loop {
        if is_scalar(node.kind()) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn mapping_value_for_cursor<'tree>(
    root: Node<'tree>,
    cursor: usize,
    cursor_line: usize,
) -> Option<Node<'tree>> {
    let mut candidates = Vec::new();
    collect_mapping_value_candidates(root, cursor, cursor_line, &mut candidates);
    candidates
        .into_iter()
        .min_by_key(|(pair_width, _)| *pair_width)
        .map(|(_, scalar)| scalar)
}

fn collect_mapping_value_candidates<'tree>(
    node: Node<'tree>,
    cursor_byte: usize,
    cursor_line: usize,
    candidates: &mut Vec<(usize, Node<'tree>)>,
) {
    if node.kind() == "block_mapping_pair"
        && (node.start_position().row == cursor_line
            || (cursor_byte >= node.start_byte() && cursor_byte <= node.end_byte()))
    {
        if let Some(value) = node
            .child_by_field_name("value")
            .and_then(single_scalar_value)
        {
            candidates.push((node.end_byte() - node.start_byte(), value));
        }
    }

    let mut tree_cursor = node.walk();
    for child in node.named_children(&mut tree_cursor) {
        collect_mapping_value_candidates(child, cursor_byte, cursor_line, candidates);
    }
}

fn single_scalar_value(node: Node<'_>) -> Option<Node<'_>> {
    if is_scalar(node.kind()) {
        return Some(node);
    }
    if matches!(
        node.kind(),
        "block_mapping"
            | "block_sequence"
            | "flow_mapping"
            | "flow_sequence"
            | "block_mapping_pair"
            | "flow_pair"
            | "block_sequence_item"
    ) {
        return None;
    }

    let mut found = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(scalar) = single_scalar_value(child) {
            if found.is_some() {
                return None;
            }
            found = Some(scalar);
        }
    }
    found
}

fn is_mapping_key(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "block_mapping_pair" | "flow_pair") {
            return parent.named_child(0).is_some_and(|key| {
                node.start_byte() >= key.start_byte() && node.end_byte() <= key.end_byte()
            });
        }
        node = parent;
    }
    false
}

fn has_flow_collection_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "flow_sequence" | "flow_mapping") {
            return true;
        }
        node = parent;
    }
    false
}

fn decode_scalar(kind: &str, raw: &str) -> AppResult<String> {
    if kind == "plain_scalar" {
        return Ok(raw.to_string());
    }
    serde_saphyr::from_str::<String>(raw)
        .map_err(|_| AppError::user("The selected YAML scalar is not a string value"))
}

fn child_indent(text: &str, offset: usize) -> String {
    let line_start = text[..offset].rfind('\n').map_or(0, |index| index + 1);
    let line_indent = leading_width(&text[line_start..]);
    let value_column = offset - line_start;
    " ".repeat(value_column.max(line_indent + 2))
}

fn leading_width(line: &str) -> usize {
    line.as_bytes()
        .iter()
        .take_while(|byte| **byte == b' ')
        .count()
}

fn vault_tag_column(line: &str) -> Option<usize> {
    let marker = line.find("!vault")?;
    let structural_prefix = line[..marker].trim_end();
    if !structural_prefix.is_empty()
        && !structural_prefix.ends_with(':')
        && !structural_prefix.ends_with('-')
    {
        return None;
    }
    let suffix = line[marker + "!vault".len()..].trim_start();
    (suffix.starts_with('|')).then_some(marker)
}

fn yaml_safe_scalar(value: &str) -> String {
    let safe_chars = !value.is_empty()
        && value.trim() == value
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_./@+-".contains(character));
    let lower = value.to_ascii_lowercase();
    let reserved = matches!(
        lower.as_str(),
        "null" | "~" | "true" | "false" | "yes" | "no" | "on" | "off"
    ) || value.parse::<f64>().is_ok();
    if safe_chars && !reserved && !value.starts_with('-') && !value.starts_with('?') {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::Position;

    #[test]
    fn finds_only_mapping_value() {
        let text = "secret: \"hello world\"\n";
        let target = find_scalar(text, Range::new(Position::new(0, 11), Position::new(0, 11)))
            .expect("value target");
        assert_eq!(target.plaintext, "hello world");
        assert_eq!(&text[target.start..target.end], "\"hello world\"");
        assert_eq!(
            find_scalar(text, Range::new(Position::new(0, 2), Position::new(0, 2)))
                .expect("value target from key")
                .plaintext,
            "hello world"
        );
        assert!(find_scalar(text, Range::new(Position::new(0, 0), Position::new(0, 6))).is_err());
        assert!(find_scalar(text, Range::new(Position::new(0, 8), Position::new(0, 21))).is_ok());
        assert!(find_scalar(text, Range::new(Position::new(0, 9), Position::new(0, 20))).is_err());
    }

    #[test]
    fn finds_mapping_value_from_any_position_on_the_key_line() {
        let text = "  secret: value # explanation\n";
        for character in [0, 4, 8, 11, 27] {
            let target = find_scalar(
                text,
                Range::new(Position::new(0, character), Position::new(0, character)),
            )
            .expect("value target from key line");
            assert_eq!(target.plaintext, "value");
            assert_eq!(&text[target.start..target.end], "value");
        }
    }

    #[test]
    fn aligns_encrypted_blocks_with_values_in_sequence_mappings() {
        let text = concat!(
            "ssh_users:\n",
            "  - name: devops\n",
            "    password: secret\n"
        );
        let name = find_scalar(text, Range::new(Position::new(1, 4), Position::new(1, 4)))
            .expect("name value");
        let password = find_scalar(text, Range::new(Position::new(2, 6), Position::new(2, 6)))
            .expect("password value");

        assert_eq!(name.continuation_indent, "          ");
        assert_eq!(password.continuation_indent, "              ");
    }

    #[test]
    fn finds_multiline_scalar_from_key_and_body_lines() {
        let text = "secret: |-\n  first line\n  second line\nnext: value\n";
        for (line, character) in [(0, 1), (0, 9), (1, 4), (2, 8)] {
            let target = find_scalar(
                text,
                Range::new(
                    Position::new(line, character),
                    Position::new(line, character),
                ),
            )
            .expect("multiline value target");
            assert_eq!(target.plaintext, "first line\nsecond line");
            assert_eq!(
                &text[target.start..target.end],
                "|-\n  first line\n  second line"
            );
        }
    }

    #[test]
    fn does_not_treat_collection_value_as_a_scalar_from_its_parent_key() {
        let text = "parent:\n  child: value\n";
        assert!(find_scalar(text, Range::new(Position::new(0, 2), Position::new(0, 2))).is_err());
        assert_eq!(
            find_scalar(text, Range::new(Position::new(1, 4), Position::new(1, 4)))
                .expect("child scalar")
                .plaintext,
            "value"
        );
    }

    #[test]
    fn extracts_vault_block() {
        let text = "secret: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  616263\nnext: ok\n";
        let target = find_vault(text, Range::new(Position::new(1, 5), Position::new(1, 5)))
            .expect("vault target");
        assert_eq!(target.vault_text, "$ANSIBLE_VAULT;1.1;AES256\n616263\n");
        assert_eq!(target.continuation_indent, "  ");
    }

    #[test]
    fn extracts_vault_block_from_its_key_line_and_payload() {
        let text = "secret: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  616263\nnext: ok\n";
        for (line, character) in [(0, 0), (0, 7), (0, 15), (1, 2), (2, 7)] {
            let target = find_vault(
                text,
                Range::new(
                    Position::new(line, character),
                    Position::new(line, character),
                ),
            )
            .expect("vault target");
            assert_eq!(target.vault_text, "$ANSIBLE_VAULT;1.1;AES256\n616263\n");
            assert_eq!(&text[target.start..target.start + 6], "!vault");
        }
    }

    #[test]
    fn recognizes_nested_vault_tag_even_when_its_header_is_malformed() {
        let text = concat!(
            "---\n",
            "ssh_users:\n",
            "  - name: devops\n",
            "    password: !vault |\n",
            "              $sANSIBLE_VAULT;1.1;AES256\n",
            "              3337646434656465\n",
            "              6462313131616338\n",
            "    uid: 1001\n"
        );
        for (line, character) in [(3, 5), (3, 22), (4, 18), (5, 25), (6, 20)] {
            let target = find_vault(
                text,
                Range::new(
                    Position::new(line, character),
                    Position::new(line, character),
                ),
            )
            .expect("tagged vault target");
            assert!(target.vault_text.starts_with("$sANSIBLE_VAULT;"));
            assert_eq!(
                classify_value(
                    text,
                    Range::new(
                        Position::new(line, character),
                        Position::new(line, character),
                    )
                ),
                Some(ValueContext::Vault)
            );
        }
    }

    #[test]
    fn sequence_item_vault_stops_before_sibling_mapping_fields() {
        let text = concat!(
            "---\n",
            "ssh_users:\n",
            "  - name: !vault |\n",
            "          $ANSIBLE_VAULT;1.1;AES256\n",
            "          616263\n",
            "    password: !vault |\n",
            "              $ANSIBLE_VAULT;1.1;AES256\n",
            "              646566\n",
            "    uid: 1001\n",
            "    comment: example\n"
        );
        let password_offset = text.find("    password:").expect("password field");

        for (line, character) in [(2, 4), (2, 17), (3, 12), (4, 12)] {
            let target = find_vault(
                text,
                Range::new(
                    Position::new(line, character),
                    Position::new(line, character),
                ),
            )
            .expect("name vault target");
            assert_eq!(target.vault_text, "$ANSIBLE_VAULT;1.1;AES256\n616263\n");
            assert_eq!(target.continuation_indent, "          ");
            assert!(target.end < password_offset);
        }

        let password = find_vault(text, Range::new(Position::new(7, 16), Position::new(7, 16)))
            .expect("password vault target");
        assert_eq!(password.vault_text, "$ANSIBLE_VAULT;1.1;AES256\n646566\n");
        assert_eq!(password.continuation_indent, "              ");
    }

    #[test]
    fn formats_yaml_safe_plaintext() {
        assert_eq!(format_plaintext_value("hello", "  "), "hello");
        assert_eq!(format_plaintext_value("true", "  "), "'true'");
        assert_eq!(
            format_plaintext_value("it's secret", "  "),
            "'it''s secret'"
        );
        assert_eq!(format_plaintext_value("one\ntwo", "  "), "|-\n  one\n  two");
    }

    #[test]
    fn decodes_quoted_and_escaped_string_scalars() {
        for (yaml, expected) in [
            ("secret: 'it''s private'\n", "it's private"),
            ("secret: \"line\\nvalue\"\n", "line\nvalue"),
            ("secret: \"unicode \\u263a\"\n", "unicode ☺"),
        ] {
            let scalar = find_scalar(yaml, Range::new(Position::new(0, 1), Position::new(0, 1)))
                .expect("string scalar");
            assert_eq!(scalar.plaintext, expected);
        }
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_utf8_never_panics_while_classifying(text in proptest::prelude::any::<String>()) {
            let cursor = Range::new(Position::new(0, 0), Position::new(0, 0));
            let _ = classify_value(&text, cursor);
            let _ = find_scalar(&text, cursor);
            let _ = find_vault(&text, cursor);
        }
    }
}
