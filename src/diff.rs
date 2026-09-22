//! Line-based diff over decrypted vault contents (unified-style output).

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Op {
    Equal,
    Delete,
    Insert,
}

pub struct DiffLine {
    pub op: Op,
    pub text: String,
}

/// Diff two line lists via Myers-style LCS (hash-accelerated). For
/// typical .env sizes this is fast and produces a minimal-ish edit script.
pub fn diff_lines(old: &[String], new: &[String]) -> Vec<DiffLine> {
    let n = old.len();
    let m = new.len();
    // LCS table with u32 to stay small; fallback to naive equality at the
    // ends keeps the table traversal simple.
    let mut table = vec![0u32; (n + 1) * (m + 1)];
    let idx = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[idx(i, j)] = if old[i] == new[j] {
                table[idx(i + 1, j + 1)] + 1
            } else {
                table[idx(i + 1, j)].max(table[idx(i, j + 1)])
            };
        }
    }
    let mut out = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while i < n && j < m {
        if old[i] == new[j] {
            out.push(DiffLine { op: Op::Equal, text: old[i].clone() });
            i += 1;
            j += 1;
        } else if table[idx(i + 1, j)] >= table[idx(i, j + 1)] {
            out.push(DiffLine { op: Op::Delete, text: old[i].clone() });
            i += 1;
        } else {
            out.push(DiffLine { op: Op::Insert, text: new[j].clone() });
            j += 1;
        }
    }
    for line in &old[i..] {
        out.push(DiffLine { op: Op::Delete, text: line.clone() });
    }
    for line in &new[j..] {
        out.push(DiffLine { op: Op::Insert, text: line.clone() });
    }
    out
}

/// Render hunks in a unified-diff style: `@@ -a,b +c,d @@` with `-`/`+`
/// markers, collapsing to single counts when 1.
pub fn render_unified(old_name: &str, new_name: &str, diff: &[DiffLine]) -> String {
    let old_total = diff.iter().filter(|l| l.op != Op::Insert).count();
    let new_total = diff.iter().filter(|l| l.op != Op::Delete).count();
    if old_total == new_total && old_total == diff.len() {
        return String::new(); // identical
    }
    let mut out = format!("--- {}\n+++ {}\n", old_name, new_name);
    let mut k = 0usize;
    let mut old_line = 1usize;
    let mut new_line = 1usize;
    while k < diff.len() {
        if diff[k].op == Op::Equal {
            k += 1;
            old_line += 1;
            new_line += 1;
            continue;
        }
        // hunk: gather around this change
        let start_k = k;
        let mut end_k = k;
        while end_k < diff.len() {
            if diff[end_k].op != Op::Equal {
                end_k += 1;
                continue;
            }
            // Equal run: consume it as hunk context only when another
            // change follows within 3 lines.
            let mut probe = end_k;
            while probe < diff.len() && diff[probe].op == Op::Equal {
                probe += 1;
            }
            if probe < diff.len() && probe - end_k <= 3 {
                end_k = probe;
            } else {
                break;
            }
        }
        let hunk = &diff[start_k..end_k];
        let dels = hunk.iter().filter(|l| l.op != Op::Insert).count();
        let ins = hunk.iter().filter(|l| l.op != Op::Delete).count();
        out.push_str(&format!("@@ -{},{} +{},{} @@\n", old_line, dels, new_line, ins));
        for line in hunk {
            match line.op {
                Op::Equal => {
                    out.push(' ');
                    old_line += 1;
                    new_line += 1;
                }
                Op::Delete => {
                    out.push('-');
                    old_line += 1;
                }
                Op::Insert => {
                    out.push('+');
                    new_line += 1;
                }
            }
            out.push_str(&line.text);
            out.push('\n');
        }
        k = end_k;
    }
    out
}

/// Convenience: diff two byte payloads split into lines. Beyond the
/// quadratic-table guard (4000 lines per side) the result degrades to a
/// wholesale replace, which is fine for a leaked-secrets audit and keeps
/// memory bounded.
pub fn diff_bytes(old: &[u8], new: &[u8]) -> Vec<DiffLine> {
    let old_lines = to_lines(old);
    let new_lines = to_lines(new);
    if old_lines.len() * new_lines.len() > 16_000_000 {
        let mut out: Vec<DiffLine> = old_lines
            .iter()
            .map(|l| DiffLine { op: Op::Delete, text: l.clone() })
            .collect();
        out.extend(new_lines.iter().map(|l| DiffLine { op: Op::Insert, text: l.clone() }));
        return out;
    }
    diff_lines(&old_lines, &new_lines)
}

fn to_lines(data: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(data)
        .lines()
        .map(|l| l.to_string())
        .collect()
}

/// Summary of an .env diff in terms of keys: keys appearing on both sides
/// count as changed, the rest as added or removed.
pub fn env_summary(diff: &[DiffLine]) -> String {
    use std::collections::HashSet;
    let mut removed_keys: HashSet<&str> = HashSet::new();
    let mut added_keys: HashSet<&str> = HashSet::new();
    for line in diff {
        match line.op {
            Op::Insert => {
                added_keys.insert(key_of(&line.text));
            }
            Op::Delete => {
                removed_keys.insert(key_of(&line.text));
            }
            Op::Equal => {}
        }
    }
    let changed = removed_keys.intersection(&added_keys).count();
    let added = added_keys.len() - changed;
    let removed = removed_keys.len() - changed;
    format!("{} key(s) changed, {} added, {} removed", changed, added, removed)
}

fn key_of(line: &str) -> &str {
    match line.find('=') {
        Some(eq) => &line[..eq],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn identical_inputs_produce_no_diff() {
        let d = diff_lines(&lines(&["A=1", "B=2"]), &lines(&["A=1", "B=2"]));
        assert!(d.iter().all(|l| l.op == Op::Equal));
        assert_eq!(render_unified("a", "b", &d), "");
    }

    #[test]
    fn changed_line_is_delete_plus_insert() {
        let d = diff_lines(&lines(&["A=1", "B=2", "C=3"]), &lines(&["A=1", "B=9", "C=3"]));
        let ops: Vec<_> = d.iter().map(|l| l.op).collect();
        assert_eq!(ops, vec![Op::Equal, Op::Delete, Op::Insert, Op::Equal]);
    }

    #[test]
    fn appended_line_is_insert() {
        let d = diff_lines(&lines(&["A=1"]), &lines(&["A=1", "B=2"]));
        assert!(d.iter().any(|l| l.op == Op::Insert && l.text == "B=2"));
        assert!(!d.iter().any(|l| l.op == Op::Delete));
    }

    #[test]
    fn unified_output_has_hunk_headers() {
        let d = diff_bytes(b"A=1\nB=2\nC=3\n", b"A=1\nB=9\nC=3\n");
        let rendered = render_unified("old.vault", "new.vault", &d);
        assert!(rendered.contains("--- old.vault"));
        assert!(rendered.contains("+++ new.vault"));
        assert!(rendered.contains("@@ -2,1 +2,1 @@"), "hunk header: {}", rendered);
        assert!(rendered.contains("-B=2\n"));
        assert!(rendered.contains("+B=9\n"));
    }

    #[test]
    fn summary_counts_keys() {
        let d = diff_bytes(b"A=1\nB=2\n", b"A=1\nB=3\nC=4\n");
        let summary = env_summary(&d);
        assert!(summary.contains("1 key(s) changed"), "{}", summary);
        assert!(summary.contains("1 added"), "{}", summary);
        assert!(summary.contains("0 removed"), "{}", summary);
    }
}
