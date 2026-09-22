//! Minimal, dependency-free PDF writer for text reports.
//!
//! Emits PDF 1.4 with the base-14 fonts (Helvetica, Helvetica-Bold,
//! Courier) so nothing is embedded and the binary stays small. Good enough
//! for headings, paragraphs and fixed-width tables — which is all
//! `kxn recommend --format pdf` needs. Text is limited to WinAnsi: other
//! characters are transliterated or replaced with `?`.

/// A block of content in reading order.
#[derive(Debug, Clone)]
pub enum Block {
    /// Section heading (Helvetica-Bold 13pt).
    Heading(String),
    /// Wrapped paragraph (Helvetica 9.5pt).
    Para(String),
    /// Fixed-width lines, never wrapped (Courier 7pt); a table usually.
    Mono(Vec<String>),
    /// Small vertical gap.
    Gap,
}

/// A4 landscape.
const PAGE_W: f64 = 841.89;
const PAGE_H: f64 = 595.28;
const MARGIN: f64 = 40.0;

const TITLE_PT: f64 = 16.0;
const HEAD_PT: f64 = 13.0;
const PARA_PT: f64 = 9.5;
const MONO_PT: f64 = 7.0;
/// Courier glyph width is 0.6 em.
const MONO_CHAR_W: f64 = 0.6;
/// Rough Helvetica average glyph width, used for paragraph wrapping.
const PARA_CHAR_W: f64 = 0.5;

/// Render `blocks` under `title` (first page header) and return the PDF bytes.
pub fn render(title: &str, subtitle: &str, blocks: &[Block]) -> Vec<u8> {
    let mut pages: Vec<String> = Vec::new();
    let mut page = Page::new();

    page.text(&mut pages, Font::Bold, TITLE_PT, title);
    page.text(&mut pages, Font::Regular, PARA_PT, subtitle);
    page.gap(PARA_PT);

    let para_cols = ((PAGE_W - 2.0 * MARGIN) / (PARA_PT * PARA_CHAR_W)) as usize;
    let mono_cols = ((PAGE_W - 2.0 * MARGIN) / (MONO_PT * MONO_CHAR_W)) as usize;

    for block in blocks {
        match block {
            Block::Heading(h) => {
                page.gap(HEAD_PT * 0.6);
                page.text(&mut pages, Font::Bold, HEAD_PT, h);
                page.gap(HEAD_PT * 0.3);
            }
            Block::Para(p) => {
                for line in wrap(p, para_cols) {
                    page.text(&mut pages, Font::Regular, PARA_PT, &line);
                }
                page.gap(PARA_PT * 0.5);
            }
            Block::Mono(lines) => {
                for line in lines {
                    let clipped: String = line.chars().take(mono_cols).collect();
                    page.text(&mut pages, Font::Mono, MONO_PT, &clipped);
                }
                page.gap(MONO_PT);
            }
            Block::Gap => page.gap(PARA_PT),
        }
    }
    page.flush(&mut pages);

    assemble(&pages)
}

#[derive(Clone, Copy)]
enum Font {
    Regular,
    Bold,
    Mono,
}

impl Font {
    fn name(self) -> &'static str {
        match self {
            Font::Regular => "/F1",
            Font::Bold => "/F2",
            Font::Mono => "/F3",
        }
    }
}

struct Page {
    content: String,
    y: f64,
    number: usize,
}

impl Page {
    fn new() -> Self {
        Self { content: String::new(), y: PAGE_H - MARGIN, number: 1 }
    }

    fn text(&mut self, pages: &mut Vec<String>, font: Font, size: f64, s: &str) {
        let leading = size * 1.3;
        if self.y - leading < MARGIN {
            self.flush(pages);
        }
        self.y -= leading;
        self.content.push_str(&format!(
            "BT {} {:.1} Tf {:.2} {:.2} Td ({}) Tj ET\n",
            font.name(),
            size,
            MARGIN,
            self.y,
            escape(s)
        ));
    }

    fn gap(&mut self, pt: f64) {
        self.y -= pt;
    }

    fn flush(&mut self, pages: &mut Vec<String>) {
        // Footer with the page number.
        let footer = format!("kxn - page {}", self.number);
        self.content.push_str(&format!(
            "BT /F1 7 Tf {:.2} {:.2} Td ({}) Tj ET\n",
            PAGE_W - MARGIN - footer.len() as f64 * 7.0 * PARA_CHAR_W,
            MARGIN * 0.5,
            escape(&footer)
        ));
        pages.push(std::mem::take(&mut self.content));
        self.y = PAGE_H - MARGIN;
        self.number += 1;
    }
}

/// Escape for a PDF literal string and squash to WinAnsi-safe ASCII.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c => out.push_str(transliterate(c)),
        }
    }
    out
}

fn transliterate(c: char) -> &'static str {
    match c {
        'à' | 'â' | 'ä' | 'á' => "a",
        'é' | 'è' | 'ê' | 'ë' => "e",
        'î' | 'ï' | 'í' => "i",
        'ô' | 'ö' | 'ó' => "o",
        'ù' | 'û' | 'ü' | 'ú' => "u",
        'ç' => "c",
        'À' | 'Â' | 'Ä' => "A",
        'É' | 'È' | 'Ê' | 'Ë' => "E",
        'Ô' | 'Ö' => "O",
        'Ù' | 'Û' | 'Ü' => "U",
        'Ç' => "C",
        '–' | '—' => "-",
        '’' | '‘' => "'",
        '“' | '”' => "\"",
        '…' => "...",
        'Δ' => "d",
        '≥' => ">=",
        '≤' => "<=",
        '→' => "->",
        '×' => "x",
        '·' | '•' => "-",
        _ => "?",
    }
}

fn wrap(text: &str, cols: usize) -> Vec<String> {
    let cols = cols.max(20);
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > cols {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() || lines.is_empty() {
        lines.push(cur);
    }
    lines
}

/// Build the object table, xref and trailer around the page content streams.
fn assemble(pages: &[String]) -> Vec<u8> {
    // Object numbering: 1 catalog, 2 pages tree, 3-5 fonts, then per page
    // (page object, content stream).
    let first_page_obj = 6;
    let mut objects: Vec<String> = Vec::new();
    let kids: Vec<String> = (0..pages.len())
        .map(|i| format!("{} 0 R", first_page_obj + i * 2))
        .collect();

    objects.push("<< /Type /Catalog /Pages 2 0 R >>".to_string());
    objects.push(format!(
        "<< /Type /Pages /Kids [{}] /Count {} >>",
        kids.join(" "),
        pages.len()
    ));
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".to_string());
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>".to_string());
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>".to_string());

    for (i, content) in pages.iter().enumerate() {
        let content_obj = first_page_obj + i * 2 + 1;
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {:.2} {:.2}] \
             /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {} 0 R >>",
            PAGE_W, PAGE_H, content_obj
        ));
        objects.push(format!(
            "<< /Length {} >>\nstream\n{}endstream",
            content.len(),
            content
        ));
    }

    let mut out = String::new();
    out.push_str("%PDF-1.4\n%\u{00e2}\u{00e3}\u{00cf}\u{00d3}\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, obj) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.push_str(&format!("{} 0 obj\n{}\nendobj\n", i + 1, obj));
    }
    let xref_at = out.len();
    out.push_str(&format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1));
    for off in &offsets {
        out.push_str(&format!("{:010} 00000 n \n", off));
    }
    out.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
        objects.len() + 1,
        xref_at
    ));
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_valid_skeleton() {
        let pdf = render(
            "Title",
            "sub",
            &[
                Block::Heading("H".into()),
                Block::Para("hello (world) \\ é".into()),
                Block::Mono(vec!["a  b".into()]),
            ],
        );
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.starts_with("%PDF-1.4"));
        assert!(text.trim_end().ends_with("%%EOF"));
        assert!(text.contains("/BaseFont /Courier"));
        assert!(text.contains("(hello \\(world\\) \\\\ e) Tj"));
        // xref offsets must point at "N 0 obj"
        let xref_pos = text.rfind("startxref\n").unwrap() + "startxref\n".len();
        let xref_at: usize = text[xref_pos..].lines().next().unwrap().parse().unwrap();
        assert!(text[xref_at..].starts_with("xref\n"));
        let first_off: usize = text[xref_at..].lines().nth(3).unwrap()[..10].parse().unwrap();
        assert!(text[first_off..].starts_with("1 0 obj"));
    }

    #[test]
    fn paginates_long_mono_blocks() {
        let lines: Vec<String> = (0..300).map(|i| format!("line {i}")).collect();
        let pdf = render("T", "", &[Block::Mono(lines)]);
        let text = String::from_utf8_lossy(&pdf);
        let pages = text.matches("/Type /Page ").count();
        assert!(pages >= 4, "expected several pages, got {pages}");
        assert!(text.contains("/Count 6") || pages >= 4);
    }

    #[test]
    fn wraps_paragraphs() {
        let l = wrap("one two three four five six seven eight", 20);
        assert_eq!(l, vec!["one two three four", "five six seven eight"]);
        assert_eq!(wrap("", 20), vec![""]);
    }
}
