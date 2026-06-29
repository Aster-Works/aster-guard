/**
 * Unicode steganography / deceptive-character analysis used by AG-016.
 *
 * Configs are plain machine text: invisible formatting characters, terminal
 * escape sequences, bidirectional overrides, and mixed-script homoglyphs have
 * essentially no legitimate reason to appear inside an MCP server definition.
 * Attackers use them to (a) smuggle instructions past keyword filters by
 * splitting words with zero-width characters, (b) hide text in terminals with
 * ANSI escapes, (c) reorder displayed text with bidi overrides (Trojan Source),
 * or (d) encode whole ASCII payloads in the Unicode Tags block ("ASCII
 * smuggling"). This module classifies those characters and produces a
 * human-readable visualization so the report can show what was hidden.
 */

export type StegoCategory =
  | 'tag'
  | 'bidi'
  | 'ansi'
  | 'invisible'
  | 'variation-selector'
  | 'line-separator'
  | 'homoglyph';

/** Unicode Tags block (U+E0000–U+E007F): invisible, decodes to ASCII. */
function isTag(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

/** Bidirectional formatting/override controls (Trojan Source, CVE-2021-42574). */
const BIDI_CONTROLS = new Set([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // LRE RLE PDF LRO RLO
  0x2066, 0x2067, 0x2068, 0x2069, // LRI RLI FSI PDI
  0x200e, 0x200f, // LRM RLM
  0x061c, // Arabic letter mark
]);

/**
 * Hard zero-width / invisible formatting characters with no place in a config
 * string. Excludes the joiners U+200C/U+200D, which are handled separately
 * (they are legitimate inside emoji ZWJ sequences and some scripts).
 */
const HARD_INVISIBLE = new Set([
  0x200b, // zero width space
  0x2060, // word joiner
  0x2061, 0x2062, 0x2063, 0x2064, // invisible math operators
  0xfeff, // zero width no-break space / BOM
  0x00ad, // soft hyphen
  0x034f, // combining grapheme joiner
  0x115f, 0x1160, // Hangul choseong/jungseong fillers
  0x17b4, 0x17b5, // Khmer inherent vowels (zero-width)
  0x180e, // Mongolian vowel separator
  0x3164, // Hangul filler
  0xffa0, // halfwidth Hangul filler
]);

/** Zero-width joiner / non-joiner — flagged only when splitting a word. */
const JOINERS = new Set([0x200c, 0x200d]);

/**
 * Variation selectors abused for data smuggling. Only the supplementary range
 * (U+E0100–U+E01EF) is flagged: the basic range U+FE00–U+FE0F — especially the
 * emoji-presentation selector U+FE0F — is ubiquitous in legitimate emoji and
 * would cause constant false positives.
 */
function isVariationSelector(cp: number): boolean {
  return cp >= 0xe0100 && cp <= 0xe01ef;
}

/** Line / paragraph separators that can hide content on a single visual line. */
const LINE_SEPARATORS = new Set([0x2028, 0x2029]);

/**
 * A "word" character for deciding whether a joiner is splitting readable text.
 * Only letters and digits count — emoji and symbols are excluded so legitimate
 * emoji ZWJ sequences (e.g. 👨‍👩‍👧) are not mistaken for word-splitting.
 */
const LETTER_OR_DIGIT = /[\p{L}\p{N}]/u;
function isWordChar(ch: string | undefined): boolean {
  return ch !== undefined && LETTER_OR_DIGIT.test(ch);
}

function marker(cp: number): string {
  return '‹U+' + cp.toString(16).toUpperCase().padStart(4, '0') + '›';
}

/**
 * Remove every deceptive character so the underlying text can be re-scanned
 * for injection phrases (the "rendered-vs-raw diff" two-stage check).
 */
export function stripDeceptive(value: string): string {
  let out = '';
  for (const ch of value) {
    const cp = ch.codePointAt(0)!;
    if (
      cp === 0x1b ||
      isTag(cp) ||
      BIDI_CONTROLS.has(cp) ||
      HARD_INVISIBLE.has(cp) ||
      JOINERS.has(cp) ||
      isVariationSelector(cp) ||
      LINE_SEPARATORS.has(cp)
    ) {
      continue;
    }
    out += ch;
  }
  return out;
}

const LATIN_LETTER = /\p{Script=Latin}/u;
const CYRILLIC_LETTER = /\p{Script=Cyrillic}/u;
const GREEK_LETTER = /\p{Script=Greek}/u;
const LETTER_RUN = /\p{L}[\p{L}\p{M}]*/gu;

/**
 * Detect homoglyph spoofing: a single alphabetic token that mixes Latin with
 * Cyrillic or Greek (e.g. "pаypal" with a Cyrillic а). Pure non-Latin text
 * (Japanese, all-Russian, all-Greek) is never flagged — only intra-word
 * mixing of confusable scripts is suspicious.
 */
function hasHomoglyphToken(value: string): boolean {
  for (const m of value.matchAll(LETTER_RUN)) {
    const token = m[0];
    if (!LATIN_LETTER.test(token)) continue;
    if (CYRILLIC_LETTER.test(token) || GREEK_LETTER.test(token)) return true;
  }
  return false;
}

export interface StegoAnalysis {
  /** Categories of deceptive characters present, worst-first is not guaranteed. */
  categories: Set<StegoCategory>;
  /** The input with every deceptive character replaced by a visible ‹U+XXXX› marker. */
  visualized: string;
  /** Whether any deceptive character at all was found. */
  hasAny: boolean;
}

/** Classify one string value. */
export function analyzeStego(value: string): StegoAnalysis {
  const categories = new Set<StegoCategory>();
  let visualized = '';

  // Per-code-point classification + visualization.
  for (const ch of value) {
    const cp = ch.codePointAt(0)!;
    if (cp === 0x1b) {
      categories.add('ansi');
      visualized += '‹ESC›';
      continue;
    }
    if (isTag(cp)) {
      categories.add('tag');
      visualized += marker(cp);
      continue;
    }
    if (BIDI_CONTROLS.has(cp)) {
      categories.add('bidi');
      visualized += marker(cp);
      continue;
    }
    if (HARD_INVISIBLE.has(cp)) {
      categories.add('invisible');
      visualized += marker(cp);
      continue;
    }
    if (isVariationSelector(cp)) {
      categories.add('variation-selector');
      visualized += marker(cp);
      continue;
    }
    if (LINE_SEPARATORS.has(cp)) {
      categories.add('line-separator');
      visualized += marker(cp);
      continue;
    }
    if (JOINERS.has(cp)) {
      // Always visualize; only count as suspicious when it splits a word.
      visualized += marker(cp);
      continue;
    }
    // Other ASCII control chars (besides tab/newline/CR) are also unusual.
    if (cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) {
      categories.add('ansi');
      visualized += marker(cp);
      continue;
    }
    visualized += ch;
  }

  // Word-splitting joiner detection (emoji ZWJ sequences are not word-splits).
  const chars = Array.from(value);
  for (let i = 0; i < chars.length; i++) {
    const cp = chars[i]!.codePointAt(0)!;
    if (!JOINERS.has(cp)) continue;
    if (isWordChar(chars[i - 1]) && isWordChar(chars[i + 1])) {
      categories.add('invisible');
      break;
    }
  }

  if (hasHomoglyphToken(value)) categories.add('homoglyph');

  return { categories, visualized, hasAny: categories.size > 0 };
}
