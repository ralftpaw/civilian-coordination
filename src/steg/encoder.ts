/**
 * Steganographic encoder for low-bandwidth, high-surveillance environments.
 *
 * Supports three encoding methods suitable for covert civilian coordination:
 *  - ZERO_WIDTH:   Unicode Zero-Width (ZW) characters embedded in text
 *  - CONFUSABLE_WS: Confusable whitespace (en-space, em-space, thin-space)
 *  - EMOJI_SKIN:   Emoji skin tone modifiers encoding binary data
 *
 * All methods are dependency-free, work offline, and output looks like normal text.
 */

// ─── Bit helpers ────────────────────────────────────────────────────────────

function stringToBits(input: string): number[] {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(input);
  const bits: number[] = [];
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  }
  return bits;
}

function bitsToString(bits: number[]): string {
  const bytes: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    const octet = bits.slice(i, i + 8);
    if (octet.length < 8) break;
    let val = 0;
    for (const b of octet) val = (val << 1) | b;
    bytes.push(val);
  }
  const decoder = new TextDecoder();
  return decoder.decode(new Uint8Array(bytes));
}

// ─── ZERO-WIDTH ENCODING ────────────────────────────────────────────────────
// Uses Zero-Width Space (U+200B) = 0 and Zero-Width Non-Joiner (U+200C) = 1
// These characters are invisible in virtually all renderers.

const ZW_0 = '\u200B';
const ZW_1 = '\u200C';

export function encodeZeroWidth(message: string, carrier: string): string {
  const bits = stringToBits(message);
  let result = '';
  let bitIdx = 0;
  for (const ch of carrier) {
    result += ch;
    if (bitIdx < bits.length) {
      result += bits[bitIdx] === 0 ? ZW_0 : ZW_1;
      bitIdx++;
    }
  }
  // If we have leftover bits, append them after the carrier
  while (bitIdx < bits.length) {
    result += bits[bitIdx] === 0 ? ZW_0 : ZW_1;
    bitIdx++;
  }
  return result;
}

export function decodeZeroWidth(encoded: string): string {
  const bits: number[] = [];
  for (const ch of encoded) {
    if (ch === ZW_0) bits.push(0);
    else if (ch === ZW_1) bits.push(1);
  }
  return bitsToString(bits);
}

// ─── CONFUSABLE WHITESPACE ENCODING ─────────────────────────────────────────
// Encodes 2 bits per space using visually identical space variants:
//   NORMAL SPACE (U+0020) = 00  (placeholder — actual text uses this unchanged)
//   EN SPACE     (U+2002) = 01
//   EM SPACE     (U+2003) = 10
//   THIN SPACE   (U+2009) = 11

const WS_00 = ' ';  // Normal space — preserved in carrier text
const WS_01 = '\u2002';
const WS_10 = '\u2003';
const WS_11 = '\u2009';

function encodePair(bits: number[]): string {
  if (bits.length === 0) return WS_00;
  if (bits.length === 1) return bits[0] === 0 ? WS_01 : WS_10;
  return bits[0] === 0 && bits[1] === 0 ? WS_00
    : bits[0] === 0 ? WS_01
    : bits[1] === 0 ? WS_10
    : WS_11;
}

function bitValue(ch: string): number[] | null {
  if (ch === WS_00) return [0, 0];
  if (ch === WS_01) return [0, 1];
  if (ch === WS_10) return [1, 0];
  if (ch === WS_11) return [1, 1];
  return null;
}

export function encodeConfusableWS(message: string, carrier: string): string {
  const bits = stringToBits(message);
  // Replace every space in the carrier with an encoded pair
  let bitIdx = 0;
  let result = '';
  for (const ch of carrier) {
    if (ch === ' ' && bitIdx < bits.length) {
      const pair = bits.slice(bitIdx, bitIdx + 2);
      result += encodePair(pair);
      bitIdx += pair.length;
    } else {
      result += ch;
    }
  }
  // Leftover — we need pairs, so pad with zeros
  if (bitIdx < bits.length) {
    const remaining = bits.slice(bitIdx);
    while (remaining.length < 2) remaining.push(0);
    result += '\u00A0' + encodePair(remaining);
  }
  return result;
}

export function decodeConfusableWS(encoded: string): string {
  const bits: number[] = [];
  for (const ch of encoded) {
    const bv = bitValue(ch);
    if (bv) bits.push(...bv);
  }
  return bitsToString(bits);
}

// ─── EMOJI SKIN TONE ENCODING ───────────────────────────────────────────────
// Uses emoji variation with skin tone modifiers (U+1F3FB through U+1F3FF).
// Four skin tones = 2 bits each: 🏻=00, 🏼=01, 🏾=10, 🏿=11
// The carrier is a sequence of base emojis (👍, 👋, 🤝, 🙌) with skin modifiers.

const SKIN_00 = '\u{1F3FB}';  // Light
const SKIN_01 = '\u{1F3FC}';  // Medium-Light
const SKIN_10 = '\u{1F3FE}';  // Medium-Dark
const SKIN_11 = '\u{1F3FF}';  // Dark

const BASE_EMOJIS = ['👍', '👋', '🤝', '🙌'];

function skinChar(bits: number[]): string {
  if (bits.length === 0) return BASE_EMOJIS[0] + SKIN_00;
  const key = `${bits[0]}${bits[1] || '0'}`;
  const skin = key === '00' ? SKIN_00 : key === '01' ? SKIN_01 : key === '10' ? SKIN_10 : SKIN_11;
  return BASE_EMOJIS[0] + skin;
}

function skinValue(modifier: string): number[] | null {
  if (modifier === SKIN_00) return [0, 0];
  if (modifier === SKIN_01) return [0, 1];
  if (modifier === SKIN_10) return [1, 0];
  if (modifier === SKIN_11) return [1, 1];
  return null;
}

export function encodeEmojiSkin(message: string): string {
  const bits = stringToBits(message);
  let result = '';
  for (let i = 0; i < bits.length; i += 2) {
    result += skinChar(bits.slice(i, i + 2));
  }
  return result;
}

export function decodeEmojiSkin(encoded: string): string {
  const bits: number[] = [];
  // Iterate codepoints to find ZWJ skin tone modifiers
  const codepoints = [...encoded];
  let i = 0;
  while (i < codepoints.length) {
    // Check if next is a skin tone modifier
    if (i + 1 < codepoints.length) {
      const mod = codepoints[i + 1];
      const val = skinValue(mod);
      if (val) {
        bits.push(...val);
        i += 2;
        continue;
      }
    }
    i++;
  }
  return bitsToString(bits);
}
