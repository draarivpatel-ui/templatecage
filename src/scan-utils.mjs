/* Small iterative lexical and Unicode helpers shared by the auditor and CLI. */

export function utf8Length(value) {
  return Buffer.byteLength(value, 'utf8');
}

export function isAsciiIdentifierStart(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code === 36;
}

export function isAsciiIdentifierPart(code) {
  return isAsciiIdentifierStart(code) || (code >= 48 && code <= 57);
}

export function isBidiCodePoint(codePoint) {
  return codePoint === 0x061c ||
    codePoint === 0x200e ||
    codePoint === 0x200f ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069);
}

export function isLineSeparatorCodePoint(codePoint) {
  return codePoint === 0x2028 || codePoint === 0x2029;
}

const FORMAT_CODE_POINT = /\p{Cf}/u;

export function isFormatCodePoint(codePoint) {
  return codePoint >= 0x00ad && FORMAT_CODE_POINT.test(String.fromCodePoint(codePoint));
}

export function isNeutralizedFormatCodePoint(codePoint) {
  return isFormatCodePoint(codePoint) || isLineSeparatorCodePoint(codePoint);
}

export function hostileCharacterKind(text, offset) {
  const code = text.charCodeAt(offset);
  if (code >= 0xd800 && code <= 0xdbff) {
    if (offset + 1 >= text.length) return 'unpaired-surrogate';
    const next = text.charCodeAt(offset + 1);
    if (next < 0xdc00 || next > 0xdfff) return 'unpaired-surrogate';
    const codePoint = text.codePointAt(offset);
    if (isFormatCodePoint(codePoint)) return 'format-character';
    return null;
  }
  if (code >= 0xdc00 && code <= 0xdfff) {
    if (offset === 0) return 'unpaired-surrogate';
    const previous = text.charCodeAt(offset - 1);
    if (previous < 0xd800 || previous > 0xdbff) return 'unpaired-surrogate';
    return null;
  }
  if (code === 0 || (code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127 || (code >= 128 && code <= 159)) {
    return 'control-character';
  }
  if (isBidiCodePoint(code)) return 'bidi-control';
  if (isLineSeparatorCodePoint(code)) return 'unicode-line-separator';
  if (isFormatCodePoint(code)) return 'format-character';
  return null;
}

export function identifierOffsets(text, identifier) {
  const needle = String(identifier).toLowerCase();
  const source = text.toLowerCase();
  const output = [];
  if (needle.length === 0) return output;
  let cursor = 0;
  while (cursor <= source.length - needle.length) {
    const found = source.indexOf(needle, cursor);
    if (found === -1) break;
    const before = found === 0 ? 0 : source.charCodeAt(found - 1);
    const afterIndex = found + needle.length;
    const after = afterIndex >= source.length ? 0 : source.charCodeAt(afterIndex);
    if (!isAsciiIdentifierPart(before) && !isAsciiIdentifierPart(after)) output.push(found);
    cursor = found + Math.max(1, needle.length);
  }
  return output;
}

export function hasIdentifier(text, identifier) {
  return identifierOffsets(text, identifier).length > 0;
}

export function hasIdentifierCall(text, identifier) {
  const positions = identifierOffsets(text, identifier);
  for (const position of positions) {
    let cursor = position + String(identifier).length;
    while (cursor < text.length && /\s/u.test(text[cursor])) cursor += 1;
    if (text[cursor] === '(') return true;
  }
  return false;
}

export function hasPipeFilter(text, filterName) {
  const positions = identifierOffsets(text, filterName);
  for (const position of positions) {
    let cursor = position - 1;
    while (cursor >= 0 && (text[cursor] === ' ' || text[cursor] === '\t')) cursor -= 1;
    if (text[cursor] === '|') return true;
  }
  return false;
}

export function firstWord(text) {
  let cursor = 0;
  while (cursor < text.length && /\s/u.test(text[cursor])) cursor += 1;
  const start = cursor;
  while (cursor < text.length && !/\s/u.test(text[cursor])) cursor += 1;
  return text.slice(start, cursor);
}

function hexValue(character) {
  const code = character.charCodeAt(0);
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 65 && code <= 70) return code - 55;
  if (code >= 97 && code <= 102) return code - 87;
  return -1;
}

function readHex(text, start, count) {
  if (start + count > text.length) return null;
  let value = 0;
  for (let index = 0; index < count; index += 1) {
    const digit = hexValue(text[start + index]);
    if (digit === -1) return null;
    value = value * 16 + digit;
  }
  return value;
}

function decodeEscape(text, slashIndex) {
  if (slashIndex + 1 >= text.length) return { value: '', end: slashIndex + 1, escaped: true };
  const marker = text[slashIndex + 1];
  if (marker === 'x') {
    const value = readHex(text, slashIndex + 2, 2);
    if (value !== null) return { value: String.fromCodePoint(value), end: slashIndex + 4, escaped: true };
  }
  if (marker === 'u') {
    if (text[slashIndex + 2] === '{') {
      let cursor = slashIndex + 3;
      let value = 0;
      let digits = 0;
      while (cursor < text.length && text[cursor] !== '}' && digits <= 6) {
        const digit = hexValue(text[cursor]);
        if (digit === -1) break;
        value = value * 16 + digit;
        digits += 1;
        cursor += 1;
      }
      if (digits > 0 && text[cursor] === '}' && value <= 0x10ffff) {
        return { value: String.fromCodePoint(value), end: cursor + 1, escaped: true };
      }
    } else {
      const value = readHex(text, slashIndex + 2, 4);
      if (value !== null) return { value: String.fromCodePoint(value), end: slashIndex + 6, escaped: true };
    }
  }
  if (marker >= '0' && marker <= '7') {
    let value = marker.charCodeAt(0) - 48;
    let end = slashIndex + 2;
    let count = 1;
    while (count < 3 && end < text.length && text[end] >= '0' && text[end] <= '7') {
      value = value * 8 + text.charCodeAt(end) - 48;
      end += 1;
      count += 1;
    }
    if (value <= 0x10ffff) return { value: String.fromCodePoint(value), end, escaped: true };
  }
  const simple = {
    n: '\n',
    r: '\r',
    t: '\t',
    b: '\b',
    f: '\f',
    v: '\v',
    '0': '\0'
  };
  if (Object.prototype.hasOwnProperty.call(simple, marker)) {
    return { value: simple[marker], end: slashIndex + 2, escaped: true };
  }
  return { value: marker, end: slashIndex + 2, escaped: true };
}

export function parseStringLiteral(text, start) {
  const quote = text[start];
  if (quote !== "'" && quote !== '"' && quote !== '`') return null;
  let cursor = start + 1;
  let value = '';
  let hadEscape = false;
  while (cursor < text.length) {
    const character = text[cursor];
    if (character === quote) {
      return { start, end: cursor + 1, value, hadEscape, quote };
    }
    if (character === '\\') {
      const decoded = decodeEscape(text, cursor);
      value += decoded.value;
      cursor = decoded.end;
      hadEscape = true;
      continue;
    }
    if ((character === '\n' || character === '\r') && quote !== '`') return null;
    value += character;
    cursor += 1;
  }
  return null;
}

function skipHorizontalWhitespace(text, cursor) {
  let index = cursor;
  while (index < text.length && /\s/u.test(text[index])) index += 1;
  return index;
}

export function stringConcatenations(text) {
  const output = [];
  let cursor = 0;
  while (cursor < text.length) {
    const character = text[cursor];
    if (character !== "'" && character !== '"' && character !== '`') {
      cursor += 1;
      continue;
    }
    const first = parseStringLiteral(text, cursor);
    if (!first) {
      cursor += 1;
      continue;
    }
    let value = first.value;
    let parts = 1;
    let encoded = first.hadEscape;
    let end = first.end;
    let lookahead = skipHorizontalWhitespace(text, end);
    while ((text[lookahead] === '+' || text[lookahead] === '~') && lookahead < text.length) {
      let nextStart = skipHorizontalWhitespace(text, lookahead + 1);
      const next = parseStringLiteral(text, nextStart);
      if (!next) break;
      value += next.value;
      parts += 1;
      encoded = encoded || next.hadEscape;
      end = next.end;
      lookahead = skipHorizontalWhitespace(text, end);
    }
    if (parts > 1 || encoded) output.push({ start: cursor, end, value, parts, encoded });
    cursor = Math.max(first.end, cursor + 1);
  }
  return output;
}

export function terminalSafe(value) {
  const input = String(value);
  let output = '';
  for (let index = 0; index < input.length; index += 1) {
    const code = input.codePointAt(index);
    if (code > 0xffff) index += 1;
    if ((code >= 0xd800 && code <= 0xdfff) || (code < 32 && code !== 9 && code !== 10) || code === 13 || code === 127 || (code >= 128 && code <= 159) || isNeutralizedFormatCodePoint(code)) {
      output += '<U+' + code.toString(16).toUpperCase().padStart(4, '0') + '>';
    } else {
      output += String.fromCodePoint(code);
    }
  }
  return output;
}

export function stripDangerousText(value) {
  const input = String(value);
  let output = '';
  for (let index = 0; index < input.length; index += 1) {
    const code = input.codePointAt(index);
    if (code > 0xffff) index += 1;
    if ((code >= 0xd800 && code <= 0xdfff) || (code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127 || (code >= 128 && code <= 159) || isNeutralizedFormatCodePoint(code)) continue;
    output += String.fromCodePoint(code);
  }
  return output;
}

export function boundedExcerpt(value, maximum) {
  const limit = typeof maximum === 'number' ? maximum : 80;
  const text = stripDangerousText(String(value));
  if (text.length <= limit) return text;
  return text.slice(0, limit) + '...';
}
