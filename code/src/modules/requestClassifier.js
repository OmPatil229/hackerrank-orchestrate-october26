/**
 * src/modules/requestClassifier.js
 *
 * Classify whether request_text authorises deletion.
 * Returns true for deletion, false for NOT_APPLICABLE.
 *
 * Two-stage:
 *   1. Fast multi-language keyword heuristic
 *   2. LLM call (Gemini or Claude) for ambiguous text
 */

import { getLLMClient } from './llmClient.js';

// ---------------------------------------------------------------------------
// Keyword patterns (multi-language)
// ---------------------------------------------------------------------------

const DELETION_PATTERNS = [
  /\bdelete\b/i, /\berase\b/i, /\bremov(e|al)\b/i,
  /\bclos(e|ing|ure)\b.*\baccount\b/i,
  /\baccount.*\bclos/i,
  /\bpermanent(ly)?\b.*\bdelet/i,
  /\bright to be forgotten\b/i,
  /\bright to erasure\b/i,
  /\bforget me\b/i,
  /\bwipe\b.*\bdata\b/i,
  /\bsuppress(ion)?\b/i,
  // Portuguese
  /\bexclus[aã]o\b/i, /\bapagar\b/i, /\bdeletar\b/i,
  // French
  /\bsupprim(er|ez|ons)\b/i, /\beffac(er|ez)\b/i,
  // Spanish
  /\belimina(r|ci[oó]n)\b/i, /\bborrar\b/i, /\bsuprimir\b/i,
  // German
  /\bl[oö]schen\b/i,
  // Japanese
  /削除|消去|アカウントの廃止/,
  // Korean
  /삭제|계정.*(삭제|폐쇄)/,
  // Arabic
  /حذف|مسح/,
];

const NON_DELETION_PATTERNS = [
  /\bdownload\b.*\bdata\b/i,
  /\bexport\b.*\bdata\b/i,
  /\baccess\b.*\bmy data\b/i,
  /\bcorrect(ion)?\b.*\b(data|information)\b/i,
  /\bopt.?out\b.*\bmarketing\b/i,
  /\bunsubscribe\b/i,
];

function keywordClassify(text) {
  const hasNonDeletion = NON_DELETION_PATTERNS.some(p => p.test(text));
  const hasDeletion = DELETION_PATTERNS.some(p => p.test(text));

  if (hasNonDeletion && !hasDeletion) return 'NO';
  if (hasDeletion) return 'YES';
  return null; // ambiguous
}

// ---------------------------------------------------------------------------
// LLM cache (text -> boolean)
// ---------------------------------------------------------------------------

const _cache = new Map();

async function llmClassify(text) {
  if (_cache.has(text)) return _cache.get(text);

  const prompt = `You are a privacy request classifier.
Determine if this customer message is a request to DELETE or ERASE their personal data, or close/delete their account.

Answer ONLY with valid JSON: {"is_deletion": true} or {"is_deletion": false}

Return true ONLY if the message explicitly asks for:
- deletion, erasure, account closure, removal of personal data

Return false for: data access requests, data export, corrections, marketing opt-out, password changes.

Customer message:
${text}`;

  const llm = getLLMClient();
  let result = true; // default to deletion if LLM fails

  try {
    const response = await llm.classify(prompt);
    const parsed = JSON.parse(response);
    result = Boolean(parsed.is_deletion);
  } catch (e) {
    // If LLM fails, fall back to keyword majority
    const kw = keywordClassify(text);
    result = kw !== 'NO';
  }

  _cache.set(text, result);
  return result;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function isDeletionRequest(requestText) {
  const kw = keywordClassify(requestText);
  if (kw === 'YES') return true;
  if (kw === 'NO') return false;
  return llmClassify(requestText);
}
