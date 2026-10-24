/**
 * src/modules/evidenceReaders/pdfReader.js
 *
 * Extract text from PDF evidence files using pdf-parse,
 * then search for user identifiers within the text.
 * For structured extraction, passes text to the LLM.
 */

import { readFileSync } from 'fs';
import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';
import { getLLMClient } from '../llmClient.js';

// Cache: filePath -> extracted text
const _textCache = new Map();
// Cache: (filePath, userId) -> records[]
const _recordCache = new Map();

async function extractText(filePath) {
  if (_textCache.has(filePath)) return _textCache.get(filePath);

  const pdfParse = (await import('pdf-parse/lib/pdf-parse.js')).default;
  const buffer = readFileSync(filePath);
  const data = await pdfParse(buffer);
  _textCache.set(filePath, data.text);
  return data.text;
}

/** Check if PDF text mentions any user identifiers */
function textMatchesCtx(text, ctx) {
  const lower = text.toLowerCase();
  if (lower.includes(ctx.userId.toLowerCase())) return true;
  for (const email of ctx.allEmails) {
    if (lower.includes(email.toLowerCase())) return true;
  }
  for (const name of ctx.nameVariants) {
    if (name && lower.includes(name.toLowerCase())) return true;
  }
  for (const phone of ctx.allPhones) {
    const norm = phone.replace(/[\s\-\(\)\+]/g, '');
    if (norm.length > 6 && text.replace(/[\s\-\(\)\+]/g, '').toLowerCase().includes(norm.toLowerCase())) return true;
  }
  return false;
}

/** Use LLM to extract structured records from PDF text */
async function extractWithLLM(text, fileId, ctx) {
  const cacheKey = `${fileId}::${ctx.userId}`;
  if (_recordCache.has(cacheKey)) return _recordCache.get(cacheKey);

  const prompt = `You are a data privacy auditor. Extract all records from this document that belong to a user with these identifiers:
- user_id: ${ctx.userId}
- emails: ${[...ctx.allEmails].join(', ')}
- phones: ${[...ctx.allPhones].join(', ')}
- names: ${[...ctx.nameVariants].join(', ')}

For each record found, return a JSON array of objects with these fields:
- resource_id: the record/entry identifier (e.g. "audit_record_123", "account_456")
- system_id: the system holding the record (e.g. "security_service", "account_service")
- data_category: one of USER_PROFILE, SECURITY_AUDIT_LOG, LEGAL_HOLD_RECORD, BACKUP_ARCHIVE, SUPPORT_MESSAGE, ACCOUNT_TOMBSTONE
- state: PRESENT, RETAINED, REDACTED, or ABSENT
- notes: brief description of what was found

If no records belong to this user, return {"records": []}.

Document content:
${text.slice(0, 8000)}

JSON response:`;

  const llm = getLLMClient();
  let records = [];

  try {
    const raw = await llm.extract(prompt);
    // Extract JSON from response
    const match = raw.match(/\{[\s\S]*\}/);
    if (match) {
      const parsed = JSON.parse(match[0]);
      records = Array.isArray(parsed.records) ? parsed.records : [];
    }
  } catch (e) {
    console.warn(`[pdfReader] LLM extraction failed for ${fileId}: ${e.message}`);
    // Simple fallback: scan for resource IDs
    records = extractResourceIdsFromText(text, fileId);
  }

  _recordCache.set(cacheKey, records);
  return records;
}

/** Simple fallback: regex-scan for resource ID patterns in text */
function extractResourceIdsFromText(text, fileId) {
  const records = [];
  const pattern = /\b(account|search|analytics|support|export|backup|audit_record|tombstone|data_flow)_\d+\b/gi;
  const matches = new Set(text.match(pattern) || []);

  for (const rid of matches) {
    const prefix = rid.split('_')[0].toLowerCase();
    const systemMap = {
      account: { systemId: 'account_service', dataCategory: 'USER_PROFILE' },
      search: { systemId: 'search_service', dataCategory: 'SEARCH_INDEX_ENTRY' },
      analytics: { systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE' },
      support: { systemId: 'support_platform', dataCategory: 'SUPPORT_MESSAGE' },
      export: { systemId: 'export_service', dataCategory: 'USER_EXPORT' },
      backup: { systemId: 'backup_service', dataCategory: 'BACKUP_ARCHIVE' },
      audit: { systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' },
      tombstone: { systemId: 'identity_service', dataCategory: 'ACCOUNT_TOMBSTONE' },
      data: { systemId: 'integration_service', dataCategory: 'ACTIVE_DATA_FLOW' },
    };
    const info = systemMap[prefix] || { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
    records.push({ resource_id: rid, ...info, state: 'PRESENT' });
  }
  return records;
}

/**
 * Extract user records from a PDF evidence file.
 */
export async function extractFromPDF(evidenceFilePath, fileId, ctx, auditAt) {
  const absPath = path.join(DATASET_DIR, evidenceFilePath);
  const results = [];

  let text;
  try {
    text = await extractText(absPath);
  } catch (e) {
    console.warn(`[pdfReader] Failed to extract text from ${evidenceFilePath}: ${e.message}`);
    return results;
  }

  if (!textMatchesCtx(text, ctx)) return results;

  const llmRecords = await extractWithLLM(text, fileId, ctx);

  for (const rec of llmRecords) {
    const resourceId = rec.resource_id;
    if (!resourceId) continue;

    const state = rec.state === 'RETAINED' ? 'PRESENT' :
      rec.state === 'ABSENT' ? null : (rec.state || 'PRESENT');
    if (!state) continue;

    results.push({
      resourceId,
      systemId: rec.system_id || rec.systemId || 'security_service',
      dataCategory: rec.data_category || rec.dataCategory || 'SECURITY_AUDIT_LOG',
      state,
      evidenceId: fileId,
      identifyingFields: {},
    });
  }

  return results;
}
