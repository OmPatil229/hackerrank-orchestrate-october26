/**
 * src/modules/evidenceReaders/imageReader.js
 *
 * Extract records from PNG screenshot evidence using LLM vision.
 * Screenshots include admin consoles, search inspector, analytics views,
 * backup/restore consoles, connector management, support ticket views, etc.
 */

import { readFileSync } from 'fs';
import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';
import { getLLMClient } from '../llmClient.js';

// Cache: (filePath, userId) -> records[]
const _cache = new Map();

/** Determine what kind of screenshot this is from filename */
function classifyScreenshot(filePath) {
  const name = path.basename(filePath).toLowerCase();
  if (name.includes('account_admin')) return 'account_service';
  if (name.includes('search_index')) return 'search_service';
  if (name.includes('analytics')) return 'analytics_platform';
  if (name.includes('backup_restore')) return 'backup_service';
  if (name.includes('connector')) return 'integration_service';
  if (name.includes('export')) return 'export_service';
  if (name.includes('marketing')) return 'marketing_platform';
  if (name.includes('support')) return 'support_platform';
  if (name.includes('security_audit')) return 'security_service';
  if (name.includes('object_storage')) return 'object_storage';
  if (name.includes('deleted_account')) return 'identity_service';
  return 'account_service';
}

const SYSTEM_TO_CATEGORY = {
  account_service: 'USER_PROFILE',
  search_service: 'SEARCH_INDEX_ENTRY',
  analytics_platform: 'ANALYTICS_PROFILE',
  backup_service: 'BACKUP_ARCHIVE',
  integration_service: 'ACTIVE_DATA_FLOW',
  export_service: 'USER_EXPORT',
  marketing_platform: 'MARKETING_PROFILE',
  support_platform: 'SUPPORT_MESSAGE',
  security_service: 'SECURITY_AUDIT_LOG',
  identity_service: 'ACCOUNT_TOMBSTONE',
  object_storage: 'USER_EXPORT',
};

/**
 * Extract records from a PNG screenshot via LLM vision.
 */
export async function extractFromImage(evidenceFilePath, fileId, ctx, auditAt) {
  const cacheKey = `${fileId}::${ctx.userId}`;
  if (_cache.has(cacheKey)) return _cache.get(cacheKey);

  const absPath = path.join(DATASET_DIR, evidenceFilePath);
  const primarySystemId = classifyScreenshot(evidenceFilePath);
  const dataCategory = SYSTEM_TO_CATEGORY[primarySystemId] || 'USER_PROFILE';

  const prompt = `You are a data privacy auditor examining an admin console screenshot.

Look for any records, entries, or data belonging to a user with these identifiers:
- user_id: ${ctx.userId}
- emails: ${[...ctx.allEmails].join(', ')}
- phones: ${[...ctx.allPhones].join(', ')}
- names: ${[...ctx.nameVariants].join(', ')}

For each user record visible in the screenshot, return a JSON object:
{
  "records": [
    {
      "resource_id": "the record ID shown (e.g. account_123, search_456)",
      "system_id": "${primarySystemId}",
      "data_category": "${dataCategory}",
      "state": "PRESENT or ABSENT or REDACTED or ANONYMIZED or ACTIVE or DISABLED or BLOCKED",
      "pii_visible": true or false
    }
  ]
}

If no records for this user are visible, return {"records": []}.
If a data flow/integration is shown, note if it is ACTIVE or DISABLED.
If a backup is shown, note if restore access is ACTIVE or BLOCKED.`;

  const llm = getLLMClient();
  let records = [];

  try {
    let imageBuffer;
    try {
      imageBuffer = readFileSync(absPath);
    } catch {
      _cache.set(cacheKey, []);
      return [];
    }

    const base64Data = imageBuffer.toString('base64');
    const raw = await llm.extractFromImage(base64Data, 'image/png', prompt);

    // Parse JSON from response
    const match = raw.match(/\{[\s\S]*\}/);
    if (match) {
      const parsed = JSON.parse(match[0]);
      records = Array.isArray(parsed.records) ? parsed.records : [];
    }
  } catch (e) {
    console.warn(`[imageReader] LLM vision failed for ${fileId}: ${e.message}`);
    records = [];
  }

  const results = records
    .filter(r => r.resource_id)
    .map(r => ({
      resourceId: r.resource_id,
      systemId: r.system_id || primarySystemId,
      dataCategory: r.data_category || dataCategory,
      state: r.state || 'PRESENT',
      evidenceId: fileId,
      identifyingFields: r.pii_visible ? { visible: true } : {},
    }));

  _cache.set(cacheKey, results);
  return results;
}
