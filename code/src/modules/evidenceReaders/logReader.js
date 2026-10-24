/**
 * src/modules/evidenceReaders/logReader.js
 *
 * Parse log evidence files (structured JSON logs, syslog archives,
 * service event streams, resource lookup traces, notification delivery logs).
 *
 * Strategy: read line-by-line, grep for user identifiers, then extract
 * structured event data from JSON-formatted lines.
 */

import { readFileSync } from 'fs';
import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';

// Cache: filePath -> lines[]
const _cache = new Map();

function loadLines(filePath) {
  if (_cache.has(filePath)) return _cache.get(filePath);
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split('\n').filter(l => l.trim().length > 0);
  _cache.set(filePath, lines);
  return lines;
}

/** Try to parse a line as JSON; return null if not JSON */
function tryParseJSON(line) {
  const start = line.indexOf('{');
  if (start === -1) return null;
  try {
    return JSON.parse(line.slice(start));
  } catch {
    // Try to find first valid JSON object substring
    try {
      const match = line.match(/\{.*\}/);
      if (match) return JSON.parse(match[0]);
    } catch {}
    return null;
  }
}

/** Check if a line string mentions any of the user's identifiers */
function lineMatchesCtx(line, ctx) {
  const lower = line.toLowerCase();

  if (lower.includes(ctx.userId.toLowerCase())) return true;
  for (const email of ctx.allEmails) {
    if (lower.includes(email.toLowerCase())) return true;
  }
  for (const hash of ctx.emailHashes) {
    if (lower.includes(hash.toLowerCase())) return true;
  }
  for (const phone of ctx.allPhones) {
    // Normalise phone: remove spaces/dashes for matching
    const norm = phone.replace(/[\s\-\(\)]/g, '');
    if (norm.length > 6 && lower.replace(/[\s\-\(\)]/g, '').includes(norm.toLowerCase())) return true;
  }
  return false;
}

/** Infer resource category from resource_id or event fields */
function inferResource(rec, line) {
  const rid = (rec.resource_id || rec.resourceId || '').toLowerCase();
  const evt = (rec.event_type || rec.eventType || rec.action || '').toLowerCase();
  const src = (rec.source_system || rec.service || '').toLowerCase();

  if (rid.startsWith('search_') || src.includes('search')) {
    return { resourceId: rid || 'search_unknown', systemId: 'search_service', dataCategory: 'SEARCH_INDEX_ENTRY' };
  }
  if (rid.startsWith('analytics_') || src.includes('analytics')) {
    return { resourceId: rid, systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE' };
  }
  if (rid.startsWith('support_') || src.includes('support')) {
    return { resourceId: rid, systemId: 'support_platform', dataCategory: 'SUPPORT_MESSAGE' };
  }
  if (rid.startsWith('export_') || src.includes('export')) {
    return { resourceId: rid, systemId: 'export_service', dataCategory: 'USER_EXPORT' };
  }
  if (rid.startsWith('backup_') || src.includes('backup')) {
    return { resourceId: rid, systemId: 'backup_service', dataCategory: 'BACKUP_ARCHIVE' };
  }
  if (rid.startsWith('audit_record_') || src.includes('security')) {
    return { resourceId: rid, systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' };
  }
  if (rid.startsWith('data_flow_') || src.includes('integration')) {
    return { resourceId: rid, systemId: 'integration_service', dataCategory: 'ACTIVE_DATA_FLOW' };
  }
  if (rid.startsWith('account_') || src.includes('account')) {
    return { resourceId: rid, systemId: 'account_service', dataCategory: 'USER_PROFILE' };
  }
  if (rid.startsWith('email_delivery_')) {
    return { resourceId: rid, systemId: 'email_delivery_service', dataCategory: 'EMAIL_DELIVERY_LOG' };
  }

  // Fallback: extract resource_id from line if not in parsed JSON
  const ridMatch = line.match(/\b(account|search|analytics|support|export|backup|audit_record|data_flow|tombstone|email_delivery)_\w+/i);
  if (ridMatch) {
    const prefix = ridMatch[1].toLowerCase();
    const found = ridMatch[0];
    const map = {
      account: { systemId: 'account_service', dataCategory: 'USER_PROFILE' },
      search: { systemId: 'search_service', dataCategory: 'SEARCH_INDEX_ENTRY' },
      analytics: { systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE' },
      support: { systemId: 'support_platform', dataCategory: 'SUPPORT_MESSAGE' },
      export: { systemId: 'export_service', dataCategory: 'USER_EXPORT' },
      backup: { systemId: 'backup_service', dataCategory: 'BACKUP_ARCHIVE' },
      audit_record: { systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' },
      data_flow: { systemId: 'integration_service', dataCategory: 'ACTIVE_DATA_FLOW' },
      tombstone: { systemId: 'identity_service', dataCategory: 'ACCOUNT_TOMBSTONE' },
      email_delivery: { systemId: 'email_delivery_service', dataCategory: 'EMAIL_DELIVERY_LOG' },
    };
    const info = map[prefix] || { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
    return { resourceId: found, ...info };
  }

  return null;
}

/**
 * Extract user-relevant events from a log evidence file.
 * Returns resource state entries.
 */
export function extractFromLog(evidenceFilePath, fileId, ctx, auditAt) {
  const absPath = path.join(DATASET_DIR, evidenceFilePath);
  const found = new Map(); // resourceId -> resourceState (latest wins)

  let lines;
  try {
    lines = loadLines(absPath);
  } catch (e) {
    console.warn(`[logReader] Failed to load ${evidenceFilePath}: ${e.message}`);
    return [];
  }

  for (const line of lines) {
    if (!lineMatchesCtx(line, ctx)) continue;

    const rec = tryParseJSON(line);
    const resourceInfo = inferResource(rec || {}, line);
    if (!resourceInfo || !resourceInfo.resourceId) continue;

    const { resourceId, systemId, dataCategory } = resourceInfo;

    // Determine state from event_type
    const eventType = (rec?.event_type || rec?.action || '').toUpperCase();
    let state = 'PRESENT';

    if (['DELETE_RECORD', 'DELETED', 'ACCOUNT_DELETED'].includes(eventType)) state = 'ABSENT';
    else if (['ANONYMIZE_RECORD', 'ANONYMIZED'].includes(eventType)) state = 'ANONYMIZED';
    else if (['REDACT_RECORD', 'REDACTED'].includes(eventType)) state = 'REDACTED';
    else if (['SYNC_RECORD', 'ACTIVE', 'ENABLED'].includes(eventType)) state = 'ACTIVE';
    else if (['DISABLE_DATA_FLOW', 'DISABLED'].includes(eventType)) state = 'DISABLED';
    else if (['BLOCK_RESTORE', 'BLOCKED'].includes(eventType)) state = 'BLOCKED';

    // Only keep non-absent records (we report what's still there)
    if (state !== 'ABSENT') {
      const existing = found.get(resourceId);
      if (!existing || existing.state === 'PRESENT') {
        found.set(resourceId, { resourceId, systemId, dataCategory, state, evidenceId: fileId, identifyingFields: {} });
      }
    }
  }

  return Array.from(found.values());
}
