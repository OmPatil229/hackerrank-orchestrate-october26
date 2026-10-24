/**
 * src/modules/evidenceReaders/logReader.js
 *
 * Parse log evidence files:
 *  1. Pipe-separated handover text (e.g. evidence_03)
 *  2. Key-value service readback logs (e.g. resource_lookup_trace_*.log, evidence_94)
 *  3. Structured JSON observability logs with trace_id correlation (e.g. evidence_06)
 *  4. Syslog & generic text logs
 */

import { readFileSync } from 'fs';
import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';

const _cache = new Map();

function loadLines(filePath) {
  if (_cache.has(filePath)) return _cache.get(filePath);
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split('\n').filter(l => l.trim().length > 0);
  _cache.set(filePath, lines);
  return lines;
}

function tryParseJSON(line) {
  const start = line.indexOf('{');
  if (start === -1) return null;
  try {
    return JSON.parse(line.slice(start));
  } catch {
    const match = line.match(/\{.*\}/);
    if (match) {
      try { return JSON.parse(match[0]); } catch {}
    }
    return null;
  }
}

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
    const norm = phone.replace(/[\s\-\(\)]/g, '');
    if (norm.length > 6 && lower.replace(/[\s\-\(\)]/g, '').includes(norm.toLowerCase())) return true;
  }
  return false;
}

function inferCategoryFromRid(rid) {
  const r = (rid || '').toLowerCase();
  if (r.startsWith('account_')) return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
  if (r.startsWith('search_')) return { systemId: 'search_service', dataCategory: 'SEARCH_INDEX_ENTRY' };
  if (r.startsWith('analytics_')) return { systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE' };
  if (r.startsWith('support_attachment_')) return { systemId: 'support_platform', dataCategory: 'SUPPORT_ATTACHMENT' };
  if (r.startsWith('support_')) return { systemId: 'support_platform', dataCategory: 'SUPPORT_MESSAGE' };
  if (r.startsWith('export_')) return { systemId: 'export_service', dataCategory: 'USER_EXPORT' };
  if (r.startsWith('backup_')) return { systemId: 'backup_service', dataCategory: 'BACKUP_ARCHIVE' };
  if (r.startsWith('audit_record_')) return { systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' };
  if (r.startsWith('data_flow_')) return { systemId: 'integration_service', dataCategory: 'ACTIVE_DATA_FLOW' };
  if (r.startsWith('tombstone_')) return { systemId: 'identity_service', dataCategory: 'ACCOUNT_TOMBSTONE' };
  if (r.startsWith('email_delivery_')) return { systemId: 'email_delivery_service', dataCategory: 'EMAIL_DELIVERY_LOG' };
  return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
}

export function extractFromLog(evidenceFilePath, fileId, ctx, auditAt) {
  const absPath = path.join(DATASET_DIR, evidenceFilePath);
  const found = new Map();

  let lines;
  try {
    lines = loadLines(absPath);
  } catch (e) {
    console.warn(`[logReader] Failed to load ${evidenceFilePath}: ${e.message}`);
    return [];
  }

  // --- Step 1: Handle pipe-separated handovers (e.g. evidence_03) ---
  // Format: - 2026-10-01T12:00:00Z | system_id | resource_id | data_category | status | identifier
  for (const line of lines) {
    if (line.includes('|') && lineMatchesCtx(line, ctx)) {
      const parts = line.split('|').map(s => s.trim().replace(/^-\s*/, ''));
      if (parts.length >= 6) {
        const [, systemId, resourceId, dataCategory, status] = parts;
        let state = 'PRESENT';
        if (status === 'NOT_FOUND') state = 'ABSENT';
        else if (status === 'ANONYMIZED') state = 'ANONYMIZED';
        else if (status === 'REDACTED') state = 'REDACTED';
        else if (status === 'ACTIVE') state = 'ACTIVE';
        else if (status === 'DISABLED') state = 'DISABLED';
        else if (status === 'BLOCKED') state = 'BLOCKED';
        else if (status === 'FOUND' || status === 'IDENTIFIABLE') state = 'PRESENT';

        found.set(resourceId, {
          resourceId, systemId, dataCategory, state, evidenceId: fileId, identifyingFields: {}
        });
      }
    }
  }

  // --- Step 2: Handle structured JSON logs with trace_id correlation ---
  const matchingTraceIds = new Set();
  const eventsByTrace = new Map();

  for (const line of lines) {
    const json = tryParseJSON(line);
    if (!json) continue;

    const traceId = json.trace_id;
    if (traceId) {
      if (!eventsByTrace.has(traceId)) eventsByTrace.set(traceId, []);
      eventsByTrace.get(traceId).push(json);

      if (lineMatchesCtx(line, ctx)) {
        matchingTraceIds.add(traceId);
      }
    }
  }

  for (const traceId of matchingTraceIds) {
    const events = eventsByTrace.get(traceId) || [];
    for (const evt of events) {
      const rid = evt.resource_id;
      if (!rid) continue;

      const { systemId, dataCategory } = inferCategoryFromRid(rid);
      let state = 'PRESENT';

      if (evt.http_status === '404' || evt.rows === '0') {
        state = 'ABSENT';
      } else if (evt.rows === '1' || evt.http_status === '200') {
        if (dataCategory === 'ANALYTICS_PROFILE') {
          const hasPii = evt.email || evt.phone || evt.email_hash || evt.customer_reference;
          state = hasPii ? 'PRESENT' : 'ANONYMIZED';
        } else if (dataCategory === 'SUPPORT_MESSAGE') {
          const hasPii = evt.requester_email || evt.requester_phone;
          state = (evt.status === 'REDACTED' || !hasPii) ? 'REDACTED' : 'PRESENT';
        } else {
          state = 'PRESENT';
        }
      } else if (evt.restore_allowed !== undefined) {
        state = evt.restore_allowed ? 'ACTIVE' : 'BLOCKED';
      } else if (evt.enabled !== undefined) {
        state = evt.enabled ? 'ACTIVE' : 'DISABLED';
      }

      found.set(rid, {
        resourceId: rid, systemId, dataCategory, state, evidenceId: fileId, identifyingFields: {}
      });
    }
  }

  // --- Step 3: Key-value log line parsing (e.g. resource_lookup_trace_*.log) ---
  for (const line of lines) {
    if (!lineMatchesCtx(line, ctx)) continue;
    if (line.includes('|')) continue; // already handled

    const ridMatch = line.match(/\bresource_id=([a-zA-Z0-9_\-]+)/);
    if (!ridMatch) continue;
    const resourceId = ridMatch[1];
    const { systemId, dataCategory } = inferCategoryFromRid(resourceId);

    let state = 'PRESENT';
    if (line.includes('http_status=404') || line.includes('rows=0')) {
      state = 'ABSENT';
    } else if (line.includes('customer_reference=null email=null phone=null')) {
      state = 'ANONYMIZED';
    } else if (line.includes('enabled=false') || line.includes('status=stopped')) {
      state = 'DISABLED';
    } else if (line.includes('enabled=true')) {
      state = 'ACTIVE';
    } else if (line.includes('restore_allowed=false') || line.includes('restore_allowed=0')) {
      state = 'BLOCKED';
    } else if (line.includes('restore_allowed=true') || line.includes('restore_allowed=1')) {
      state = 'ACTIVE';
    } else if (line.includes('status=REDACTED') || (line.includes('requester_name=null requester_email=null'))) {
      state = 'REDACTED';
    }

    found.set(resourceId, {
      resourceId, systemId, dataCategory, state, evidenceId: fileId, identifyingFields: {}
    });
  }

  return Array.from(found.values());
}
