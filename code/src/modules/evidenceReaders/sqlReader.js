/**
 * src/modules/evidenceReaders/sqlReader.js
 *
 * Fast line-by-line SQLite snapshot parser without regex backtracking.
 */

import { readFileSync } from 'fs';
import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';

// Cache: absPath -> { lines: string[], tableColumns: Map<string, string[]> }
const _fileCache = new Map();

function getCachedSqlFile(absPath) {
  if (_fileCache.has(absPath)) return _fileCache.get(absPath);

  let content;
  try {
    content = readFileSync(absPath, 'utf8');
  } catch (e) {
    console.warn(`[sqlReader] Failed to read ${absPath}: ${e.message}`);
    return null;
  }

  const lines = content.split('\n');
  const tableColumns = new Map();

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('CREATE TABLE')) {
      const nameMatch = trimmed.match(/CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+["']?([a-zA-Z0-9_]+)["']?\s*\((.*)\)/i);
      if (nameMatch) {
        const tblName = nameMatch[1];
        const colDef = nameMatch[2];
        const cols = colDef.split(',').map(c => {
          const m = c.trim().match(/^["']?([a-zA-Z0-9_]+)["']?/);
          return m ? m[1].toLowerCase() : null;
        }).filter(c => c && !['check', 'primary', 'foreign', 'unique', 'constraint'].includes(c));
        tableColumns.set(tblName, cols);
      }
    }
  }

  const cached = { lines, tableColumns };
  _fileCache.set(absPath, cached);
  return cached;
}

function parseSqlValues(valStr) {
  const values = [];
  let cur = '';
  let inQuotes = false;
  let quoteChar = '';

  for (let i = 0; i < valStr.length; i++) {
    const ch = valStr[i];
    if (inQuotes) {
      if (ch === quoteChar) {
        if (valStr[i + 1] === quoteChar) {
          cur += quoteChar;
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += ch;
      }
    } else {
      if (ch === "'" || ch === '"') {
        inQuotes = true;
        quoteChar = ch;
      } else if (ch === ',') {
        values.push(cleanVal(cur));
        cur = '';
      } else {
        cur += ch;
      }
    }
  }
  values.push(cleanVal(cur));
  return values;
}

function cleanVal(v) {
  const trimmed = v.trim();
  if (trimmed.toUpperCase() === 'NULL') return null;
  return trimmed;
}

function inferCategoryFromRid(rid, tableName) {
  const r = (rid || '').toLowerCase();
  const t = (tableName || '').toLowerCase();

  if (r.startsWith('account_') || t.includes('profile')) return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
  if (r.startsWith('search_') || t.includes('search')) return { systemId: 'search_service', dataCategory: 'SEARCH_INDEX_ENTRY' };
  if (r.startsWith('analytics_') || t.includes('analytics')) return { systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE' };
  if (r.startsWith('support_attachment_')) return { systemId: 'support_platform', dataCategory: 'SUPPORT_ATTACHMENT' };
  if (r.startsWith('support_') || t.includes('support')) return { systemId: 'support_platform', dataCategory: 'SUPPORT_MESSAGE' };
  if (r.startsWith('export_') || t.includes('export')) return { systemId: 'export_service', dataCategory: 'USER_EXPORT' };
  if (r.startsWith('backup_') || t.includes('backup')) return { systemId: 'backup_service', dataCategory: 'BACKUP_ARCHIVE' };
  if (r.startsWith('audit_record_') || t.includes('security')) return { systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' };
  if (r.startsWith('data_flow_') || t.includes('connector')) return { systemId: 'integration_service', dataCategory: 'ACTIVE_DATA_FLOW' };
  if (r.startsWith('tombstone_') || t.includes('deleted_customer')) return { systemId: 'identity_service', dataCategory: 'ACCOUNT_TOMBSTONE' };
  return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
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
    const norm = phone.replace(/[\s\-\(\)\+]/g, '');
    if (norm.length > 6 && lower.replace(/[\s\-\(\)\+]/g, '').includes(norm.toLowerCase())) return true;
  }
  return false;
}

export function extractFromSQL(evidenceFilePath, fileId, ctx, auditAt) {
  const absPath = path.join(DATASET_DIR, evidenceFilePath);
  const records = [];

  const cached = getCachedSqlFile(absPath);
  if (!cached) return records;

  const { lines, tableColumns } = cached;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('INSERT INTO')) continue;
    if (!lineMatchesCtx(trimmed, ctx)) continue;

    // Parse: INSERT INTO [table] VALUES(...)
    const match = trimmed.match(/INSERT\s+INTO\s+["']?([a-zA-Z0-9_]+)["']?(?:\s*\([^)]+\))?\s+VALUES\s*\(([\s\S]*)\);?/i);
    if (!match) continue;

    const tableName = match[1];
    const valStr = match[2];

    const cols = tableColumns.get(tableName) || [];
    const vals = parseSqlValues(valStr);

    const row = {};
    for (let i = 0; i < vals.length; i++) {
      const colName = cols[i] || `col_${i}`;
      row[colName] = vals[i];
    }

    const resourceId = row.resource_id || row.id || vals[0];
    if (!resourceId) continue;

    const { systemId, dataCategory } = inferCategoryFromRid(resourceId, tableName);
    let state = 'PRESENT';

    if (dataCategory === 'BACKUP_ARCHIVE') {
      const allowed = row.restore_allowed === 1 || row.restore_allowed === '1' || row.restore_allowed === true;
      state = allowed ? 'ACTIVE' : 'BLOCKED';
    } else if (dataCategory === 'ACTIVE_DATA_FLOW') {
      const enabled = row.enabled === 1 || row.enabled === '1' || row.enabled === true;
      state = enabled ? 'ACTIVE' : 'DISABLED';
    } else if (dataCategory === 'ANALYTICS_PROFILE') {
      const hasPii = row.email || row.phone || row.email_hash;
      state = hasPii ? 'PRESENT' : 'ANONYMIZED';
    } else if (dataCategory === 'ACCOUNT_TOMBSTONE') {
      const hasPii = row.full_name || row.email || row.phone || row.email_hash;
      state = hasPii ? 'PRESENT' : 'REDACTED';
    } else if (row.account_status === 'DELETED') {
      state = 'ABSENT';
    } else if (tableName.includes('replica') && row.account_status === 'ACTIVE') {
      state = 'PRESENT';
    }

    records.push({
      resourceId,
      systemId,
      dataCategory,
      state,
      evidenceId: fileId,
      identifyingFields: {},
      sourceTable: tableName,
    });
  }

  return records;
}
