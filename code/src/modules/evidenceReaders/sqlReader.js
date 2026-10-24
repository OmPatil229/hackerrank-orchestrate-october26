/**
 * src/modules/evidenceReaders/sqlReader.js
 *
 * Pure JavaScript SQLite snapshot parser.
 * Reads SQL dumps without native binary dependencies (safe across WSL/Linux/macOS/Windows).
 */

import { readFileSync } from 'fs';
import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';

const _cache = new Map();

/** Parse SQL row values, respecting quoted strings with commas and escaped quotes */
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
          i++; // skip escaped quote
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

/** Check if a line string mentions any user identifier */
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

export function extractFromSQL(evidenceFilePath, fileId, ctx, auditAt) {
  const absPath = path.join(DATASET_DIR, evidenceFilePath);
  const records = [];

  let sqlContent;
  if (_cache.has(absPath)) {
    sqlContent = _cache.get(absPath);
  } else {
    try {
      sqlContent = readFileSync(absPath, 'utf8');
      _cache.set(absPath, sqlContent);
    } catch (e) {
      console.warn(`[sqlReader] Failed to load ${evidenceFilePath}: ${e.message}`);
      return records;
    }
  }

  // 1. Extract table column definitions
  const tableColumns = new Map();
  const createTableRegex = /CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+["']?([a-zA-Z0-9_]+)["']?\s*\(([\s\S]*?)\);/gi;
  let match;
  while ((match = createTableRegex.exec(sqlContent)) !== null) {
    const tableName = match[1];
    const colDefStr = match[2];
    const cols = [];
    const lines = colDefStr.split(',');
    for (const colLine of lines) {
      const colNameMatch = colLine.trim().match(/^["']?([a-zA-Z0-9_]+)["']?\s+/);
      if (colNameMatch && !['CHECK', 'PRIMARY', 'FOREIGN', 'UNIQUE', 'CONSTRAINT'].includes(colNameMatch[1].toUpperCase())) {
        cols.push(colNameMatch[1].toLowerCase());
      }
    }
    tableColumns.set(tableName, cols);
  }

  // 2. Parse INSERT statements
  const insertRegex = /INSERT\s+INTO\s+["']?([a-zA-Z0-9_]+)["']?(?:\s*\(([^)]+)\))?\s+VALUES\s*\(([\s\S]*?)\);/gi;
  while ((match = insertRegex.exec(sqlContent)) !== null) {
    const tableName = match[1];
    const valStr = match[3];

    // Quick filter: check if line mentions user identifiers
    if (!lineMatchesCtx(match[0], ctx)) continue;

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
