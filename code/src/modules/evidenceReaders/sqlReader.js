/**
 * src/modules/evidenceReaders/sqlReader.js
 *
 * Parse SQLite-compatible SQL snapshot files.
 * Loads the SQL into an in-memory SQLite DB, then queries for records
 * associated with any of the user's identifiers.
 */

import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';

const _dbCache = new Map();

function getDb(filePath) {
  if (_dbCache.has(filePath)) return _dbCache.get(filePath);

  const sql = readFileSync(filePath, 'utf8');
  const db = new Database(':memory:');

  db.pragma('journal_mode = WAL');
  try {
    db.exec(sql);
  } catch {
    const statements = sql.split(';').map(s => s.trim()).filter(s => s.length > 0);
    for (const stmt of statements) {
      try { db.exec(stmt + ';'); } catch {}
    }
  }

  _dbCache.set(filePath, db);
  return db;
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

export function extractFromSQL(evidenceFilePath, fileId, ctx, auditAt) {
  const absPath = path.join(DATASET_DIR, evidenceFilePath);
  const records = [];

  let db;
  try {
    db = getDb(absPath);
  } catch (e) {
    console.warn(`[sqlReader] Failed to load ${evidenceFilePath}: ${e.message}`);
    return records;
  }

  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();

  for (const { name: tableName } of tables) {
    let rows;
    try {
      rows = db.prepare(`SELECT * FROM "${tableName}"`).all();
    } catch {
      continue;
    }

    for (const row of rows) {
      const resourceId = row.resource_id || row.id;
      if (!resourceId) continue;

      // Check matching identity
      let matches = false;
      if (row.subject_reference === ctx.userId) matches = true;
      if (row.customer_reference === ctx.userId) matches = true;
      if (row.user_id === ctx.userId) matches = true;

      const emailVal = row.email || row.owner_email || row.customer_email || row.requester_email;
      if (emailVal && ctx.allEmails.has(emailVal.toLowerCase().trim())) matches = true;

      const phoneVal = row.phone || row.owner_phone || row.requester_phone;
      if (phoneVal && ctx.allPhones.has(phoneVal.trim())) matches = true;

      if (row.email_hash && ctx.emailHashes.has(row.email_hash)) matches = true;

      if (!matches) continue;

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
  }

  return records;
}
