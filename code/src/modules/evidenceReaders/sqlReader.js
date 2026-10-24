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

// Cache parsed databases: filePath -> Database instance
const _dbCache = new Map();

function getDb(filePath) {
  if (_dbCache.has(filePath)) return _dbCache.get(filePath);

  const sql = readFileSync(filePath, 'utf8');
  const db = new Database(':memory:');

  // SQLite strict mode workarounds for the generated SQL
  db.pragma('journal_mode = WAL');
  try {
    db.exec(sql);
  } catch (e) {
    // Some files may have CHECK(json_valid()) constraints — ignore parse errors
    // and try to import statement by statement
    const statements = sql.split(';').map(s => s.trim()).filter(s => s.length > 0);
    for (const stmt of statements) {
      try { db.exec(stmt + ';'); } catch {}
    }
  }

  _dbCache.set(filePath, db);
  return db;
}

/**
 * Check if a JSON record blob matches any of the user's identifiers.
 */
function matchesIdentity(recordJson, ctx) {
  if (!recordJson) return false;
  try {
    const rec = typeof recordJson === 'string' ? JSON.parse(recordJson) : recordJson;
    const userId = ctx.userId;

    // user_id / subject_reference / customer_reference
    if (rec.subject_reference === userId) return true;
    if (rec.customer_reference === userId) return true;
    if (rec.user_id === userId) return true;

    // email
    if (rec.email && ctx.allEmails.has(rec.email.toLowerCase())) return true;

    // email_hash
    if (rec.email_hash && ctx.emailHashes.has(rec.email_hash)) return true;

    // phone
    if (rec.phone && ctx.allPhones.has(rec.phone.trim())) return true;

    return false;
  } catch {
    return false;
  }
}

/**
 * Determine the state of a record from its JSON blob.
 * Returns: PRESENT | REDACTED | ANONYMIZED
 */
function determineRecordState(recordJson, ctx) {
  try {
    const rec = typeof recordJson === 'string' ? JSON.parse(recordJson) : recordJson;

    // Tombstone: all PII fields null → redacted; some PII still present → exposed
    const hasPii = (
      (rec.name && rec.name !== null) ||
      (rec.email && rec.email !== null) ||
      (rec.phone && rec.phone !== null) ||
      (rec.email_hash && rec.email_hash !== null)
    );

    if (rec.account_status === 'DELETED') {
      return hasPii ? 'PRESENT_WITH_PII' : 'REDACTED';
    }

    // Analytics anonymized: user_id null or no user reference
    if (rec.user_id === null && rec.subject_reference === undefined) {
      return 'ANONYMIZED';
    }

    return 'PRESENT';
  } catch {
    return 'PRESENT';
  }
}

/**
 * Map a table/collection name to a system_id and data_category.
 */
function inferSystemInfo(tableName, collectionName, resourceId) {
  const col = (collectionName || '').toLowerCase();
  const tbl = (tableName || '').toLowerCase();
  const rid = (resourceId || '').toLowerCase();

  if (col.includes('security_audit') || rid.startsWith('audit_record_')) {
    return { systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' };
  }
  if (col.includes('deleted_customer') || rid.startsWith('tombstone_')) {
    return { systemId: 'identity_service', dataCategory: 'ACCOUNT_TOMBSTONE' };
  }
  if (col.includes('customer_profile') || col.includes('account')) {
    return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
  }
  if (col.includes('search')) {
    return { systemId: 'search_service', dataCategory: 'SEARCH_INDEX_ENTRY' };
  }
  if (col.includes('analytics')) {
    return { systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE' };
  }
  if (col.includes('support')) {
    return { systemId: 'support_platform', dataCategory: 'SUPPORT_MESSAGE' };
  }
  if (col.includes('export')) {
    return { systemId: 'export_service', dataCategory: 'USER_EXPORT' };
  }
  if (col.includes('marketing')) {
    return { systemId: 'marketing_platform', dataCategory: 'MARKETING_PROFILE' };
  }
  if (col.includes('backup')) {
    return { systemId: 'backup_service', dataCategory: 'BACKUP_ARCHIVE' };
  }
  if (tbl.includes('failover') || tbl.includes('replica')) {
    if (col.includes('security') || rid.startsWith('audit_record_')) {
      return { systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' };
    }
    return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
  }

  // Infer from resource_id prefix
  if (rid.startsWith('account_')) return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
  if (rid.startsWith('search_')) return { systemId: 'search_service', dataCategory: 'SEARCH_INDEX_ENTRY' };
  if (rid.startsWith('analytics_')) return { systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE' };
  if (rid.startsWith('support_')) return { systemId: 'support_platform', dataCategory: 'SUPPORT_MESSAGE' };
  if (rid.startsWith('export_')) return { systemId: 'export_service', dataCategory: 'USER_EXPORT' };
  if (rid.startsWith('backup_')) return { systemId: 'backup_service', dataCategory: 'BACKUP_ARCHIVE' };
  if (rid.startsWith('tombstone_')) return { systemId: 'identity_service', dataCategory: 'ACCOUNT_TOMBSTONE' };
  if (rid.startsWith('audit_record_')) return { systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' };
  if (rid.startsWith('data_flow_')) return { systemId: 'integration_service', dataCategory: 'ACTIVE_DATA_FLOW' };

  return { systemId: 'unknown_service', dataCategory: 'USER_PROFILE' };
}

/**
 * Extract user records from an SQL evidence file.
 *
 * @param {string} evidenceFilePath - relative path from dataset root
 * @param {string} fileId - evidence file_id for citation
 * @param {object} ctx - IdentityContext
 * @param {Date} auditAt - cutoff
 * @returns {Array} ResourceState objects
 */
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

  // Get all table names
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

      // Try to get record_json column
      const recordJson = row.record_json || null;
      const collectionName = row.collection_name || row.collection || '';

      let matches = false;
      if (recordJson) {
        matches = matchesIdentity(recordJson, ctx);
      } else {
        // Check direct columns
        const email = row.email || row.full_name ? false : null;
        if (row.subject_reference === ctx.userId) matches = true;
        if (row.customer_reference === ctx.userId) matches = true;
        if (row.user_id === ctx.userId) matches = true;
        if (row.email && ctx.allEmails.has(row.email.toLowerCase())) matches = true;
        if (row.email_hash && ctx.emailHashes.has(row.email_hash)) matches = true;
        if (row.phone && ctx.allPhones.has(row.phone.trim())) matches = true;
      }

      if (!matches) continue;

      const { systemId, dataCategory } = inferSystemInfo(tableName, collectionName, resourceId);

      // Determine state
      let state = 'PRESENT';
      if (recordJson) {
        const rawState = determineRecordState(recordJson, ctx);
        if (rawState === 'REDACTED') state = 'REDACTED';
        else if (rawState === 'ANONYMIZED') state = 'ANONYMIZED';
        else if (rawState === 'PRESENT_WITH_PII') state = 'PRESENT';
        else state = 'PRESENT';
      }

      // Check account_status
      if (row.account_status === 'DELETED' || (recordJson && recordJson.includes('"DELETED"'))) {
        // Still present as tombstone if it's identity_service
        if (dataCategory === 'ACCOUNT_TOMBSTONE') {
          // state already determined above
        } else {
          state = 'ABSENT';
          continue; // Record is deleted — don't flag
        }
      }

      // Skip absent non-tombstone records
      if (state === 'ABSENT') continue;

      // Extract identifying fields still exposed
      const identifyingFields = {};
      if (recordJson) {
        try {
          const rec = JSON.parse(recordJson);
          if (rec.name) identifyingFields.name = rec.name;
          if (rec.email) identifyingFields.email = rec.email;
          if (rec.phone) identifyingFields.phone = rec.phone;
          if (rec.email_hash) identifyingFields.email_hash = rec.email_hash;
          if (rec.full_name) identifyingFields.full_name = rec.full_name;
        } catch {}
      }

      records.push({
        resourceId,
        systemId,
        dataCategory,
        state,
        evidenceId: fileId,
        identifyingFields,
        sourceTable: tableName,
      });
    }
  }

  return records;
}
