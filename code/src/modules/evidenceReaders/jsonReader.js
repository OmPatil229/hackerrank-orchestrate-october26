/**
 * src/modules/evidenceReaders/jsonReader.js
 *
 * Parse JSON evidence files (snapshot bundles, service exports, analytics reports,
 * connector configs, export manifests, security ledgers).
 */

import { readFileSync } from 'fs';
import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';

// Cache: filePath -> parsed JSON
const _cache = new Map();

function loadJSON(filePath) {
  if (_cache.has(filePath)) return _cache.get(filePath);
  const data = JSON.parse(readFileSync(filePath, 'utf8'));
  _cache.set(filePath, data);
  return data;
}

/** Infer system_id and data_category from field names and resource_id prefix */
function inferSystemInfo(dataStore, collection, resourceId) {
  const ds = (dataStore || '').toLowerCase();
  const col = (collection || '').toLowerCase();
  const rid = (resourceId || '').toLowerCase();

  if (ds.includes('account_service') || col.includes('customer_profile')) {
    return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
  }
  if (ds.includes('search_service') || col.includes('search')) {
    return { systemId: 'search_service', dataCategory: 'SEARCH_INDEX_ENTRY' };
  }
  if (ds.includes('analytics') || col.includes('analytics')) {
    return { systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE' };
  }
  if (ds.includes('support') || col.includes('support')) {
    return { systemId: 'support_platform', dataCategory: 'SUPPORT_MESSAGE' };
  }
  if (ds.includes('export') || col.includes('export')) {
    return { systemId: 'export_service', dataCategory: 'USER_EXPORT' };
  }
  if (ds.includes('marketing') || col.includes('marketing')) {
    return { systemId: 'marketing_platform', dataCategory: 'MARKETING_PROFILE' };
  }
  if (ds.includes('backup') || col.includes('backup')) {
    return { systemId: 'backup_service', dataCategory: 'BACKUP_ARCHIVE' };
  }
  if (ds.includes('security') || col.includes('security_audit')) {
    return { systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' };
  }
  if (ds.includes('identity') || col.includes('deleted_customer')) {
    return { systemId: 'identity_service', dataCategory: 'ACCOUNT_TOMBSTONE' };
  }
  if (ds.includes('integration') || col.includes('connector') || col.includes('data_flow')) {
    return { systemId: 'integration_service', dataCategory: 'ACTIVE_DATA_FLOW' };
  }

  // Fallback from resource_id prefix
  if (rid.startsWith('account_')) return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
  if (rid.startsWith('search_')) return { systemId: 'search_service', dataCategory: 'SEARCH_INDEX_ENTRY' };
  if (rid.startsWith('analytics_')) return { systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE' };
  if (rid.startsWith('support_')) return { systemId: 'support_platform', dataCategory: 'SUPPORT_MESSAGE' };
  if (rid.startsWith('export_')) return { systemId: 'export_service', dataCategory: 'USER_EXPORT' };
  if (rid.startsWith('backup_')) return { systemId: 'backup_service', dataCategory: 'BACKUP_ARCHIVE' };
  if (rid.startsWith('tombstone_')) return { systemId: 'identity_service', dataCategory: 'ACCOUNT_TOMBSTONE' };
  if (rid.startsWith('audit_record_')) return { systemId: 'security_service', dataCategory: 'SECURITY_AUDIT_LOG' };
  if (rid.startsWith('data_flow_')) return { systemId: 'integration_service', dataCategory: 'ACTIVE_DATA_FLOW' };

  return { systemId: 'account_service', dataCategory: 'USER_PROFILE' };
}

/** Check if a record object matches the user's identity context */
function recordMatchesCtx(rec, ctx) {
  if (!rec || typeof rec !== 'object') return false;
  if (rec.customer_reference === ctx.userId) return true;
  if (rec.user_id === ctx.userId) return true;
  if (rec.subject_reference === ctx.userId) return true;
  if (rec.email && ctx.allEmails.has(rec.email.toLowerCase())) return true;
  if (rec.email_hash && ctx.emailHashes.has(rec.email_hash)) return true;
  if (rec.phone && ctx.allPhones.has(rec.phone.trim())) return true;
  // Support document: search for email in nested document field
  if (rec.document) {
    const doc = rec.document;
    if (doc.email && ctx.allEmails.has(doc.email.toLowerCase())) return true;
    if (doc.email_hash && ctx.emailHashes.has(doc.email_hash)) return true;
    if (doc.customer_reference === ctx.userId) return true;
  }
  return false;
}

/** Determine state of a record */
function determineState(rec, dataCategory) {
  if (!rec) return 'PRESENT';

  // Tombstone check
  if (dataCategory === 'ACCOUNT_TOMBSTONE') {
    const hasAnyPii = rec.name || rec.email || rec.phone || rec.email_hash;
    return hasAnyPii ? 'PRESENT' : 'REDACTED';
  }

  // Analytics: if user_id is null and no personal info → anonymized
  if (dataCategory === 'ANALYTICS_PROFILE') {
    if (rec.user_id === null && !rec.email && !rec.phone) return 'ANONYMIZED';
  }

  // Support: check if PII fields redacted
  if (dataCategory === 'SUPPORT_MESSAGE') {
    const hasExposedPii = rec.customer_email || rec.customer_name || rec.customer_phone;
    if (!hasExposedPii && rec.status === 'REDACTED') return 'REDACTED';
  }

  // Integration / data flow: check if active
  if (dataCategory === 'ACTIVE_DATA_FLOW') {
    if (rec.status === 'ACTIVE' || rec.enabled === true) return 'ACTIVE';
    if (rec.status === 'DISABLED' || rec.enabled === false) return 'DISABLED';
  }

  if (rec.account_status === 'DELETED') return 'ABSENT';
  return 'PRESENT';
}

/**
 * Extract user records from a JSON evidence file.
 *
 * Handles:
 * - customer_data_snapshot_bundle: {snapshots: [{data_store, collection, records[]}]}
 * - service_resource_export: {resources: [{resource_id, ...}]}
 * - customer_export_manifest: {exports: [...]}
 * - security_audit_ledger: {entries: [...]}
 * - connector_configurations: {connectors: [...]}
 * - customer_analytics_report: {records: [...]}
 */
export function extractFromJSON(evidenceFilePath, fileId, ctx, auditAt) {
  const absPath = path.join(DATASET_DIR, evidenceFilePath);
  const records = [];

  let data;
  try {
    data = loadJSON(absPath);
  } catch (e) {
    console.warn(`[jsonReader] Failed to load ${evidenceFilePath}: ${e.message}`);
    return records;
  }

  // --- customer_data_snapshot_bundle ---
  if (data.snapshots && Array.isArray(data.snapshots)) {
    for (const snap of data.snapshots) {
      const capturedAt = snap.captured_at ? new Date(snap.captured_at) : null;
      if (capturedAt && capturedAt > auditAt) continue;

      const dataStore = snap.data_store || '';
      const collection = snap.collection || '';

      for (const rec of (snap.records || [])) {
        if (!recordMatchesCtx(rec, ctx)) continue;

        const resourceId = rec.resource_id || rec.id;
        if (!resourceId) continue;

        const { systemId, dataCategory } = inferSystemInfo(dataStore, collection, resourceId);
        const state = determineState(rec, dataCategory);

        if (state === 'ABSENT') continue;

        const identifyingFields = {};
        if (rec.full_name) identifyingFields.full_name = rec.full_name;
        if (rec.email) identifyingFields.email = rec.email;
        if (rec.phone) identifyingFields.phone = rec.phone;
        if (rec.name) identifyingFields.name = rec.name;
        if (rec.email_hash) identifyingFields.email_hash = rec.email_hash;

        // For ANONYMIZED / REDACTED: only include if still has PII
        records.push({ resourceId, systemId, dataCategory, state, evidenceId: fileId, identifyingFields });
      }
    }
  }

  // --- service_resource_export ---
  if (data.resources && Array.isArray(data.resources)) {
    for (const res of data.resources) {
      if (!recordMatchesCtx(res, ctx)) continue;
      const resourceId = res.resource_id;
      if (!resourceId) continue;

      const { systemId, dataCategory } = inferSystemInfo(
        res.origin_system || res.system || '',
        res.collection || res.type || '',
        resourceId
      );
      const state = determineState(res, dataCategory);
      if (state === 'ABSENT') continue;

      records.push({
        resourceId, systemId, dataCategory, state, evidenceId: fileId,
        identifyingFields: {}
      });
    }
  }

  // --- connector_configurations ---
  if (data.connectors && Array.isArray(data.connectors)) {
    for (const conn of data.connectors) {
      if (!recordMatchesCtx(conn, ctx)) {
        // Also check by email in connection string or references
        const connStr = JSON.stringify(conn).toLowerCase();
        const hasRef = [...ctx.allEmails].some(e => connStr.includes(e)) ||
          connStr.includes(ctx.userId.toLowerCase());
        if (!hasRef) continue;
      }
      const resourceId = conn.connector_id || conn.id || conn.resource_id;
      if (!resourceId) continue;

      const state = (conn.status === 'ACTIVE' || conn.enabled) ? 'ACTIVE' : 'DISABLED';
      records.push({
        resourceId,
        systemId: 'integration_service',
        dataCategory: 'ACTIVE_DATA_FLOW',
        state,
        evidenceId: fileId,
        identifyingFields: {}
      });
    }
  }

  // --- customer_export_jobs / export manifests ---
  if (data.exports && Array.isArray(data.exports)) {
    for (const exp of data.exports) {
      if (!recordMatchesCtx(exp, ctx)) continue;
      const resourceId = exp.export_id || exp.resource_id || exp.id;
      if (!resourceId) continue;
      const state = exp.status === 'DELETED' ? 'ABSENT' : 'PRESENT';
      if (state === 'ABSENT') continue;
      records.push({
        resourceId, systemId: 'export_service', dataCategory: 'USER_EXPORT',
        state: 'PRESENT', evidenceId: fileId, identifyingFields: {}
      });
    }
  }

  // --- security_audit_ledger ---
  if (data.entries && Array.isArray(data.entries)) {
    for (const entry of data.entries) {
      if (!recordMatchesCtx(entry, ctx)) {
        const ref = entry.subject_reference || entry.user_id || '';
        if (ref !== ctx.userId) continue;
      }
      const resourceId = entry.resource_id || entry.audit_id;
      if (!resourceId) continue;
      records.push({
        resourceId,
        systemId: 'security_service',
        dataCategory: 'SECURITY_AUDIT_LOG',
        state: 'PRESENT',
        evidenceId: fileId,
        identifyingFields: {}
      });
    }
  }

  // --- customer_analytics_report ---
  if (data.records && Array.isArray(data.records)) {
    for (const rec of data.records) {
      if (!recordMatchesCtx(rec, ctx)) continue;
      const resourceId = rec.resource_id || rec.analytics_id;
      if (!resourceId) continue;
      const state = determineState(rec, 'ANALYTICS_PROFILE');
      if (state === 'ABSENT') continue;
      records.push({
        resourceId, systemId: 'analytics_platform', dataCategory: 'ANALYTICS_PROFILE',
        state, evidenceId: fileId, identifyingFields: {}
      });
    }
  }

  return records;
}
