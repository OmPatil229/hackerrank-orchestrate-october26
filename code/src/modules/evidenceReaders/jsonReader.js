/**
 * src/modules/evidenceReaders/jsonReader.js
 *
 * Parse JSON evidence files (snapshot bundles, service exports, analytics reports,
 * connector configs, export manifests, security ledgers).
 */

import { readFileSync } from 'fs';
import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';

const _cache = new Map();

function loadJSON(filePath) {
  if (_cache.has(filePath)) return _cache.get(filePath);
  const data = JSON.parse(readFileSync(filePath, 'utf8'));
  _cache.set(filePath, data);
  return data;
}

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

  // --- 1. service_exports (e.g. service_resource_export_*.json, evidence_92) ---
  if (data.service_exports && typeof data.service_exports === 'object') {
    const se = data.service_exports;

    // account_service
    if (se.account_service?.profile_lookups) {
      for (const item of se.account_service.profile_lookups) {
        const prof = item.profile;
        const matches = prof && (
          (prof.email && ctx.allEmails.has(prof.email.toLowerCase())) ||
          (prof.customer_reference && prof.customer_reference === ctx.userId) ||
          (prof.phone && ctx.allPhones.has(prof.phone.trim())) ||
          (prof.email_hash && ctx.emailHashes.has(prof.email_hash))
        );
        if (matches) {
          records.push({
            resourceId: item.resource_id,
            systemId: 'account_service',
            dataCategory: 'USER_PROFILE',
            state: item.status_code === 404 ? 'ABSENT' : 'PRESENT',
            evidenceId: fileId,
            identifyingFields: prof || {}
          });
        }
      }
    }

    // analytics_platform
    if (se.analytics_platform?.profiles) {
      for (const item of se.analytics_platform.profiles) {
        const matches = (
          (item.email && ctx.allEmails.has(item.email.toLowerCase())) ||
          (item.customer_reference && item.customer_reference === ctx.userId) ||
          (item.phone && ctx.allPhones.has(item.phone.trim())) ||
          (item.email_hash && ctx.emailHashes.has(item.email_hash))
        );
        if (matches) {
          const hasPii = item.email || item.phone || item.email_hash;
          records.push({
            resourceId: item.resource_id,
            systemId: 'analytics_platform',
            dataCategory: 'ANALYTICS_PROFILE',
            state: hasPii ? 'PRESENT' : 'ANONYMIZED',
            evidenceId: fileId,
            identifyingFields: {}
          });
        }
      }
    }

    // backup_service
    if (se.backup_service?.restore_entries) {
      for (const item of se.backup_service.restore_entries) {
        const matches = (
          (item.customer_email && ctx.allEmails.has(item.customer_email.toLowerCase())) ||
          (item.customer_reference && item.customer_reference === ctx.userId)
        );
        if (matches) {
          records.push({
            resourceId: item.resource_id,
            systemId: 'backup_service',
            dataCategory: 'BACKUP_ARCHIVE',
            state: item.restore_allowed ? 'ACTIVE' : 'BLOCKED',
            evidenceId: fileId,
            identifyingFields: {}
          });
        }
      }
    }

    // export_service
    if (se.export_service?.exports) {
      for (const item of se.export_service.exports) {
        const matches = (
          (item.owner_email && ctx.allEmails.has(item.owner_email.toLowerCase())) ||
          (item.customer_reference && item.customer_reference === ctx.userId) ||
          (item.owner_phone && ctx.allPhones.has(item.owner_phone.trim()))
        );
        if (matches) {
          records.push({
            resourceId: item.resource_id,
            systemId: 'export_service',
            dataCategory: 'USER_EXPORT',
            state: 'PRESENT',
            evidenceId: fileId,
            identifyingFields: {}
          });
        }
      }
    }

    // integration_service
    if (se.integration_service?.connectors) {
      for (const item of se.integration_service.connectors) {
        const matches = (
          (item.customer_email && ctx.allEmails.has(item.customer_email.toLowerCase())) ||
          (item.customer_reference && item.customer_reference === ctx.userId)
        );
        if (matches) {
          records.push({
            resourceId: item.resource_id,
            systemId: 'integration_service',
            dataCategory: 'ACTIVE_DATA_FLOW',
            state: item.enabled ? 'ACTIVE' : 'DISABLED',
            evidenceId: fileId,
            identifyingFields: {}
          });
        }
      }
    }

    // search_service
    if (se.search_service?.index_queries) {
      for (const item of se.search_service.index_queries) {
        const docs = item.hits?.documents || [];
        for (const doc of docs) {
          const matches = (
            (doc.email && ctx.allEmails.has(doc.email.toLowerCase())) ||
            (doc.customer_reference && doc.customer_reference === ctx.userId) ||
            (doc.phone && ctx.allPhones.has(doc.phone.trim())) ||
            (doc.email_hash && ctx.emailHashes.has(doc.email_hash))
          );
          if (matches) {
            records.push({
              resourceId: doc.resource_id || item.resource_id,
              systemId: 'search_service',
              dataCategory: 'SEARCH_INDEX_ENTRY',
              state: 'PRESENT',
              evidenceId: fileId,
              identifyingFields: {}
            });
          }
        }
      }
    }

    // security_service
    if (se.security_service?.audit_records || se.security_service?.audit_events) {
      const entries = se.security_service.audit_records || se.security_service.audit_events || [];
      for (const item of entries) {
        const matches = (item.subject_reference && item.subject_reference === ctx.userId);
        if (matches) {
          records.push({
            resourceId: item.resource_id,
            systemId: 'security_service',
            dataCategory: 'SECURITY_AUDIT_LOG',
            state: 'PRESENT',
            evidenceId: fileId,
            identifyingFields: {}
          });
        }
      }
    }

    // support_platform
    if (se.support_platform?.support_tickets || se.support_platform?.tickets) {
      const tickets = se.support_platform.support_tickets || se.support_platform.tickets || [];
      for (const item of tickets) {
        const matches = (
          (item.requester_email && ctx.allEmails.has(item.requester_email.toLowerCase())) ||
          (item.customer_reference && item.customer_reference === ctx.userId) ||
          (item.requester_phone && ctx.allPhones.has(item.requester_phone.trim()))
        );
        if (matches) {
          const hasPii = item.requester_email || item.requester_phone;
          records.push({
            resourceId: item.resource_id,
            systemId: 'support_platform',
            dataCategory: item.resource_id?.startsWith('support_attachment_') ? 'SUPPORT_ATTACHMENT' : 'SUPPORT_MESSAGE',
            state: (item.status === 'REDACTED' || !hasPii) ? 'REDACTED' : 'PRESENT',
            evidenceId: fileId,
            identifyingFields: {}
          });
        }
      }
    }
  }

  // --- 2. customer_data_snapshot_bundle ---
  if (data.snapshots && Array.isArray(data.snapshots)) {
    for (const snap of data.snapshots) {
      const capturedAt = snap.captured_at ? new Date(snap.captured_at) : null;
      if (capturedAt && capturedAt > auditAt) continue;

      const dataStore = (snap.data_store || '').toLowerCase();
      const collection = (snap.collection || '').toLowerCase();

      for (const rec of (snap.records || [])) {
        const matches = (
          rec.customer_reference === ctx.userId ||
          rec.user_id === ctx.userId ||
          rec.subject_reference === ctx.userId ||
          (rec.email && ctx.allEmails.has(rec.email.toLowerCase())) ||
          (rec.email_hash && ctx.emailHashes.has(rec.email_hash)) ||
          (rec.phone && ctx.allPhones.has(rec.phone.trim()))
        );
        if (!matches) continue;

        const resourceId = rec.resource_id || rec.id;
        if (!resourceId) continue;

        let systemId = 'account_service';
        let dataCategory = 'USER_PROFILE';
        if (dataStore.includes('search') || collection.includes('search') || resourceId.startsWith('search_')) {
          systemId = 'search_service';
          dataCategory = 'SEARCH_INDEX_ENTRY';
        } else if (dataStore.includes('analytics') || collection.includes('analytics') || resourceId.startsWith('analytics_')) {
          systemId = 'analytics_platform';
          dataCategory = 'ANALYTICS_PROFILE';
        } else if (dataStore.includes('support') || collection.includes('support') || resourceId.startsWith('support_')) {
          systemId = 'support_platform';
          dataCategory = 'SUPPORT_MESSAGE';
        } else if (dataStore.includes('export') || collection.includes('export') || resourceId.startsWith('export_')) {
          systemId = 'export_service';
          dataCategory = 'USER_EXPORT';
        } else if (dataStore.includes('backup') || collection.includes('backup') || resourceId.startsWith('backup_')) {
          systemId = 'backup_service';
          dataCategory = 'BACKUP_ARCHIVE';
        } else if (dataStore.includes('security') || collection.includes('security') || resourceId.startsWith('audit_record_')) {
          systemId = 'security_service';
          dataCategory = 'SECURITY_AUDIT_LOG';
        } else if (dataStore.includes('identity') || collection.includes('deleted_customer') || resourceId.startsWith('tombstone_')) {
          systemId = 'identity_service';
          dataCategory = 'ACCOUNT_TOMBSTONE';
        }

        let state = 'PRESENT';
        if (dataCategory === 'ACCOUNT_TOMBSTONE') {
          const hasPii = rec.name || rec.email || rec.phone || rec.email_hash;
          state = hasPii ? 'PRESENT' : 'REDACTED';
        } else if (dataCategory === 'ANALYTICS_PROFILE') {
          state = (rec.email || rec.phone) ? 'PRESENT' : 'ANONYMIZED';
        } else if (rec.account_status === 'DELETED') {
          state = 'ABSENT';
        }

        records.push({
          resourceId, systemId, dataCategory, state, evidenceId: fileId,
          identifyingFields: {}
        });
      }
    }
  }

  // --- 3. customer_analytics_report ---
  if (data.records && Array.isArray(data.records) && data.collection?.includes('analytics')) {
    for (const rec of data.records) {
      const matches = (
        (rec.email && ctx.allEmails.has(rec.email.toLowerCase())) ||
        (rec.user_id && rec.user_id === ctx.userId) ||
        (rec.phone && ctx.allPhones.has(rec.phone.trim())) ||
        (rec.email_hash && ctx.emailHashes.has(rec.email_hash))
      );
      if (!matches) continue;
      const resourceId = rec.resource_id;
      if (!resourceId) continue;
      const hasPii = rec.email || rec.phone || rec.email_hash;
      records.push({
        resourceId,
        systemId: 'analytics_platform',
        dataCategory: 'ANALYTICS_PROFILE',
        state: hasPii ? 'PRESENT' : 'ANONYMIZED',
        evidenceId: fileId,
        identifyingFields: {}
      });
    }
  }

  // --- 4. connector_configurations ---
  if (data.connectors && Array.isArray(data.connectors)) {
    for (const conn of data.connectors) {
      const connStr = JSON.stringify(conn).toLowerCase();
      const matches = (
        [...ctx.allEmails].some(e => connStr.includes(e)) ||
        connStr.includes(ctx.userId.toLowerCase())
      );
      if (!matches) continue;
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

  // --- 5. customer_export_jobs / export manifests ---
  if (data.exports && Array.isArray(data.exports)) {
    for (const exp of data.exports) {
      const matches = (
        (exp.email && ctx.allEmails.has(exp.email.toLowerCase())) ||
        (exp.customer_reference && exp.customer_reference === ctx.userId) ||
        (exp.owner_email && ctx.allEmails.has(exp.owner_email.toLowerCase()))
      );
      if (!matches) continue;
      const resourceId = exp.export_id || exp.resource_id || exp.id;
      if (!resourceId) continue;
      records.push({
        resourceId,
        systemId: 'export_service',
        dataCategory: 'USER_EXPORT',
        state: exp.status === 'DELETED' ? 'ABSENT' : 'PRESENT',
        evidenceId: fileId,
        identifyingFields: {}
      });
    }
  }

  // --- 6. security_audit_ledger ---
  if (data.entries && Array.isArray(data.entries)) {
    for (const entry of data.entries) {
      const ref = entry.subject_reference || entry.user_id || '';
      if (ref !== ctx.userId) continue;
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

  return records;
}
