/**
 * src/modules/stateReconstructor.js
 *
 * Given an IdentityContext and the relevant evidence files,
 * determine the actual state of all user records at audit_at.
 *
 * Integrates system_activity.csv events to update state
 * between evidence capture time and audit_at.
 */

import { extractFromSQL } from './evidenceReaders/sqlReader.js';
import { extractFromJSON } from './evidenceReaders/jsonReader.js';
import { extractFromLog } from './evidenceReaders/logReader.js';
import { extractFromPDF } from './evidenceReaders/pdfReader.js';
import { extractFromImage } from './evidenceReaders/imageReader.js';
import path from 'path';

/** Dispatch evidence file to the correct reader based on extension */
async function readEvidenceFile(evidenceFile, ctx, auditAt) {
  const ext = path.extname(evidenceFile.filePath).toLowerCase();
  const { fileId, filePath } = evidenceFile;

  try {
    if (ext === '.sql') return extractFromSQL(filePath, fileId, ctx, auditAt);
    if (ext === '.json') return extractFromJSON(filePath, fileId, ctx, auditAt);
    if (ext === '.log') return extractFromLog(filePath, fileId, ctx, auditAt);
    if (ext === '.txt') return extractFromLog(filePath, fileId, ctx, auditAt);
    if (ext === '.pdf') return await extractFromPDF(filePath, fileId, ctx, auditAt);
    if (ext === '.png' || ext === '.jpg') return await extractFromImage(filePath, fileId, ctx, auditAt);
  } catch (e) {
    console.warn(`[StateReconstructor] Error reading ${filePath}: ${e.message}`);
  }
  return [];
}

/**
 * Apply system_activity events to potentially update resource state.
 */
function applyActivityEvents(resources, ctx, auditAt, store) {
  const resourceMap = new Map();
  for (const r of resources) {
    const key = `${r.systemId}::${r.resourceId}`;
    resourceMap.set(key, r);
  }

  for (const [key, resource] of resourceMap) {
    const events = store.activityByResource.get(resource.resourceId) || [];
    const relevant = events
      .filter(e => e.eventTime <= auditAt)
      .sort((a, b) => a.eventTime - b.eventTime);

    let latestState = resource.state;
    for (const evt of relevant) {
      if (evt.reportedResult !== 'SUCCESS' && evt.reportedResult !== 'PARTIAL') continue;

      switch (evt.eventType) {
        case 'DELETE_RECORD':
          latestState = 'ABSENT';
          break;
        case 'ANONYMIZE_RECORD':
          latestState = 'ANONYMIZED';
          break;
        case 'REDACT_RECORD':
          latestState = 'REDACTED';
          break;
        case 'DISABLE_DATA_FLOW':
          latestState = 'DISABLED';
          break;
        case 'BLOCK_RESTORE':
          latestState = 'BLOCKED';
          break;
        case 'RESTORE_BACKUP':
        case 'SYNC_RECORD':
          if (latestState === 'ABSENT' || latestState === 'ANONYMIZED') {
            latestState = 'PRESENT';
          }
          break;
      }
    }

    resource.state = latestState;
  }

  return Array.from(resourceMap.values());
}

/** Deduplicate resources: keep the most informative state per (systemId, resourceId) */
function deduplicateResources(resources) {
  const STATE_PRIORITY = {
    'PRESENT': 5,
    'PRESENT_WITH_PII': 5,
    'ACTIVE': 4,
    'REDACTED': 3,
    'ANONYMIZED': 3,
    'BLOCKED': 2,
    'DISABLED': 2,
    'ABSENT': 1,
  };

  const map = new Map();
  for (const r of resources) {
    const key = `${r.systemId}::${r.resourceId}`;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, r);
    } else {
      const curPri = STATE_PRIORITY[r.state] || 0;
      const exPri = STATE_PRIORITY[existing.state] || 0;
      if (curPri > exPri) {
        map.set(key, r);
      }
    }
  }
  return Array.from(map.values());
}

/**
 * Reconstruct the system state at audit_at for the given user.
 */
export async function reconstructState(ctx, relevantEvidence, auditAt, store) {
  // Read all evidence files in parallel
  const allResults = await Promise.all(
    relevantEvidence.map(ef => readEvidenceFile(ef, ctx, auditAt))
  );

  let allResources = allResults.flat();

  // Apply activity log updates
  allResources = applyActivityEvents(allResources, ctx, auditAt, store);

  // Deduplicate
  allResources = deduplicateResources(allResources);

  // Partition into categories
  const systemState = {
    resources: [],          // records that need treatment or verification
    activeDataFlows: [],    // active / disabled integrations
    restoreRisks: [],       // backups (active or blocked)
    retainedRecords: [],    // records that must be kept (security audit, legal hold)
  };

  for (const r of allResources) {
    if (r.dataCategory === 'ACTIVE_DATA_FLOW') {
      systemState.activeDataFlows.push(r);
    } else if (r.dataCategory === 'BACKUP_ARCHIVE') {
      systemState.restoreRisks.push(r);
    } else if (r.dataCategory === 'SECURITY_AUDIT_LOG' || r.dataCategory === 'LEGAL_HOLD_RECORD') {
      systemState.retainedRecords.push(r);
    } else {
      systemState.resources.push(r);
    }
  }

  return systemState;
}
