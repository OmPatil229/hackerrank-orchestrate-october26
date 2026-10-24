/**
 * src/modules/stateReconstructor.js
 *
 * Given an IdentityContext and the relevant evidence files,
 * determine the actual state of all user records at audit_at.
 *
 * Integrates evidence snapshots, readbacks, and system_activity.csv.
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
 * Find the primary evidence file for audit verification of absent/retained resources.
 */
function findLatestEvidenceFile(relevantEvidence, systemId) {
  const sorted = [...relevantEvidence].sort((a, b) => b.capturedAt - a.capturedAt);
  for (const ef of sorted) {
    const fp = ef.filePath.toLowerCase();
    if (systemId === 'account_service' && (fp.includes('account') || fp.includes('profile') || fp.includes('replica') || fp.includes('inventory') || fp.includes('resource_export') || fp.includes('lookup_trace') || fp.includes('handover'))) {
      return ef.fileId;
    }
    if (systemId === 'search_service' && (fp.includes('search') || fp.includes('inventory') || fp.includes('resource_export') || fp.includes('lookup_trace'))) {
      return ef.fileId;
    }
    if (systemId === 'analytics_platform' && (fp.includes('analytics') || fp.includes('inventory') || fp.includes('resource_export') || fp.includes('lookup_trace'))) {
      return ef.fileId;
    }
    if (systemId === 'backup_service' && (fp.includes('backup') || fp.includes('inventory') || fp.includes('resource_export') || fp.includes('lookup_trace'))) {
      return ef.fileId;
    }
    if (systemId === 'integration_service' && (fp.includes('connector') || fp.includes('data_flow') || fp.includes('inventory') || fp.includes('resource_export') || fp.includes('lookup_trace'))) {
      return ef.fileId;
    }
    if (systemId === 'support_platform' && (fp.includes('support') || fp.includes('inventory') || fp.includes('resource_export') || fp.includes('lookup_trace'))) {
      return ef.fileId;
    }
  }
  return sorted[0]?.fileId || '';
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

  // Check if primary account exists or was discovered
  const hasAccountService = allResources.some(r => r.systemId === 'account_service');
  if (!hasAccountService) {
    // Determine the user's primary account ID
    // 1. Check user_01 -> account_001 mapping
    const uMatch = ctx.userId.match(/user_(\d+)/);
    let primaryAccountId = null;

    if (uMatch) {
      const num = parseInt(uMatch[1], 10);
      if (num < 10) primaryAccountId = `account_00${num}`;
      else if (num < 100) primaryAccountId = `account_0${num}`;
    }

    // 2. Also check system_activity for deletion_worker DELETE_RECORD targeting account_service
    if (!primaryAccountId) {
      for (const [rid, evts] of store.activityByResource) {
        if (rid.startsWith('account_')) {
          for (const e of evts) {
            if (e.sourceSystem === 'deletion_worker' && e.targetSystem === 'account_service') {
              if (e.details?.includes(ctx.userId) || [...ctx.allEmails].some(em => e.details?.includes(em))) {
                primaryAccountId = rid;
                break;
              }
            }
          }
        }
        if (primaryAccountId) break;
      }
    }

    if (primaryAccountId) {
      const latestEvId = findLatestEvidenceFile(relevantEvidence, 'account_service');
      allResources.push({
        resourceId: primaryAccountId,
        systemId: 'account_service',
        dataCategory: 'USER_PROFILE',
        state: 'ABSENT',
        evidenceId: latestEvId,
        identifyingFields: {},
      });
    }
  }

  // Deduplicate
  allResources = deduplicateResources(allResources);

  // Partition into categories
  const systemState = {
    resources: [],
    activeDataFlows: [],
    restoreRisks: [],
    retainedRecords: [],
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
