/**
 * src/data/loader.js
 * Load all CSV dataset files into indexed in-memory structures.
 * All paths are resolved relative to the repository root.
 */

import { createReadStream } from 'fs';
import { parse } from 'csv-parse';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
export const DATASET_DIR = path.join(REPO_ROOT, 'dataset');

/** Parse ISO-8601 string to Date object */
function parseDate(s) {
  return new Date(s.trim());
}

/** Read a CSV file and return an array of row objects */
async function readCSV(filePath) {
  return new Promise((resolve, reject) => {
    const rows = [];
    createReadStream(filePath)
      .pipe(parse({ columns: true, trim: true, skip_empty_lines: true, relax_quotes: true }))
      .on('data', row => rows.push(row))
      .on('end', () => resolve(rows))
      .on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

export async function loadDeletionCases(filePath) {
  filePath = filePath || path.join(DATASET_DIR, 'deletion_requests.csv');
  const rows = await readCSV(filePath);
  return rows.map(r => ({
    caseId: r.case_id,
    email: r.email,
    requestedAt: parseDate(r.requested_at),
    reportedStatus: r.reported_status,
    reportedAt: parseDate(r.reported_at),
    auditAt: parseDate(r.audit_at),
    requestText: r.request_text,
  })).sort((a, b) => a.caseId.localeCompare(b.caseId));
}

export async function loadSampleCases(filePath) {
  filePath = filePath || path.join(DATASET_DIR, 'sample_deletion_requests.csv');
  return loadDeletionCases(filePath);
}

export async function loadUserIdentities(filePath) {
  filePath = filePath || path.join(DATASET_DIR, 'user_identities.csv');
  const rows = await readCSV(filePath);
  const byEmail = new Map();
  const byId = new Map();
  for (const r of rows) {
    const u = {
      userId: r.user_id,
      name: r.name,
      email: r.email,
      phone: r.phone,
      emailHash: r.email_hash,
      updatedAt: parseDate(r.updated_at),
    };
    byId.set(u.userId, u);
    byEmail.set(u.email.toLowerCase(), u);
  }
  return { byEmail, byId };
}

export async function loadAuditLog(filePath) {
  filePath = filePath || path.join(DATASET_DIR, 'user_audit_log.csv');
  const rows = await readCSV(filePath);
  const byUser = new Map();
  for (const r of rows) {
    const entry = {
      auditId: r.audit_id,
      userId: r.user_id,
      eventTime: parseDate(r.event_time),
      fieldName: r.field_name,
      oldValue: r.old_value,
      newValue: r.new_value,
    };
    if (!byUser.has(entry.userId)) byUser.set(entry.userId, []);
    byUser.get(entry.userId).push(entry);
  }
  return byUser;
}

export async function loadSystemActivity(filePath) {
  filePath = filePath || path.join(DATASET_DIR, 'system_activity.csv');
  const rows = await readCSV(filePath);
  const byResource = new Map();
  const byId = new Map();
  for (const r of rows) {
    const e = {
      activityId: r.activity_id,
      eventTime: parseDate(r.event_time),
      eventType: r.event_type,
      sourceSystem: r.source_system,
      targetSystem: r.target_system,
      resourceId: r.resource_id,
      reportedResult: r.reported_result,
      details: r.details,
    };
    byId.set(e.activityId, e);
    if (!byResource.has(e.resourceId)) byResource.set(e.resourceId, []);
    byResource.get(e.resourceId).push(e);
  }
  return { byResource, byId };
}

export async function loadDeletionRules(filePath) {
  filePath = filePath || path.join(DATASET_DIR, 'deletion_rules.csv');
  const rows = await readCSV(filePath);
  return rows.map(r => ({
    ruleId: r.rule_id,
    dataCategory: r.data_category,
    condition: r.condition,
    requiredAction: r.required_action,
  }));
}

export async function loadEvidenceManifest(filePath) {
  filePath = filePath || path.join(DATASET_DIR, 'evidence_files.csv');
  const rows = await readCSV(filePath);
  const manifest = new Map();
  for (const r of rows) {
    const e = {
      fileId: r.file_id,
      filePath: r.file_path,
      origin: r.origin,
      capturedAt: parseDate(r.captured_at),
    };
    manifest.set(e.fileId, e);
  }
  return manifest;
}

// ---------------------------------------------------------------------------
// DataStore — central in-memory store loaded once at startup
// ---------------------------------------------------------------------------

export class DataStore {
  constructor() {
    this.cases = [];
    this.sampleCases = [];
    this.usersByEmail = new Map();
    this.usersById = new Map();
    this.auditLog = new Map();          // userId -> entries[]
    this.activityByResource = new Map();
    this.activityById = new Map();
    this.deletionRules = [];
    this.rulesByCategory = new Map();   // dataCategory -> rule
    this.evidenceManifest = new Map();  // fileId -> evidence file
  }

  async load() {
    console.log('[DataStore] Loading datasets...');
    [
      this.cases,
      this.sampleCases,
      { byEmail: this.usersByEmail, byId: this.usersById },
      this.auditLog,
      { byResource: this.activityByResource, byId: this.activityById },
      this.deletionRules,
      this.evidenceManifest,
    ] = await Promise.all([
      loadDeletionCases(),
      loadSampleCases(),
      loadUserIdentities(),
      loadAuditLog(),
      loadSystemActivity(),
      loadDeletionRules(),
      loadEvidenceManifest(),
    ]);

    for (const rule of this.deletionRules) {
      this.rulesByCategory.set(rule.dataCategory, rule);
    }

    console.log(`[DataStore] Loaded ${this.cases.length} cases, ` +
      `${this.usersById.size} users, ` +
      `${this.evidenceManifest.size} evidence files.`);
  }

  resolveUser(email) {
    return this.usersByEmail.get(email.toLowerCase().trim()) || null;
  }

  getEvidenceFilesBefore(auditAt) {
    const result = [];
    for (const f of this.evidenceManifest.values()) {
      if (f.capturedAt <= auditAt) result.push(f);
    }
    return result;
  }

  getActivityForResource(resourceId, before) {
    const events = this.activityByResource.get(resourceId) || [];
    return events.filter(e => e.eventTime <= before);
  }
}
