/**
 * src/modules/stepBuilder.js
 *
 * Formats and strictly orders steps into JSON schema per problem specifications:
 *   1. Phase order: FINDING -> REMEDIATION -> VERIFICATION
 *   2. Intra-phase operation order (from Problem Statement table)
 *   3. Tie-breaking: system_id ASC, resource_id ASC
 *   4. Consecutive step_no starting from 1
 *   5. Accurate evidence_id citation rules:
 *      - COMPLETE: VERIFICATION steps cite evidence_id
 *      - INCOMPLETE: FINDING cites evidence_id; REMEDIATION and future VERIFICATION use ""
 */

const FINDING_ORDER = {
  'REPORT_REMAINING_RECORD': 1,
  'REPORT_EXPOSED_PII': 2,
  'REPORT_ACTIVE_DATA_FLOW': 3,
  'REPORT_RESTORE_RISK': 4,
};

const REMEDIATION_ORDER = {
  'DISABLE_DATA_FLOW': 1,
  'BLOCK_RESTORE': 2,
  'DELETE_RECORD': 3,
  'REDACT_RECORD': 4,
  'ANONYMIZE_RECORD': 5,
};

const VERIFICATION_ORDER = {
  'VERIFY_RECORD_ABSENT': 1,
  'VERIFY_RECORD_PRESENT': 2,
  'VERIFY_RECORD_REDACTED': 3,
  'VERIFY_RECORD_ANONYMIZED': 4,
  'VERIFY_DATA_FLOW_DISABLED': 5,
  'VERIFY_RESTORE_BLOCKED': 6,
};

function sortSteps(steps, orderMap) {
  return [...steps].sort((a, b) => {
    const ordA = orderMap[a.operation] || 99;
    const ordB = orderMap[b.operation] || 99;
    if (ordA !== ordB) return ordA - ordB;
    if (a.systemId !== b.systemId) return a.systemId.localeCompare(b.systemId);
    return a.resourceId.localeCompare(b.resourceId);
  });
}

function deduplicateSteps(steps) {
  const seen = new Set();
  const deduped = [];
  for (const s of steps) {
    const key = `${s.phase}::${s.operation}::${s.systemId}::${s.resourceId}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(s);
    }
  }
  return deduped;
}

export function buildSteps(policyVerdict) {
  const { isComplete, findings, remediations, verifications } = policyVerdict;

  if (isComplete) {
    // COMPLETE: ONLY VERIFICATION steps proving compliant state
    const sortedVerif = sortSteps(deduplicateSteps(verifications), VERIFICATION_ORDER);

    return sortedVerif.map((s, idx) => ({
      step_no: idx + 1,
      phase: 'VERIFICATION',
      system_id: s.systemId,
      resource_id: s.resourceId,
      operation: s.operation,
      state: s.state,
      evidence_id: s.evidenceId || '',
    }));
  }

  // INCOMPLETE: FINDING -> REMEDIATION -> VERIFICATION
  const sortedFindings = sortSteps(deduplicateSteps(findings), FINDING_ORDER);
  const sortedRemediations = sortSteps(deduplicateSteps(remediations), REMEDIATION_ORDER);
  const sortedVerif = sortSteps(deduplicateSteps(verifications), VERIFICATION_ORDER);

  const allSteps = [];
  let stepNo = 1;

  for (const s of sortedFindings) {
    allSteps.push({
      step_no: stepNo++,
      phase: 'FINDING',
      system_id: s.systemId,
      resource_id: s.resourceId,
      operation: s.operation,
      state: s.state,
      evidence_id: s.evidenceId || '',
    });
  }

  for (const s of sortedRemediations) {
    allSteps.push({
      step_no: stepNo++,
      phase: 'REMEDIATION',
      system_id: s.systemId,
      resource_id: s.resourceId,
      operation: s.operation,
      state: s.state,
      evidence_id: '',
    });
  }

  for (const s of sortedVerif) {
    allSteps.push({
      step_no: stepNo++,
      phase: 'VERIFICATION',
      system_id: s.systemId,
      resource_id: s.resourceId,
      operation: s.operation,
      state: s.state,
      evidence_id: '',
    });
  }

  return allSteps;
}
