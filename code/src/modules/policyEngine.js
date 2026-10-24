/**
 * src/modules/policyEngine.js
 *
 * Apply deletion_rules.csv and policy requirements to reconstructed system state.
 * Determines required operations for findings, remediations, and verifications.
 */

export function evaluatePolicy(systemState) {
  const findings = [];
  const remediations = [];
  const verifications = [];

  // 1. Process active data flows (must be disabled first)
  for (const flow of systemState.activeDataFlows || []) {
    if (flow.state === 'ACTIVE') {
      findings.push({
        phase: 'FINDING',
        systemId: flow.systemId,
        resourceId: flow.resourceId,
        operation: 'REPORT_ACTIVE_DATA_FLOW',
        state: 'ACTIVE',
        evidenceId: flow.evidenceId,
      });
      remediations.push({
        phase: 'REMEDIATION',
        systemId: flow.systemId,
        resourceId: flow.resourceId,
        operation: 'DISABLE_DATA_FLOW',
        state: 'DISABLED',
        evidenceId: '',
      });
      verifications.push({
        phase: 'VERIFICATION',
        systemId: flow.systemId,
        resourceId: flow.resourceId,
        operation: 'VERIFY_DATA_FLOW_DISABLED',
        state: 'DISABLED',
        evidenceId: flow.evidenceId,
      });
    } else if (flow.state === 'DISABLED') {
      verifications.push({
        phase: 'VERIFICATION',
        systemId: flow.systemId,
        resourceId: flow.resourceId,
        operation: 'VERIFY_DATA_FLOW_DISABLED',
        state: 'DISABLED',
        evidenceId: flow.evidenceId,
      });
    }
  }

  // 2. Process restore risks (backups)
  for (const backup of systemState.restoreRisks || []) {
    if (backup.state === 'ACTIVE') {
      findings.push({
        phase: 'FINDING',
        systemId: backup.systemId,
        resourceId: backup.resourceId,
        operation: 'REPORT_RESTORE_RISK',
        state: 'ACTIVE',
        evidenceId: backup.evidenceId,
      });
      remediations.push({
        phase: 'REMEDIATION',
        systemId: backup.systemId,
        resourceId: backup.resourceId,
        operation: 'BLOCK_RESTORE',
        state: 'BLOCKED',
        evidenceId: '',
      });
      verifications.push({
        phase: 'VERIFICATION',
        systemId: backup.systemId,
        resourceId: backup.resourceId,
        operation: 'VERIFY_RESTORE_BLOCKED',
        state: 'BLOCKED',
        evidenceId: backup.evidenceId,
      });
    } else if (backup.state === 'BLOCKED') {
      verifications.push({
        phase: 'VERIFICATION',
        systemId: backup.systemId,
        resourceId: backup.resourceId,
        operation: 'VERIFY_RESTORE_BLOCKED',
        state: 'BLOCKED',
        evidenceId: backup.evidenceId,
      });
    }
  }

  // 3. Process normal records
  for (const rec of systemState.resources || []) {
    const cat = rec.dataCategory;

    // Delete categories
    if (['USER_PROFILE', 'SEARCH_INDEX_ENTRY', 'USER_EXPORT', 'MARKETING_PROFILE', 'CACHE_ENTRY', 'SUPPORT_ATTACHMENT'].includes(cat)) {
      if (rec.state === 'PRESENT') {
        findings.push({
          phase: 'FINDING',
          systemId: rec.systemId,
          resourceId: rec.resourceId,
          operation: 'REPORT_REMAINING_RECORD',
          state: 'PRESENT',
          evidenceId: rec.evidenceId,
        });
        remediations.push({
          phase: 'REMEDIATION',
          systemId: rec.systemId,
          resourceId: rec.resourceId,
          operation: 'DELETE_RECORD',
          state: 'ABSENT',
          evidenceId: '',
        });
      }
      verifications.push({
        phase: 'VERIFICATION',
        systemId: rec.systemId,
        resourceId: rec.resourceId,
        operation: 'VERIFY_RECORD_ABSENT',
        state: 'ABSENT',
        evidenceId: rec.evidenceId,
      });
    }

    // Redact categories (Support message, tombstone, email delivery log)
    else if (['SUPPORT_MESSAGE', 'ACCOUNT_TOMBSTONE', 'EMAIL_DELIVERY_LOG'].includes(cat)) {
      if (rec.state === 'PRESENT') {
        findings.push({
          phase: 'FINDING',
          systemId: rec.systemId,
          resourceId: rec.resourceId,
          operation: 'REPORT_EXPOSED_PII',
          state: 'PRESENT',
          evidenceId: rec.evidenceId,
        });
        remediations.push({
          phase: 'REMEDIATION',
          systemId: rec.systemId,
          resourceId: rec.resourceId,
          operation: 'REDACT_RECORD',
          state: 'REDACTED',
          evidenceId: '',
        });
      }
      verifications.push({
        phase: 'VERIFICATION',
        systemId: rec.systemId,
        resourceId: rec.resourceId,
        operation: 'VERIFY_RECORD_REDACTED',
        state: 'REDACTED',
        evidenceId: rec.evidenceId,
      });
    }

    // Anonymize categories (Analytics, telemetry)
    else if (['ANALYTICS_PROFILE', 'PRODUCT_TELEMETRY'].includes(cat)) {
      if (rec.state === 'PRESENT') {
        findings.push({
          phase: 'FINDING',
          systemId: rec.systemId,
          resourceId: rec.resourceId,
          operation: 'REPORT_EXPOSED_PII',
          state: 'PRESENT',
          evidenceId: rec.evidenceId,
        });
        remediations.push({
          phase: 'REMEDIATION',
          systemId: rec.systemId,
          resourceId: rec.resourceId,
          operation: 'ANONYMIZE_RECORD',
          state: 'ANONYMIZED',
          evidenceId: '',
        });
      }
      verifications.push({
        phase: 'VERIFICATION',
        systemId: rec.systemId,
        resourceId: rec.resourceId,
        operation: 'VERIFY_RECORD_ANONYMIZED',
        state: 'ANONYMIZED',
        evidenceId: rec.evidenceId,
      });
    }
  }

  // 4. Process retained records (Security audit logs, legal hold)
  for (const rec of systemState.retainedRecords || []) {
    verifications.push({
      phase: 'VERIFICATION',
      systemId: rec.systemId,
      resourceId: rec.resourceId,
      operation: 'VERIFY_RECORD_PRESENT',
      state: 'PRESENT',
      evidenceId: rec.evidenceId,
    });
  }

  const isComplete = findings.length === 0;
  return {
    isComplete,
    deletionStatus: isComplete ? 'COMPLETE' : 'INCOMPLETE',
    findings,
    remediations,
    verifications,
  };
}
