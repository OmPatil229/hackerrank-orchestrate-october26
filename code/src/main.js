/**
 * src/main.js
 *
 * Main Orchestrator for HackerRank Orchestrate — Ghost Data Still Exists
 *
 * Runs all 518 cases from dataset/deletion_requests.csv and outputs output.csv
 * at repository root.
 *
 * Usage:
 *   node src/main.js              # Runs full 518 cases -> output.csv
 *   node src/main.js --sample     # Runs 32 sample cases & evaluates vs sample_output.csv
 */

import { DataStore, REPO_ROOT } from './data/loader.js';
import { resolveIdentity } from './modules/identityResolver.js';
import { isDeletionRequest } from './modules/requestClassifier.js';
import { reconstructState } from './modules/stateReconstructor.js';
import { evaluatePolicy } from './modules/policyEngine.js';
import { buildSteps } from './modules/stepBuilder.js';
import { getUsageReport } from './modules/llmClient.js';
import { writeFileSync, readFileSync } from 'fs';
import path from 'path';

/** Escape CSV field if it contains commas, quotes, or newlines */
function escapeCSV(val) {
  if (val === null || val === undefined) return '';
  const str = String(val);
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/** Format output CSV string */
function toCSV(results) {
  const lines = ['case_id,deletion_status,steps_json'];
  for (const r of results) {
    lines.push(`${r.caseId},${r.deletionStatus},${escapeCSV(r.stepsJson)}`);
  }
  return lines.join('\n') + '\n';
}

async function processCase(caseItem, store) {
  const { caseId, email, requestText, auditAt } = caseItem;

  // 1. Request classification
  const isDeletion = await isDeletionRequest(requestText);
  if (!isDeletion) {
    return {
      caseId,
      deletionStatus: 'NOT_APPLICABLE',
      stepsJson: '[]',
      steps: [],
    };
  }

  // 2. Identity resolution
  const ctx = resolveIdentity(email, auditAt, store);
  if (!ctx) {
    return {
      caseId,
      deletionStatus: 'NOT_APPLICABLE',
      stepsJson: '[]',
      steps: [],
    };
  }

  // 3. Evidence gathering (captured_at <= audit_at)
  const relevantEvidence = store.getEvidenceFilesBefore(auditAt);

  // 4. State reconstruction
  const systemState = await reconstructState(ctx, relevantEvidence, auditAt, store);

  // 5. Policy evaluation
  const policyVerdict = evaluatePolicy(systemState);

  // 6. Step generation
  const steps = buildSteps(policyVerdict);

  return {
    caseId,
    deletionStatus: policyVerdict.deletionStatus,
    stepsJson: JSON.stringify(steps),
    steps,
  };
}

async function main() {
  const args = process.argv.slice(2);
  const isSampleRun = args.includes('--sample') || args.includes('-s');

  console.log('='.repeat(60));
  console.log(' Ghost Data Still Exists — Audit Agent');
  console.log(` Mode: ${isSampleRun ? 'SAMPLE (32 cases evaluation)' : 'FULL RUN (518 cases)'}`);
  console.log('='.repeat(60));

  const store = new DataStore();
  await store.load();

  const casesToProcess = isSampleRun ? store.sampleCases : store.cases;
  console.log(`\nProcessing ${casesToProcess.length} cases...`);

  const results = [];
  const startTime = Date.now();

  for (let i = 0; i < casesToProcess.length; i++) {
    const caseItem = casesToProcess[i];
    const res = await processCase(caseItem, store);
    results.push(res);

    if ((i + 1) % 50 === 0 || i === casesToProcess.length - 1) {
      console.log(`  Processed ${i + 1}/${casesToProcess.length} cases...`);
    }
  }

  // Sort by case_id ASC
  results.sort((a, b) => a.caseId.localeCompare(b.caseId));

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log(`\nFinished in ${elapsed}s.`);

  // Write output.csv
  const outputPath = path.join(REPO_ROOT, isSampleRun ? 'sample_test_output.csv' : 'output.csv');
  writeFileSync(outputPath, toCSV(results), 'utf8');
  console.log(`Written output to: ${outputPath}`);

  // If sample run, evaluate accuracy vs sample_output.csv
  if (isSampleRun) {
    evaluateSampleAccuracy(results);
  }

  // Print token usage summary
  const usage = getUsageReport();
  console.log('\n--- LLM Usage Summary ---');
  console.log(`Model: ${usage.model}`);
  console.log(`Total API Calls: ${usage.calls}`);
  console.log(`Total Tokens: In=${usage.inputTokens}, Out=${usage.outputTokens}`);
  console.log('--------------------------\n');
}

function evaluateSampleAccuracy(results) {
  const sampleOutputPath = path.join(REPO_ROOT, 'dataset', 'sample_output.csv');
  let expectedLines;
  try {
    expectedLines = readFileSync(sampleOutputPath, 'utf8')
      .split('\n')
      .filter(l => l.trim().length > 0)
      .slice(1);
  } catch {
    console.log('Could not load sample_output.csv for comparison.');
    return;
  }

  const expectedMap = new Map();
  for (const line of expectedLines) {
    const firstComma = line.indexOf(',');
    const secondComma = line.indexOf(',', firstComma + 1);
    const caseId = line.slice(0, firstComma).trim();
    const status = line.slice(firstComma + 1, secondComma).trim();
    let jsonStr = line.slice(secondComma + 1).trim();
    if (jsonStr.startsWith('"') && jsonStr.endsWith('"')) {
      jsonStr = jsonStr.slice(1, -1).replace(/""/g, '"');
    }
    expectedMap.set(caseId, { status, jsonStr });
  }

  let statusMatches = 0;
  let exactStepMatches = 0;

  console.log('\n--- Sample Cases Evaluation ---');
  for (const r of results) {
    const exp = expectedMap.get(r.caseId);
    if (!exp) continue;

    const statusMatch = r.deletionStatus === exp.status;
    if (statusMatch) statusMatches++;

    let stepMatch = false;
    try {
      const expSteps = JSON.parse(exp.jsonStr);
      const actualSteps = r.steps;
      if (JSON.stringify(expSteps) === JSON.stringify(actualSteps)) {
        exactStepMatches++;
        stepMatch = true;
      }
    } catch {}

    const icon = statusMatch ? '✓' : '✗';
    console.log(`  ${icon} ${r.caseId}: status=${r.deletionStatus} (expected ${exp.status}) | steps=${r.steps.length}`);
  }

  console.log('-------------------------------');
  console.log(`Status Accuracy: ${statusMatches}/${expectedMap.size} (${((statusMatches / expectedMap.size) * 100).toFixed(1)}%)`);
  console.log(`Exact Step Sequence Matches: ${exactStepMatches}/${expectedMap.size}`);
  console.log('-------------------------------\n');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
