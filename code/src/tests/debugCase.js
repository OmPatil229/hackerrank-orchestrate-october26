import { DataStore } from '../data/loader.js';
import { resolveIdentity } from '../modules/identityResolver.js';
import { reconstructState } from '../modules/stateReconstructor.js';
import { evaluatePolicy } from '../modules/policyEngine.js';

async function testCase(caseId) {
  const store = new DataStore();
  await store.load();

  const c = store.sampleCases.find(x => x.caseId === caseId);
  console.log('Case:', c);

  const ctx = resolveIdentity(c.email, c.auditAt, store);
  console.log('Context:', ctx);

  const evidence = store.getEvidenceFilesBefore(c.auditAt);
  console.log(`Evidence before audit_at (${evidence.length} files)`);

  const hasEv54 = evidence.find(e => e.fileId === 'evidence_54');
  console.log('Has evidence_54 in list?', Boolean(hasEv54));

  const state = await reconstructState(ctx, evidence, c.auditAt, store);
  console.log('Reconstructed State:', JSON.stringify(state, null, 2));

  const verdict = evaluatePolicy(state);
  console.log('Policy Verdict:', verdict);
}

testCase(process.argv[2] || 'case_05');
