import { DataStore } from '../data/loader.js';
import { resolveIdentity } from '../modules/identityResolver.js';
import { isDeletionRequest } from '../modules/requestClassifier.js';
import { reconstructState } from '../modules/stateReconstructor.js';
import { evaluatePolicy } from '../modules/policyEngine.js';
import { buildSteps } from '../modules/stepBuilder.js';

async function profile() {
  const store = new DataStore();
  await store.load();

  const c = store.sampleCases[0];
  console.log('Testing case 1:', c.caseId);

  console.time('isDeletionRequest');
  const isDel = await isDeletionRequest(c.requestText);
  console.timeEnd('isDeletionRequest');

  console.time('resolveIdentity');
  const ctx = resolveIdentity(c.email, c.auditAt, store);
  console.timeEnd('resolveIdentity');

  console.time('getEvidenceFilesBefore');
  const ev = store.getEvidenceFilesBefore(c.auditAt);
  console.timeEnd('getEvidenceFilesBefore');

  console.time('reconstructState');
  const state = await reconstructState(ctx, ev, c.auditAt, store);
  console.timeEnd('reconstructState');

  console.time('evaluatePolicy');
  const pol = evaluatePolicy(state);
  console.timeEnd('evaluatePolicy');

  console.time('buildSteps');
  const steps = buildSteps(pol);
  console.timeEnd('buildSteps');

  console.log('Finished case 1 successfully with', steps.length, 'steps');
  process.exit(0);
}

profile();
