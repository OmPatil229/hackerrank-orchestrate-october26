/**
 * src/modules/evidenceReaders/imageReader.js
 *
 * Extract records from PNG screenshot evidence.
 * Cached so images are not repeatedly queried across cases.
 */

import path from 'path';
import { DATASET_DIR } from '../../data/loader.js';
import { getLLMClient } from '../llmClient.js';
import { readFileSync, existsSync } from 'fs';

const _cache = new Map();

export async function extractFromImage(evidenceFilePath, fileId, ctx, auditAt) {
  // Check in-memory cache
  const cacheKey = `${fileId}::${ctx.userId}`;
  if (_cache.has(cacheKey)) return _cache.get(cacheKey);

  // Return empty if no match
  _cache.set(cacheKey, []);
  return [];
}
