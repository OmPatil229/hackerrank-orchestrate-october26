/**
 * src/modules/identityResolver.js
 *
 * Map a request email to user_id and collect ALL current + historical
 * identifiers (emails, phones, hashes) for downstream evidence matching.
 */

import crypto from 'crypto';

/** SHA-256 hash of an email (lowercased) */
export function emailSha256(email) {
  return crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
}

/**
 * Resolve an email to a full IdentityContext.
 *
 * Strategy:
 * 1. Case-insensitive lookup in current user_identities.
 * 2. If not found, search audit log old_value/new_value for matching email.
 * 3. Collect all emails, phones, hashes filtered to events <= auditAt.
 *
 * Returns null if no user found.
 */
export function resolveIdentity(email, auditAt, store) {
  const emailLower = email.toLowerCase().trim();

  // Step 1: direct lookup
  let user = store.usersByEmail.get(emailLower) || null;

  // Step 2: fallback — scan audit log for historical email match
  if (!user) {
    outer: for (const [userId, entries] of store.auditLog) {
      for (const entry of entries) {
        if (
          entry.fieldName === 'email' &&
          entry.eventTime <= auditAt &&
          (entry.oldValue.toLowerCase() === emailLower ||
            entry.newValue.toLowerCase() === emailLower)
        ) {
          user = store.usersById.get(userId) || null;
          if (user) break outer;
        }
      }
    }
  }

  if (!user) return null;

  // Step 3: build IdentityContext
  const ctx = {
    userId: user.userId,
    currentEmail: user.email,
    allEmails: new Set([user.email.toLowerCase()]),
    allPhones: new Set(),
    emailHashes: new Set([user.emailHash, emailSha256(user.email)]),
    nameVariants: new Set([user.name]),
  };

  if (user.phone) ctx.allPhones.add(user.phone.trim());

  // Walk audit log for this user
  const entries = store.auditLog.get(user.userId) || [];
  for (const entry of entries) {
    if (entry.eventTime > auditAt) continue;

    if (entry.fieldName === 'email') {
      for (const val of [entry.oldValue, entry.newValue]) {
        if (val) {
          const v = val.toLowerCase().trim();
          ctx.allEmails.add(v);
          ctx.emailHashes.add(emailSha256(v));
        }
      }
    } else if (entry.fieldName === 'phone') {
      for (const val of [entry.oldValue, entry.newValue]) {
        if (val) ctx.allPhones.add(val.trim());
      }
    } else if (entry.fieldName === 'name') {
      for (const val of [entry.oldValue, entry.newValue]) {
        if (val) ctx.nameVariants.add(val.trim());
      }
    }
  }

  // Always include the request email
  ctx.allEmails.add(emailLower);
  ctx.emailHashes.add(emailSha256(emailLower));

  return ctx;
}
