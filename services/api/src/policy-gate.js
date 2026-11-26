import { policy as policyLib } from '@secureshare/crypto';

/**
 * Live server-side gate. Uses the same parser as the cryptography (packages/crypto), so the
 * accepted attribute syntax (dept:comp-sci, email:a@b.c, && / ||, quotes) cannot drift apart.
 * Anything that fails to parse is denied (fail closed).
 */
export function satisfiesPolicy(policyText, attributes) {
  try {
    return policyLib.satisfies(policyLib.parsePolicy(String(policyText)), attributes.map((a) => String(a).toLowerCase()));
  } catch {
    return false;
  }
}
