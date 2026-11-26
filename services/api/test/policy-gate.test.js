import { describe, it, expect } from 'vitest';
import { satisfiesPolicy } from '../src/policy-gate.js';

describe('server-side policy gate', () => {
  it('matches the cryptographic policy grammar (hyphens, dots, @, && and ||)', () => {
    expect(satisfiesPolicy('dept:comp-sci', ['dept:comp-sci'])).toBe(true);
    expect(satisfiesPolicy('email:bob@corp.com', ['email:bob@corp.com'])).toBe(true);
    expect(satisfiesPolicy('dept:cse && role:faculty', ['dept:cse', 'role:faculty'])).toBe(true);
    expect(satisfiesPolicy('dept:cse || dept:hr', ['dept:hr'])).toBe(true);
  });

  it('is case-insensitive for attributes', () => {
    expect(satisfiesPolicy('Dept:CSE AND role:faculty', ['DEPT:cse', 'role:Faculty'])).toBe(true);
  });

  it('gives AND higher precedence than OR', () => {
    expect(satisfiesPolicy('a:1 OR b:2 AND c:3', ['a:1'])).toBe(true);
    expect(satisfiesPolicy('a:1 OR b:2 AND c:3', ['b:2'])).toBe(false);
    expect(satisfiesPolicy('(a:1 OR b:2) AND c:3', ['a:1'])).toBe(false);
  });

  it('does not let OR short-circuiting hide a later operand', () => {
    expect(satisfiesPolicy('(user:alice OR role:faculty) AND dept:cse', ['user:alice'])).toBe(false);
  });

  it('fails closed on malformed or empty policies', () => {
    for (const bad of ['', '   ', 'dept:cse AND', '(dept:cse', 'dept:cse)', 'AND dept:cse', 'not-an-attribute', null, undefined]) {
      expect(satisfiesPolicy(bad, ['dept:cse'])).toBe(false);
    }
  });
});
