// Fixtures for secret-share-range-validation-missing.
//
// Shamir over GF(256). `split` evaluates f at x = 1..n and never at x = 0,
// because f(0) is the secret itself. The question for each `combine` below is
// whether it enforces the same bound its own `split` does.

interface Share {
  x: number;
  y: Uint8Array;
}

const FIELD_SIZE = 256;

export function split(secret: Uint8Array, shares: number, threshold: number): Share[] {
  const out: Share[] = [];
  for (let x = 1; x <= shares; x++) {
    // x starts at 1: evaluating at 0 would hand back the secret.
    out.push({ x, y: evaluate(secret, threshold, x) });
  }
  return out;
}

// Distinctness is checked, range is not: a crafted { x: 0, y } is accepted and
// interpolated over, and the caller controls the output.
export function combine(shares: Share[]): Uint8Array {
  // ruleid: secret-share-range-validation-missing
  const xs = new Set(shares.map((s) => s.x));
  if (xs.size !== shares.length) {
    throw new Error('shares must have distinct x-coordinates');
  }
  return lagrangeInterpolate(shares, 0);
}

export function reconstructSecret(shares: Share[]): Uint8Array {
  // ruleid: secret-share-range-validation-missing
  const seen = new Set<number>();
  for (const s of shares) {
    if (seen.has(s.x)) {
      throw new Error('duplicate share');
    }
    seen.add(s.x);
  }
  return lagrangeInterpolate(shares, 0);
}

// Both bounds enforced, matching what `split` will ever emit.
export function combineChecked(shares: Share[]): Uint8Array {
  // ok: secret-share-range-validation-missing
  const xs = new Set(shares.map((s) => s.x));
  if (xs.size !== shares.length) {
    throw new Error('shares must have distinct x-coordinates');
  }
  for (const s of shares) {
    if (s.x < 1 || s.x >= FIELD_SIZE) {
      throw new Error('share x-coordinate out of range');
    }
  }
  return lagrangeInterpolate(shares, 0);
}

// The zero coordinate is rejected explicitly before anything else happens.
export function recoverSecret(shares: Share[]): Uint8Array {
  const bad = shares.some((s) => s.x === 0);
  if (bad) {
    throw new Error('x = 0 is the secret, not a share');
  }
  // ok: secret-share-range-validation-missing
  const seen = new Set<number>();
  for (const s of shares) {
    if (seen.has(s.x)) {
      throw new Error('duplicate share');
    }
    seen.add(s.x);
  }
  return lagrangeInterpolate(shares, 0);
}

// Not a combine routine: deduplicating a device list has no coordinate to bound.
export function dedupeDeviceIds(ids: number[]): number[] {
  // ok: secret-share-range-validation-missing
  const seen = new Set(ids);
  return [...seen];
}

function evaluate(_secret: Uint8Array, _threshold: number, _x: number): Uint8Array {
  return new Uint8Array(0);
}

function lagrangeInterpolate(_shares: Share[], _at: number): Uint8Array {
  return new Uint8Array(0);
}
