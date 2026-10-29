// Fixtures for the Node sandbox denylist rules.
//
// The two denylist rules are deliberately independent: a list that is complete
// with respect to realm-escape modules can still be incomplete with respect to
// the `node:` aliases, and vice versa. The fixtures below keep each failure mode
// isolated so that one annotation does not mask the other.

// `vm`, `module`, `repl`, `inspector` and `worker_threads` are all reachable.
// ruleid: vm-sandbox-denylist-missing-realm-escape-module
const BLOCKED_MODULES = new Set([
  'fs', 'node:fs',
  'child_process', 'node:child_process',
  'net', 'node:net',
]);

// Nearly complete, but `worker_threads` is missing — one `new Worker` with an
// eval:true option is enough to get a fresh host-realm thread back.
// ruleid: vm-sandbox-denylist-missing-realm-escape-module
const denyRequire = [
  'fs', 'node:fs',
  'child_process', 'node:child_process',
  'vm', 'node:vm',
  'module', 'node:module',
  'repl', 'node:repl',
  'inspector', 'node:inspector',
];

// Every realm-escape module is listed, but only under its bare specifier, so
// require('node:vm') resolves to the same builtin and is not blocked.
// ruleid: vm-sandbox-denylist-missing-node-prefix-alias
const forbiddenSpecifiers = new Set([
  'fs', 'child_process', 'net',
  'vm', 'module', 'repl', 'inspector', 'worker_threads',
]);

// Only `child_process` lost its alias.
// ruleid: vm-sandbox-denylist-missing-node-prefix-alias
const restrictedBuiltins = new Set([
  'fs', 'node:fs',
  'child_process',
  'net', 'node:net',
  'vm', 'node:vm',
  'module', 'node:module',
  'repl', 'node:repl',
  'inspector', 'node:inspector',
  'worker_threads', 'node:worker_threads',
]);

// ok: vm-sandbox-denylist-missing-realm-escape-module
// ok: vm-sandbox-denylist-missing-node-prefix-alias
const blockedComplete = new Set([
  'fs', 'node:fs',
  'child_process', 'node:child_process',
  'net', 'node:net',
  'vm', 'node:vm',
  'module', 'node:module',
  'repl', 'node:repl',
  'inspector', 'node:inspector',
  'worker_threads', 'node:worker_threads',
]);

// An allowlist is the recommended shape and is not a denylist at all.
// ok: vm-sandbox-denylist-missing-realm-escape-module
// ok: vm-sandbox-denylist-missing-node-prefix-alias
const ALLOWED_MODULES = new Set(['lodash', 'dayjs', 'semver']);

// Not a module list; the name matches but the contents do not.
// ok: vm-sandbox-denylist-missing-realm-escape-module
// ok: vm-sandbox-denylist-missing-node-prefix-alias
const blockedUserAgents = ['curl', 'wget', 'python-requests'];

function normaliseSpecifier(spec) {
  return spec.replace(/^node:/, '').toLowerCase();
}

function guardedRequire(spec) {
  if (blockedComplete.has(normaliseSpecifier(spec))) {
    throw new Error(`module ${spec} is not available in this sandbox`);
  }
  return require(spec);
}

const vm = require('node:vm');

function evalUserExpression(src) {
  // ruleid: vm-run-in-this-context-untrusted-code
  return vm.runInThisContext(src);
}

function evalUserExpressionWithTimeout(src) {
  // ruleid: vm-run-in-this-context-untrusted-code
  return vm.runInThisContext(`return (${src})`, { timeout: 50 });
}

function fixedBootstrap() {
  // ok: vm-run-in-this-context-untrusted-code
  return vm.runInThisContext('globalThis.__ready = true');
}

function sandboxed(src) {
  const context = vm.createContext({ console: { log() {} } });
  // ok: vm-run-in-this-context-untrusted-code
  return vm.runInContext(src, context, { timeout: 50 });
}

module.exports = {
  BLOCKED_MODULES,
  denyRequire,
  forbiddenSpecifiers,
  restrictedBuiltins,
  blockedComplete,
  ALLOWED_MODULES,
  blockedUserAgents,
  guardedRequire,
  evalUserExpression,
  evalUserExpressionWithTimeout,
  fixedBootstrap,
  sandboxed,
};
