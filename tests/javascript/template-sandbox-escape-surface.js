// Fixtures for template-context-exposes-host-capability.
//
// The shape here stands in for a report/notification renderer: a template is
// pulled from storage and rendered with a context assembled by the caller.

const nunjucks = require('nunjucks');
const ejs = require('ejs');
const childProcess = require('child_process');

function renderReport(templateSource, report) {
  // ruleid: template-context-exposes-host-capability
  return nunjucks.renderString(templateSource, {
    report,
    require: require,
  });
}

function renderInvoice(templateSource, invoice) {
  // ruleid: template-context-exposes-host-capability
  return ejs.render(templateSource, {
    invoice,
    env: process,
  });
}

function renderWithExec(templateSource, data) {
  // ruleid: template-context-exposes-host-capability
  return nunjucks.renderString(templateSource, {
    data,
    shell: require('child_process'),
  });
}

function renderViaCompiled(templateSource, data) {
  const compiled = ejs.compile(templateSource);
  // ruleid: template-context-exposes-host-capability
  return compiled({ data, Fn: Function });
}

function renderEscapeViaConstructor(templateSource, data) {
  // ruleid: template-context-exposes-host-capability
  return nunjucks.renderString(templateSource, {
    data,
    ctor: data.constructor,
  });
}

// Plain serialisable data: nothing in the context reaches the host realm.
function renderReportSafely(templateSource, report) {
  // ok: template-context-exposes-host-capability
  return nunjucks.renderString(templateSource, {
    title: report.title,
    rows: report.rows,
    total: report.total,
  });
}

// Host access is resolved before rendering, so the result is a string.
function renderInvoiceSafely(templateSource, invoice) {
  const hostname = process.env.HOSTNAME;
  // ok: template-context-exposes-host-capability
  return ejs.render(templateSource, {
    invoice,
    hostname,
  });
}

// A helper object is deliberately not flagged: see the rule's metadata note.
function renderWithHelpers(templateSource, data) {
  const helpers = { formatDate: (d) => new Date(d).toISOString() };
  // ok: template-context-exposes-host-capability
  return nunjucks.renderString(templateSource, { data, helpers });
}

// Using the host capability outside the context is not this bug.
function runLocalCommand(cmd) {
  // ok: template-context-exposes-host-capability
  return childProcess.execFileSync(cmd, [], { timeout: 1000 });
}

module.exports = {
  renderReport,
  renderInvoice,
  renderWithExec,
  renderViaCompiled,
  renderEscapeViaConstructor,
  renderReportSafely,
  renderInvoiceSafely,
  renderWithHelpers,
  runLocalCommand,
};
