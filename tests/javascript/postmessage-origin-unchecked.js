// Fixtures for the postMessage origin rules.

const TRUSTED_ORIGINS = ['https://app.example.com', 'https://admin.example.com'];

// ruleid: postmessage-handler-missing-origin-check
window.addEventListener('message', function (event) {
  const { type, payload } = event.data;
  if (type === 'navigate') {
    window.location.href = payload.url;
  }
});

// ruleid: postmessage-handler-missing-origin-check
window.addEventListener('message', (event) => {
  document.getElementById('frame-status').textContent = event.data.status;
});

// Checking event.source alone is not an origin check, but this rule treats any
// mention of `.origin` as a check, so the fixture below uses only `.source`.
// ruleid: postmessage-handler-missing-origin-check
self.onmessage = function (e) {
  if (e.source !== window.parent) return;
  applyTheme(e.data.theme);
};

// ok: postmessage-handler-missing-origin-check
window.addEventListener('message', function (event) {
  if (!TRUSTED_ORIGINS.includes(event.origin)) return;
  const { type, payload } = event.data;
  if (type === 'navigate') {
    window.location.href = payload.url;
  }
});

// ok: postmessage-handler-missing-origin-check
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://app.example.com') {
    return;
  }
  document.getElementById('frame-status').textContent = event.data.status;
});

// A handler that never reads the payload has nothing to validate.
// ok: postmessage-handler-missing-origin-check
window.addEventListener('message', function () {
  bumpMessageCounter();
});

function sendSession(frame, session) {
  // ruleid: postmessage-wildcard-target-origin
  frame.contentWindow.postMessage({ token: session.accessToken }, '*');
}

function relayState(state) {
  // ruleid: postmessage-wildcard-target-origin
  window.parent.postMessage(state, '*');
}

function sendSessionSafely(frame, session) {
  // ok: postmessage-wildcard-target-origin
  frame.contentWindow.postMessage({ token: session.accessToken }, 'https://app.example.com');
}

function pingParent() {
  // A constant carries nothing worth stealing, so the wildcard is acceptable.
  // ok: postmessage-wildcard-target-origin
  window.parent.postMessage('iframe-ready', '*');
}

function applyTheme() {}
function bumpMessageCounter() {}
