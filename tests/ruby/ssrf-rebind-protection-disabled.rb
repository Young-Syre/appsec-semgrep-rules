# frozen_string_literal: true
#
# Fixtures for ssrf-rebind-protection-disabled.
#
# These stand in for an unauthenticated preview/probe endpoint that fetches a
# user-supplied URL server-side. The HTTP wrapper already resolves the host once
# and connects to the resolved address; each call below opts out of that.

module LinkPreview
  def self.fetch(url)
    # ruleid: ssrf-rebind-protection-disabled
    Internal::HTTP.get(url, dns_rebind_protection: false)
  end

  def self.notify(url, payload)
    # ruleid: ssrf-rebind-protection-disabled
    Internal::HTTP.post(url, body: payload.to_json, allow_local_requests: true)
  end

  def self.head_check(url)
    # ruleid: ssrf-rebind-protection-disabled
    Internal::HTTP.try_get(url, { dns_rebind_protection: false })
  end

  def self.probe_localhost(url)
    # ruleid: ssrf-rebind-protection-disabled
    HttpClient.request(url, method: :get, allow_localhost: true)
  end

  # The wrapper's defaults resolve once and connect to the resolved address.
  def self.fetch_safely(url)
    # ok: ssrf-rebind-protection-disabled
    Internal::HTTP.get(url, headers: { 'User-Agent' => 'link-preview' })
  end

  # Opting in explicitly is fine; the rule only looks for the protection being
  # turned off.
  def self.notify_safely(url, payload)
    # ok: ssrf-rebind-protection-disabled
    Internal::HTTP.post(url, body: payload.to_json, dns_rebind_protection: true, allow_local_requests: false)
  end

  # Not an HTTP request: a settings hash that happens to carry the same key.
  def self.default_options
    # ok: ssrf-rebind-protection-disabled
    Settings.merge(dns_rebind_protection: false)
  end

  # Validation with local networks explicitly refused.
  def self.validate(url)
    # ok: ssrf-rebind-protection-disabled
    Internal::UrlBlocker.validate!(url, allow_local_network: false, allow_localhost: false)
  end
end
