require 'minitest/autorun'
require_relative 'authfi'
require 'json'
require 'base64'
require 'jwt'
require 'openssl'

# --- Test signing helpers ---------------------------------------------------
#
# These tests exercise REAL RS256 signature verification. We generate an RSA
# keypair in-process, expose its public half as a JWKS, and stub the SDK's
# network fetch so no HTTP is performed. Tokens are signed with the jwt gem.
#
# NOTE: this suite requires a Ruby runtime with the `jwt` and `openssl` gems.
# It was NOT executed in the authoring environment (no runtime available);
# it is written to run under `ruby test_authfi.rb` / `rake test`.

module SigningHelper
  RSA_KEY = OpenSSL::PKey::RSA.generate(2048)
  KID     = 'test-key-1'

  # A second, unrelated key used to forge signatures the SDK must reject.
  ATTACKER_KEY = OpenSSL::PKey::RSA.generate(2048)

  # JWKS document containing only the public half of RSA_KEY, in the exact
  # shape AuthFI serves at /v1/{tenant}/.well-known/jwks.json.
  def self.jwks
    jwk = JWT::JWK.new(RSA_KEY.public_key, kid: KID)
    # Stringified keys mirror a parsed JSON response.
    JSON.parse({ keys: [jwk.export] }.to_json)
  end

  # Sign a payload with the trusted key (default) or any provided key.
  def self.sign(payload, key: RSA_KEY, kid: KID, alg: 'RS256')
    JWT.encode(payload, key, alg, { kid: kid })
  end

  def self.base_claims(overrides = {})
    {
      'sub'         => 'usr_123',
      'email'       => 'jane@acme.com',
      'roles'       => %w[admin editor],
      'permissions' => %w[read:users write:users],
      'org_slug'    => 'acme-corp',
      'iss'         => 'https://acme.authfi.app',
      'iat'         => Time.now.to_i,
      'exp'         => Time.now.to_i + 3600
    }.merge(overrides)
  end
end

# Build an AuthFI client whose JWKS fetch is stubbed to return our in-memory
# JWKS — no real network calls. The block runs with the stub installed.
def with_stubbed_jwks(auth, jwks = SigningHelper.jwks)
  auth.stub(:fetch_jwks, jwks) { yield }
end

class TestAuthFIInit < Minitest::Test
  def test_creates_instance
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    assert_instance_of AuthFI, auth
  end
end

class TestVerifyToken < Minitest::Test
  def setup
    @auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
  end

  def test_rejects_invalid_format
    assert_raises(AuthFI::Error) { @auth.verify_token('not-a-jwt') }
  end

  # --- Happy path: validly-signed token is accepted ------------------------
  def test_accepts_validly_signed_token
    token = SigningHelper.sign(SigningHelper.base_claims)
    claims = with_stubbed_jwks(@auth) { @auth.verify_token(token) }

    assert_equal 'usr_123', claims['sub']
    assert_equal 'jane@acme.com', claims['email']
    assert_equal %w[admin editor], claims['roles']
    assert_equal %w[read:users write:users], claims['permissions']
    assert_equal 'acme-corp', claims['org_slug']
  end

  # --- Forged signature: signed with the WRONG key -> REJECTED -------------
  def test_rejects_forged_signature
    forged = SigningHelper.sign(
      SigningHelper.base_claims,
      key: SigningHelper::ATTACKER_KEY # attacker's key, not the JWKS key
    )
    err = assert_raises(AuthFI::Error) do
      with_stubbed_jwks(@auth) { @auth.verify_token(forged) }
    end
    assert_equal 401, err.status
  end

  # --- Tampered token: valid signature, then payload mutated -> REJECTED ---
  def test_rejects_tampered_payload
    token = SigningHelper.sign(SigningHelper.base_claims('permissions' => %w[read:users]))
    header_b64, payload_b64, sig_b64 = token.split('.')

    # Attacker rewrites the payload to grant themselves more permissions,
    # keeping the original (now mismatched) signature.
    tampered_payload = JSON.parse(Base64.urlsafe_decode64(payload_b64))
    tampered_payload['permissions'] = %w[read:users write:users delete:users]
    forged_payload_b64 = Base64.urlsafe_encode64(tampered_payload.to_json, padding: false)
    tampered = "#{header_b64}.#{forged_payload_b64}.#{sig_b64}"

    err = assert_raises(AuthFI::Error) do
      with_stubbed_jwks(@auth) { @auth.verify_token(tampered) }
    end
    assert_equal 401, err.status
  end

  # --- Expired token -> REJECTED ------------------------------------------
  def test_rejects_expired_token
    token = SigningHelper.sign(SigningHelper.base_claims('exp' => Time.now.to_i - 3600))
    err = assert_raises(AuthFI::Error) do
      with_stubbed_jwks(@auth) { @auth.verify_token(token) }
    end
    assert_equal 'Token expired', err.message
  end

  # --- Wrong issuer -> REJECTED -------------------------------------------
  def test_rejects_wrong_issuer
    token = SigningHelper.sign(SigningHelper.base_claims('iss' => 'https://evil.example.com'))
    err = assert_raises(AuthFI::Error) do
      with_stubbed_jwks(@auth) { @auth.verify_token(token) }
    end
    assert_equal 401, err.status
  end

  # --- Unknown kid (key rotation): not in JWKS -> REJECTED ----------------
  def test_rejects_unknown_kid
    token = SigningHelper.sign(SigningHelper.base_claims, kid: 'rotated-away-key')
    err = assert_raises(AuthFI::Error) do
      with_stubbed_jwks(@auth) { @auth.verify_token(token) }
    end
    assert_equal 401, err.status
  end

  # --- JWKS fetch failure must NOT silently pass --------------------------
  def test_jwks_fetch_failure_raises
    token = SigningHelper.sign(SigningHelper.base_claims)
    boom = ->(*) { raise AuthFI::Error.new('JWKS fetch failed: boom') }
    err = assert_raises(AuthFI::Error) do
      @auth.stub(:fetch_jwks, boom) { @auth.verify_token(token) }
    end
    assert_equal 401, err.status
  end
end

class TestRequirePermissions < Minitest::Test
  def test_passes_with_matching_permissions
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    claims = { 'permissions' => ['read:users', 'write:users'] }
    assert_nil auth.require_permissions!(claims, 'read:users')
  end

  def test_raises_on_missing_permission
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    claims = { 'permissions' => ['read:users'] }
    err = assert_raises(AuthFI::Error) { auth.require_permissions!(claims, 'delete:users') }
    assert_equal 403, err.status
    assert_includes err.message, 'delete:users'
  end

  def test_handles_empty_permissions
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    claims = {}
    assert_raises(AuthFI::Error) { auth.require_permissions!(claims, 'read:users') }
  end
end

class TestRequireRole < Minitest::Test
  def test_passes_with_matching_role
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    claims = { 'roles' => ['editor'] }
    assert_nil auth.require_role!(claims, 'admin', 'editor')
  end

  def test_raises_on_missing_role
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    claims = { 'roles' => ['viewer'] }
    err = assert_raises(AuthFI::Error) { auth.require_role!(claims, 'admin') }
    assert_equal 403, err.status
  end

  def test_handles_empty_roles
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    claims = {}
    assert_raises(AuthFI::Error) { auth.require_role!(claims, 'admin') }
  end
end

class TestRegisterPermission < Minitest::Test
  def test_registers_permissions
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    auth.register_permission('read:users', 'Read user data')
    auth.register_permission('write:users')
    # No assertion needed — should not raise
  end
end

class TestSyncEmpty < Minitest::Test
  def test_sync_empty_is_noop
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    assert_nil auth.sync!
  end
end

class TestErrorStatus < Minitest::Test
  def test_default_status
    err = AuthFI::Error.new('test')
    assert_equal 401, err.status
  end

  def test_custom_status
    err = AuthFI::Error.new('forbidden', status: 403)
    assert_equal 403, err.status
  end
end
