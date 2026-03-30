require 'minitest/autorun'
require_relative 'authfi'
require 'json'
require 'base64'

class TestAuthFIInit < Minitest::Test
  def test_creates_instance
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    assert_instance_of AuthFI, auth
  end
end

class TestVerifyToken < Minitest::Test
  def make_token(payload, header = { alg: 'RS256', typ: 'JWT', kid: 'test-key-1' })
    h = Base64.urlsafe_encode64(header.to_json, padding: false)
    p = Base64.urlsafe_encode64(payload.to_json, padding: false)
    s = Base64.urlsafe_encode64('fakesig', padding: false)
    "#{h}.#{p}.#{s}"
  end

  def test_rejects_invalid_format
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    assert_raises(AuthFI::Error) { auth.verify_token('not-a-jwt') }
  end

  def test_rejects_expired_token
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    token = make_token({ sub: 'usr_123', exp: Time.now.to_i - 3600 })
    err = assert_raises(AuthFI::Error) { auth.verify_token(token) }
    assert_equal 'Token expired', err.message
  end

  def test_decodes_valid_payload
    auth = AuthFI.new(tenant: 'acme', api_key: 'sk_test')
    token = make_token({
      sub: 'usr_123',
      email: 'jane@acme.com',
      roles: ['admin', 'editor'],
      permissions: ['read:users', 'write:users'],
      org_slug: 'acme-corp',
      exp: Time.now.to_i + 3600
    })
    claims = auth.verify_token(token)
    assert_equal 'usr_123', claims['sub']
    assert_equal 'jane@acme.com', claims['email']
    assert_equal ['admin', 'editor'], claims['roles']
    assert_equal ['read:users', 'write:users'], claims['permissions']
    assert_equal 'acme-corp', claims['org_slug']
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
