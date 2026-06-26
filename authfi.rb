# AuthFI Ruby SDK
#
# Usage (Rails):
#   auth = AuthFI.new(tenant: 'acme', api_key: 'sk_live_...')
#
#   class ApplicationController < ActionController::API
#     before_action :authenticate!
#
#     def authenticate!
#       @current_user = auth.authenticate(request)
#     end
#
#     def require_permission!(*perms)
#       auth.require_permissions!(@current_user, *perms)
#     end
#   end
#
#   class UsersController < ApplicationController
#     before_action -> { require_permission!('read:users') }
#     def index; render json: User.all; end
#   end
#
#   # On startup (config/initializers/authfi.rb)
#   auth.sync!

require 'net/http'
require 'json'
require 'base64'
require 'jwt'

class AuthFI
  class Error < StandardError
    attr_reader :status
    def initialize(message, status: 401)
      super(message)
      @status = status
    end
  end

  # jwks_ttl: how long (seconds) to trust a cached JWKS before refetching.
  # issuer:   override the expected token issuer (`iss` claim). Defaults to
  #           the tenant's public host, e.g. https://acme.authfi.io.
  def initialize(tenant:, api_key:, api_url: 'https://api.authfi.io',
                 application_id: nil, jwks_ttl: 300, issuer: nil)
    @tenant = tenant
    @api_key = api_key
    @api_url = api_url
    @application_id = application_id
    @jwks_ttl = jwks_ttl
    @issuer = issuer
    @registered_permissions = {}

    # JWKS cache: in-memory, short TTL, refetched on unknown kid (rotation).
    @jwks = nil
    @jwks_fetched_at = 0
    @jwks_mutex = Mutex.new
  end

  # Authenticate request, return decoded claims
  def authenticate(request)
    auth = request.headers['Authorization'] || ''
    raise Error.new('Missing authorization') unless auth.start_with?('Bearer ')
    verify_token(auth[7..])
  end

  # Verify JWT, return claims hash.
  #
  # Performs full RS256 signature verification against the tenant's JWKS,
  # then validates exp/nbf/iat and the issuer. Any failure raises
  # AuthFI::Error (status 401). The return value is the decoded claims
  # hash with string keys — backward compatible with the previous
  # base64-only implementation.
  def verify_token(token)
    parts = token.to_s.split('.')
    raise Error.new('Invalid token') unless parts.length == 3

    payload, _header = JWT.decode(
      token,
      nil,
      true, # verify the signature — this is the whole point of the fix
      algorithms: ['RS256'],
      jwks: jwks_loader,
      iss: expected_issuers,
      verify_iss: true,
      verify_expiration: true,
      verify_not_before: true,
      verify_iat: true
    )

    payload
  rescue JWT::ExpiredSignature
    raise Error.new('Token expired')
  rescue JWT::InvalidIssuerError
    raise Error.new('Invalid token issuer')
  rescue JWT::ImmatureSignature
    raise Error.new('Token not yet valid')
  rescue JWT::InvalidIatError
    raise Error.new('Invalid token issued-at')
  rescue JWT::DecodeError => e
    # Covers bad/forged signature, unknown kid, malformed token,
    # unsupported algorithm, JWKS lookup failure, etc.
    raise Error.new("Invalid token: #{e.message}")
  end

  # Check ALL permissions (raises on failure)
  def require_permissions!(claims, *permissions)
    user_perms = claims['permissions'] || []
    permissions.each { |p| register_permission(p) }

    missing = permissions - user_perms
    unless missing.empty?
      raise Error.new("Missing permissions: #{missing.join(', ')}", status: 403)
    end
  end

  # Check ANY role (raises on failure)
  def require_role!(claims, *roles)
    user_roles = claims['roles'] || []
    unless roles.any? { |r| user_roles.include?(r) }
      raise Error.new('Insufficient role', status: 403)
    end
  end

  def register_permission(name, description = nil)
    @registered_permissions[name] ||= description
  end

  # Sync permissions to AuthFI
  def sync!
    return if @registered_permissions.empty?

    body = {
      permissions: @registered_permissions.map { |name, desc|
        h = { name: name }
        h[:description] = desc if desc
        h
      }
    }
    body[:application_id] = @application_id if @application_id

    uri = URI("#{@api_url}/manage/v1/#{@tenant}/permissions/sync")
    req = Net::HTTP::Put.new(uri)
    req['X-API-Key'] = @api_key
    req['Content-Type'] = 'application/json'
    req.body = body.to_json

    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }

    if res.code.to_i < 400
      data = JSON.parse(res.body)
      puts "[authfi] Synced #{data['synced']} permissions (#{data['total']} total)"
    else
      warn "[authfi] Sync failed: #{res.body}"
    end
  end

  private

  # Tenant-scoped auth base, matching the other AuthFI SDKs:
  #   {api_url}/v1/{tenant}
  def auth_url
    "#{@api_url}/v1/#{@tenant}"
  end

  def jwks_url
    "#{auth_url}/.well-known/jwks.json"
  end

  # Issuers the token's `iss` claim may match. AuthFI stamps tokens with
  # the tenant's public host; we also accept the tenant-scoped auth base
  # form for robustness across deployments. A caller-supplied issuer
  # overrides both.
  def expected_issuers
    return [@issuer] if @issuer
    ["https://#{@tenant}.authfi.io", auth_url]
  end

  # Returns a lambda compatible with the jwt gem's `jwks:` option.
  #
  # The gem calls the loader with an options hash. On the first miss for a
  # given kid it sets options[:kid_not_found] (older gems) / options[:invalidate]
  # (newer gems) so the loader can force a refetch — that's how key rotation
  # is handled: an unknown kid triggers exactly one fresh JWKS fetch.
  def jwks_loader
    @jwks_loader ||= ->(options) do
      force = options[:invalidate] || options[:kid_not_found]
      fetch_jwks(force: force)
    end
  end

  # Fetch + cache the JWKS. Cached for @jwks_ttl seconds; `force: true`
  # bypasses the cache (used on unknown-kid to pick up rotated keys).
  def fetch_jwks(force: false)
    @jwks_mutex.synchronize do
      now = Time.now.to_i
      if !force && @jwks && (now - @jwks_fetched_at) < @jwks_ttl
        return @jwks
      end

      uri = URI(jwks_url)
      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
        http.request(Net::HTTP::Get.new(uri))
      end

      unless res.code.to_i < 400
        raise Error.new("JWKS fetch failed: HTTP #{res.code}")
      end

      @jwks = JSON.parse(res.body)
      @jwks_fetched_at = now
      @jwks
    end
  rescue Error
    raise
  rescue StandardError => e
    # Network/parse failures must NOT silently pass — surface as auth error.
    raise Error.new("JWKS fetch failed: #{e.message}")
  end
end
