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

class AuthFI
  class Error < StandardError
    attr_reader :status
    def initialize(message, status: 401)
      super(message)
      @status = status
    end
  end

  def initialize(tenant:, api_key:, api_url: 'https://api.authfi.app', application_id: nil)
    @tenant = tenant
    @api_key = api_key
    @api_url = api_url
    @application_id = application_id
    @registered_permissions = {}
  end

  # Authenticate request, return decoded claims
  def authenticate(request)
    auth = request.headers['Authorization'] || ''
    raise Error.new('Missing authorization') unless auth.start_with?('Bearer ')
    verify_token(auth[7..])
  end

  # Verify JWT, return claims hash
  def verify_token(token)
    parts = token.split('.')
    raise Error.new('Invalid token') unless parts.length == 3

    payload = JSON.parse(Base64.urlsafe_decode64(parts[1] + '=='))

    if payload['exp'] && payload['exp'] < Time.now.to_i
      raise Error.new('Token expired')
    end

    # NOTE: For production, verify RS256 signature using jwt gem
    payload
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
end
