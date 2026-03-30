# AuthFI Ruby SDK

Official Ruby SDK for [AuthFI](https://authfi.app) — the identity control plane.

## Install

```bash
gem install authfi
```

Or in your Gemfile:

```ruby
gem 'authfi'
```

## Quick Start (Rails)

```ruby
# config/initializers/authfi.rb
AUTH = AuthFI.new(tenant: 'acme', api_key: 'sk_live_...')
AUTH.sync!

# app/controllers/application_controller.rb
class ApplicationController < ActionController::API
  before_action :authenticate!

  private

  def authenticate!
    @current_user = AUTH.authenticate(request)
  end
end

# app/controllers/users_controller.rb
class UsersController < ApplicationController
  before_action -> { AUTH.require_permissions!(@current_user, 'read:users') }

  def index
    render json: User.all
  end
end
```

## Features

- JWT verification (RS256 via JWKS)
- Permission checks — `require_permissions!(claims, 'read:users')`
- Role checks — `require_role!(claims, 'admin')`
- Permission auto-sync to AuthFI console
- Works with Rails, Sinatra, Grape, any Rack app

## Token Verification

```ruby
claims = auth.verify_token(token)
# claims['sub'], claims['email'], claims['roles'], claims['permissions']
```

## Running Tests

```bash
ruby test_authfi.rb
```

## License

MIT
