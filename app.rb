require 'logger'
require 'securerandom'
require 'json'
require 'bundler'
Bundler.setup

require 'sinatra'
require 'sinatra/flash'
require 'sequel'
require 'dry/schema'
require 'dry/monads/all'
require "dry/matcher/result_matcher"
require 'bcrypt'
require 'uuid'
require "rack/csrf"
require 'byebug'


include Dry::Monads[:result, :maybe]

def logger
  @logger ||= Logger.new(STDOUT)
end

configure do
  set :session_secret, ENV.fetch('SESSION_SECRET') { SecureRandom.hex(64) }
  enable :sessions
  # use Rack::Csrf, :raise => true
end

configure :development do
  logger.info("Running in development mode")
  DB = Sequel.sqlite('dev.db')
end

configure :test do
  logger.info("Running in test environment")
  DB = Sequel.sqlite

  def logger
    @logger ||= Logger.new('/dev/null')
  end
end

configure :production do
  logger.info("Running in production environment")
  DB = Sequel.sqlite('prod.db')
end


# schema
DB.create_table :users do
  primary_key :id
  String :user_id, null: false, unique: true
  String :username, null: false
  String :email, null: false, unique: true
  String :password
end unless DB.table_exists?(:users)

DB.create_table :clients do
  primary_key :id
  String  :client_id, null: false, unique: true
  String  :client_secret, null: false, unique: true
  String  :name, null: false
  String  :redirect_url, null: false
  Integer :user_id, null: false
end unless DB.table_exists?(:clients)

DB.create_table :auth_codes do
  String      :code, null: false, unique: true
  Integer     :client_id, null: false
  Integer     :user_id, null: false
  String      :scope
  String      :state
  String      :redirect_url, null: false
  Time        :created_at, null: false, default: Time.now
  Integer     :lifetime, null: false
  Boolean     :valid, null: false, default: true
end unless DB.table_exists?(:auth_codes)

DB.create_table :tokens do
  String   :token, null: false, unique: true
  String   :refresh_token, null: false, unique: true
  Integer  :user_id, null: false
  String   :scope, null: false
  String   :state
  Time     :created_at, null: false, default: Time.now
  Integer  :lifetime, null: false
  Boolean  :valid, null: false, default: true
end unless DB.table_exists?(:tokens)

# models
module Model
  class User
    attr_reader :id, :user_id, :username, :email, :password

    def initialize(opts)
      @id       = opts[:id]
      @user_id  = opts[:user_id]
      @username = opts[:username]
      @email    = opts[:email]
      @password = opts[:password]
    end

    def ==(other)
      @id = other.id && @user_id == other.user_id && @username == other.username && @email == other.email
    end
  end

  class Client
    attr_reader :id, :client_id, :client_secret, :name, :redirect_url, :user_id

    def initialize(opts)
      @id            = opts[:id]
      @client_id     = opts[:client_id]
      @client_secret = opts[:client_secret]
      @name          = opts[:name]
      @redirect_url  = opts[:redirect_url]
      @user_id       = opts[:user_id]
    end
  end

  class AuthCode
    attr_reader :code, :client_id, :user_id, :scope, :state, :redirect_url, :created_at, :valid, :lifetime

    def initialize(opts)
      @code         = opts[:code] 
      @client_id    = opts[:client_id]
      @user_id      = opts[:user_id]
      @scope        = opts[:scope]
      @state        = opts[:state]
      @redirect_url = opts[:redirect_url]
      @created_at   = opts[:created_at] 
      @valid        = opts[:valid]    
      @lifetime     = opts[:lifetime]
    end

    def expired?
      Time.now - @created_at > @lifetime
    end
  end

  class Token
    attr_reader :token, :refresh_token, :user_id, :scope, :state, :created_at, :valid, :type, :lifetime

    def initialize(opts)
      @token         = opts[:token]
      @refresh_token = opts[:refresh_token]
      @user_id       = opts[:user_id]
      @scope         = opts[:scope]
      @state         = opts[:state]
      @created_at    = opts[:created_at]
      @valid         = opts[:valid]
      @lifetime      = opts[:lifetime]
    end
  end
end


# forms
module Form
  class RegisterUser
    Schema =  Dry::Schema.Params do
      required(:username) { filled? & size?(5..100) }
      required(:email) { filled? & size?(1..100) & format?(/.*@.*/) }
      required(:password) { filled? & size?(5..100) }
    end

    def initialize(db)
      @db = db
    end

    def call(params) 
      errors = Hash.new([]).merge(Schema.(params).errors(full:true).to_h)
      if errors['email'].empty?
        if @db[:users].where(email: params['email']).count > 0 
          errors['email'].push("email is already taken")
        end
      end

      if errors.empty?
        Success(params)
      else
        Failure([:registration_invalid, errors])
      end
    end
  end

  class LoginUser
    Schema = Dry::Schema.Params do
      required(:password) { filled? }
      required(:email) { filled? }
    end

    def call(params)
      errors = Schema.(params).errors(full:true).to_h
      if errors.empty?
        Success(params)
      else
        Failure([:login_invalid, errors])
      end
    end
  end

  class CreateClient
    Schema = Dry::Schema.Params do
      required(:name) { filled? }
      required(:redirect_url) { filled? }
    end

    def call(params)
      errors = Schema.(params).errors(full: true).to_h
      if errors.empty?
        Success(params)
      else
        Failure([:invalid_client, errors])
      end
    end
  end

  class CreateAuthCode
    Schema = Dry::Schema.Params do
      required(:client_id) { filled? }
      required(:redirect_url) { filled? }
      required(:scope) { filled? }
    end

    def call(params)
      errors = Schema.(params).errors(full: true).to_h
      if errors.empty?
        Success(params)
      else
        Failure([:bad_request, errors])
      end
    end
  end

  class ExchangeAuthCode
    Schema = Dry::Schema.Params do
      required(:redirect_url) { filled? }
      required(:client_id) { filled? }
      required(:client_secret) { filled? }
      required(:code) { filled? }
    end
    
    def call(params)
      errors = Schema.(params).errors(full: true).to_h
      if errors.empty?
        Success(params)
      else
        Failure([:bad_request, errors])
      end
    end
  end
end

# repos
module Repo
  class User
    def initialize(db)
      @db = db
    end
    
    def create(user)
      id = @db[:users].insert(user_id: user.user_id, username: user.username, email: user.email, password: user.password)
      user = Model::User.new({
        id: id,
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        password: user.password,
      })
      Success(user)
    rescue => e 
      logger.error(e)
      Failure(:server_error)
    end

    def find(user_id)
      record = @db[:users].where(:user_id => user_id).first
      if record
        Success(Model::User.new(record))
      else
        Failure(:record_not_found)
      end
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end

    def find_by_id(id)
      record = @db[:users].where(:id => id).first
      if record
        Success(Model::User.new(record))
      else
        Failure(:record_not_found)
      end
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end

    def find_by_email(email)
      record = @db[:users].where(email: email).first
      if record
        Success(Model::User.new(record))
      else
        Failure(:record_not_found)
      end
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end
  end

  class Client
    def initialize(db)
      @db = db
    end

    def create(client)
      id = @db[:clients].insert({
        client_id: client.client_id,
        client_secret: client.client_secret,
        name: client.name,
        redirect_url: client.redirect_url,
        user_id: client.user_id,
      })
      Success(Model::Client.new({
        id: id,
        client_id: client.client_id,
        client_secret: client.client_secret,
        name: client.name,
        redirect_url: client.redirect_url,
        user_id: client.user_id,
      }))
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end

    def owned_by(user)
      clients = @db[:clients].where(user_id: user.id).map do |row|
        Model::Client.new(row)
      end
      Success(clients)
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end

    def find(client_id)
      record = @db[:clients].where(client_id: client_id).first
      if record 
        Success(Model::Client.new(record))
      else
        Failure(:record_not_found)
      end
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end

    def find_by(conditions)
      record = @db[:clients].where(conditions).first
      if record 
        Success(Model::Client.new(record))
      else
        Failure(:record_not_found)
      end
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end

    def delete(client)
      @db[:clients].where(id: client.id).delete
      Success(client)
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end
  end

  class AuthCode
    def initialize(db)
      @db = db
    end

    def create(auth_code)
      _ = @db[:auth_codes].insert({
        code: auth_code.code,
        client_id: auth_code.client_id,
        user_id: auth_code.user_id,
        scope: auth_code.scope,
        state: auth_code.state,
        redirect_url: auth_code.redirect_url,
        created_at: auth_code.created_at,
        lifetime: auth_code.lifetime,
        valid: auth_code.valid,
      })
      Success(auth_code)
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end

    def find_by(conditions)
      record = @db[:auth_codes].where(conditions).first
      if record
        Success(Model::AuthCode.new(record))
      else
        Failure(:record_not_found)
      end
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end

    def delete(auth_code)
      @db[:auth_codes].where(code: auth_code.code).delete
      Success(auth_code)
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end
  end

  class Token
    def initialize(db)
      @db = db
    end

    def find(token)
      record = @db[:tokens].where(token: token).first
      if record
        Success(Model::Token.new(record))
      else
        Failure(:record_not_found)
      end
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end

    def create(token)
      _ = @db[:tokens].insert(
        token:         token.token,
        refresh_token: token.refresh_token,
        user_id:       token.user_id,
        scope:         token.scope,
        created_at:    token.created_at,
        valid:         token.valid,
        lifetime:      token.lifetime,
      )
      Success(token)
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end
  end
end

# services
module Service
  module URL
    def self.append_query_params_to(uri, params)
      uri = URI.parse(uri.to_s)
      query = uri
                .query
                .to_s
                .split('&')
      params.each do |key, val|
        query.push("#{key}=#{val}")
      end
      uri.query = query.join('&')
      uri.to_s
    end
  end

  class RegisterUser
    def initialize(repo, uuidgen)
      @repo = repo
      @uuidgen = uuidgen
    end

    def call(params)
      password = BCrypt::Password.create(params['password']) .to_s
      user_id = @uuidgen.generate
      user = Model::User.new({user_id: user_id, email: params['email'], username: params['username'], password: password})
      @repo.create(user)
    end
  end

  class LoginUser
    def initialize(repo)
      @repo = repo
    end

    def call(params)
      @repo.find_by_email(params['email']).bind do |user|
        if BCrypt::Password.new(user.password) == params['password']
          return Success(user)
        end
      end
      Failure('wrong email and password combination')
    end
  end

  class CreateClient
    def initialize(repo, uuidgen)
      @repo = repo
      @uuidgen = uuidgen
    end

    def call(params)
      client_id = @uuidgen.generate
      client_secret = @uuidgen.generate
      client = Model::Client.new({
        client_id: client_id,
        client_secret: client_secret,
        name: params['name'],
        redirect_url: params['redirect_url'],
        user_id: params['user_id'],
      })
      @repo.create(client)
    end
  end

  class CreateAuthCode
    def initialize(user, repo, uuidgen)
      @user = user
      @repo = repo
      @uuidgen = uuidgen
    end

    def call(params)
      return Failure([
        :grant_rejected, 
        URL.append_query_params_to(params['redirect_url'], { 'error' => 'rejected' })
      ]) unless params.key?('allow')
      code = @uuidgen.generate
      auth_code = Model::AuthCode.new({
        code: code,
        client_id: params['client_id'],
        redirect_url: params['redirect_url'],
        user_id: @user.id,
        scope: params['scope'],
        state: params['state'],
        valid: true,
        created_at: Time.now,
        lifetime: 5 * 60,
      })
      @repo.create(auth_code)
      Success(URL.append_query_params_to(auth_code.redirect_url, { 'code' => auth_code.code, 'state' => auth_code.state }))
    rescue => e
      logger.error(e)
      Failure(:server_error)
    end
  end


  class ExchangeAuthCode
    def initialize(auth_code_repo, token_repo, uuidgen)
      @auth_code_repo = auth_code_repo
      @token_repo = token_repo
      @uuidgen = uuidgen
    end

    def call(auth_code)
      if Time.now - auth_code.created_at > auth_code.lifetime
        @auth_code_repo.delete(auth_code).bind do |auth_code|
          return Failure(:auth_code_expired)
        end
      end
      code = @uuidgen.generate
      refresh_token = @uuidgen.generate
      token = Model::Token.new(
        token: code,
        refresh_token: refresh_token,
        user_id: auth_code.user_id,
        scope: auth_code.scope,
        valid: true,
        created_at: Time.now,
        lifetime: 3600,
      )

      @token_repo.create(token) do |token|
        @auth_code_repo.delete(auth_code) do |_|
          Success(token)
        end
      end
    end
  end
end


# authorization
module Authorization
  class ClientPolicy
    def initialize(user, client)
      @user = user
      @client = client
    end

    def delete?
      @client.user_id == @user.id
    end
  end
end 

# sinatra

set(:protected) do |_|
  condition do
    unless current_user
      flash[:warning] = 'Login please'
      redirect "/login?next=#{URI.encode_www_form_component(env.fetch('REQUEST_URI', '/'))}", 303
    end
  end
end

helpers do
  def current_user
    @current_user ||= session[:user_id] && Repo::User.new(DB).find(session[:user_id]).value_or(nil)
  end

  def errors
    @errors ||= {}
  end

  def csrf_token
    Rack::Csrf.csrf_token(env)
  end

  def csrf_tag
    Rack::Csrf.csrf_tag(env)
  end

  def title(title)
    @title = title
  end

  def authorize!(object, method)
    policy_clazz = Authorization.const_get("#{object.class.name.split("::").last}Policy")  
    policy = policy_clazz.new(current_user, object)
    if policy.send(:"#{method}?")
      Success(object) 
    else
      Failure([:access_forbidden, object, method])
    end
  rescue => e
    logger.error(e)
    Failure(:server_error)
  end
end

get '/register' do
  title 'register'
  erb :register
end

post '/register' do
  title 'register'
  form = Form::RegisterUser.new(DB)
  repo = Repo::User.new(DB)
  svc = Service::RegisterUser.new(repo, UUID.new)
  Dry::Matcher::ResultMatcher.(
    form.(params)
      .bind(-> (params) { svc.call(params) })
  ) do |m|
    m.success(Model::User) do |_|
      redirect '/login', 303
    end
    m.failure(:registration_invalid) do |_,  errors|
      @errors = errors
      erb :register
    end
  
    m.failure(:server_error) do
      halt 500, 'Server Error'
    end
  end
end

get '/login' do
  title 'login'
  erb :login
end

post '/login' do
  title 'login'
  form = Form::LoginUser.new()
  svc = Service::LoginUser.new(Repo::User.new(DB))
  Dry::Matcher::ResultMatcher.(
    form.(params)
      .bind(->(params){ svc.call(params) })
  ) do |m|
    m.success(Model::User) do |user|
      session[:user_id] = user.user_id
      flash[:success] = "Welcome back #{user.username}"
      redirect params['next'] || '/', 303
    end
    
    m.failure(:login_invalid) do |_, errors|
      @errors = errors
      erb :login
    end

    m.failure do |error|
      @errors = {base: [error]}
      erb :login
    end

    m.failure(:server_error) do
      halt 500, 'Server Error'
    end
  end
end

get '/logout' do
  session[:user_id] = nil
  flash[:success] = "Logged out successfully!"
  redirect '/login', 303
end

get '/', :protected => true do
  title "dashboard"
  repo = Repo::Client.new(DB)
  Dry::Matcher::ResultMatcher.(repo.owned_by(current_user)) do |m|
    m.success do |clients|
      @clients = clients
      erb :dashboard
    end

    m.failure(:server_error) do |_|
      halt 500, 'Server Error'
    end
  end
end

get "/clients/new", :protected => true do
  title "add-new-client"
  erb :client_new
end

post "/clients", :protected => true do
  title "add-new-client"
  form = Form::CreateClient.new
  svc = Service::CreateClient.new(Repo::Client.new(DB), UUID.new)
  params['user_id'] = current_user.id
  Dry::Matcher::ResultMatcher.(
    form.(params)
      .bind(->(params) { svc.(params) })
  ) do |m|
    m.success(Model::Client) do |_| 
      flash[:success] = "Client successfully created"
      redirect '/', 303
    end

    m.failure(:invalid_client) do |_, errors|
      @errors = errors
      erb :client_new
    end
  end
end

get "/clients/:id/delete", :protected => true do |id|
  repo = Repo::Client.new(DB)
  Dry::Matcher::ResultMatcher.(
    repo.find(id)
      .bind(->(client) { authorize! client, :delete })
      .bind(->(client) { repo.delete(client) })
  ) do |m|
    m.success do |client|
      flash[:success] = "Client successfully deleted"
      redirect '/', 303
    end

    m.failure(:access_forbidden) do |_, client, method|
      halt 403, "You are not allowed to perform #{method} on #{client.name}"
    end

    m.failure(:server_error) do |_|
      halt 500, 'Server Error'
    end
  end
end

get '/auth', :protected => true do
  pass if params[:response_type] != 'code'
  form = Form::CreateAuthCode.new
  repo = Repo::Client.new(DB)
  Dry::Matcher::ResultMatcher.(
    form.(params)
      .bind(->(params) { repo.find_by({client_id: params['client_id'], redirect_url: params['redirect_url']}) })
  ) do |m|
    m.success do |client|
      @client = client
      @scope = params['scope']
      erb :auth_grant     
    end

    m.failure(:server_error) do
      halt 500, "Server Error"
    end

    m.failure(:record_not_found) do
      halt 404, "Not Found" 
    end

    m.failure(:bad_request) do |_, errors|
      halt 400, errors.to_json
    end
  end
end

post '/auth', :protected => true do
  pass if params[:response_type] != 'code'
  form = Form::CreateAuthCode.new
  client_repo = Repo::Client.new(DB)
  auth_code_repo = Repo::AuthCode.new(DB)
  svc = Service::CreateAuthCode.new(current_user, auth_code_repo, UUID.new)
  Dry::Matcher::ResultMatcher.(
    form.(params)
      .bind(->(params) { client_repo.find_by({client_id: params['client_id'], redirect_url: params['redirect_url']}) })
      .bind(->(_) { svc.(params) })
  ) do |m|
    m.success do |url|
      redirect url, 303
    end

    m.failure(:server_error) do
      halt 500, "Server Error"
    end

    m.failure(:record_not_found) do
      halt 404, "Not Found" 
    end

    m.failure(:bad_request) do |_, errors|
      halt 400, errors.to_json
    end

    m.failure(:grant_rejected) do |_, url| 
      redirect url, 303
    end
  end

end

post '/token' do
  pass if params['grant_type'] != 'authorization_code'
  form = Form::ExchangeAuthCode.new
  client_repo = Repo::Client.new(DB)
  auth_code_repo = Repo::AuthCode.new(DB)
  token_repo = Repo::Token.new(DB)
  svc = Service::ExchangeAuthCode.new(
    auth_code_repo,
    token_repo,
    UUID.new,
  )
  Dry::Matcher::ResultMatcher.(
    form.(params)
      .bind(->(params) { client_repo.find_by(client_id: params['client_id'], client_secret: params['client_secret'], redirect_url: URI.decode_www_form_component(params['redirect_url'])) })
      .bind(->(client) { auth_code_repo.find_by(code: params['code'], client_id: client.client_id, valid: true) })
      .bind(->(auth_code) { svc.(auth_code) })
  ) do |m|
    m.success do |token|
      return {
        access_token: token.token,
        expires_in: token.lifetime,
      }.to_json
    end

    m.failure(:server_error) do
      halt 500, "Server Error"
    end

    m.failure(:record_not_found) do
      halt 404, { "error" => "not found" }.to_json
      # halt 400, { "error" => "invalid_request" }.to_json
    end

    m.failure(:bad_request) do |_, _|
      halt 400, { "error" => "invalid_request" }.to_json
    end

    m.failure(:auth_code_expired) do
      halt 400, { "error" => "code expired" }.to_json
      # halt 400, { "error" => "invalid_request" }.to_json
    end
  end
end

post '/auth/refresh' do

end

get '/auth/me' do

end


__END__

@@layout
<!doctype html>
<html>
<head>
  <title><%= @title %></title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/skeleton/2.0.4/skeleton.css" />
  <style>
    body {
      background: #fafafa;
      color: #6f6f6f;
    }

    .flash {
      border: 1px solid #ccc;
      padding: 10px;
    }
    .flash-success {
      border-top-color: rgb(204, 204, 204);
      border-right-color: rgb(204, 204, 204);
      border-bottom-color: rgb(204, 204, 204);
      border-left-color: rgb(204, 204, 204);
      border-color: #090;
      background: #070;
      color: #fff;
    }
    .flash-warning {
      border-color: #900;
      background: #700;
      color: #fff;
    }
    .header {
      padding: 10px;
      border: 1px solid #ccc;
      margin-bottom: 10px;
    }
    .grant-form {
      border: 1px solid #ccc;
      padding: 30px;
      text-align: center;
      margin: 0px auto;
      width: 620px;
    }
    .client-name, .scope {
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="container">
    <% flash.keys.each do |type| %>
      <div class="flash flash-<%= type %>">
        <%= flash[type] %>
      </div>
    <% end %>

    <% if current_user %>
      <div class="header">
          <a href="/logout">Logout</a>
      </div>
    <% end %>

    <%= yield %>
  </div>
</body>
</html>

@@register
<h2>Register</h2>
<ul class="errors">
<% errors.each do |key, messages| %>
  <% messages.each do |msg| %>
  <li><%= msg.capitalize %></li>
  <% end %>
<% end %>
</ul>
<form method="post" action="/register">
  <%= csrf_tag %>
  <div class="row">
    <label for="username">Username</label>
    <input type="text" name="username" id="username" class="u-full-width"/>
  </div>

  <div class="row">
    <label for="email">Email</label>
    <input type="text" name="email" id="email" class="u-full-width" />
  </div>

  <div class="row">
    <label for="password">Password</label>
    <input type="password" name="password" id="password" class="u-full-width" />
  </div>

  <input type="submit" value="Register" />
</form>

@@login
<h2>Login</h2>
<ul class="errors">
<% errors.each do |key, messages| %>
  <% messages.each do |msg| %>
  <li><%= msg.capitalize %></li>
  <% end %>
<% end %>
</ul>
<form method="post" action="">
  <%= csrf_tag %>
  <div class="row">
    <label for="email">Email</label>
    <input type="text" name="email" id="email" class="u-full-width" />
  </div>

  <div class="row">
    <label for="password">Password</label>
    <input type="password" name="password" id="password" class="u-full-width" />
  </div>

  <input type="submit" value="Login" />
</form>

@@dashboard
<h2>Dashboard</h2>
<a href="/clients/new">Add new client</a>
<% if @clients.any? %>
  <table class="u-full-width">
    <thead>
      <tr>
        <th>Name</th>
        <th>Redirect URL</th>
        <th>Client ID</th>
        <th>Client Secret</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      <% @clients.each do |client| %>
        <tr>
          <td><%= client.name %></td>
          <td><%= client.redirect_url %></td>
          <td><%= client.client_id %></td>
          <td><%= client.client_secret %></td>
          <td>
            <a href="/clients/<%= client.client_id %>/delete">Delete</a>
          </td>
        </tr>
      <% end %>
  </table>
<% end %>

@@client_new
<h2>Add New Client</h2>
<ul class="errors">
<% errors.each do |key, messages| %>
  <% messages.each do |msg| %>
  <li><%= msg.capitalize %></li>
  <% end %>
<% end %>
</ul>
<form method="post" action="/clients">
  <%= csrf_tag %>
  <div class="row">
    <label for="name">Name</label>
    <input type="text" name="name" id="name" class="u-full-width" />
  </div>

  <div class="row">
    <label for="redirect_url">Callback URL</label>
    <input type="text" name="redirect_url" id="redirect_url" class="u-full-width" />
  </div>

  <input type="submit" value="Submit" />
</form>

@@auth_grant
<div class="grant-form">
  <h2>An application would like to connect to your account</h2>

  <p>The app <span class="client-name"><%= @client.name %></span> would like the ability to access your <span class="scope"><%= @scope %></span></p>

  <p>Allow <span class="client-name"><%= @client.name %></span> access?</p>

  <form method="post" action="">
    <%= csrf_tag %>
    <input type="hidden" name="client_id" value="<%= params['client_id'] %>" />
    <input type="hidden" name="redirect_uri" value="<%= params['redirect_url'] %>" />
    <input type="hidden" name="scope" value="<%= params['scope'] %>" />
    <input type="hidden" name="state" value="<%= params['state'] %>" />
    <input type="submit" value="Allow" name="allow" class="button" />
    <input type="submit" value="Deny" name="deny" class="button" />
  </form>
</div>
