require 'logger'
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


include Dry::Monads[:result, :maybe]

def logger
  @logger ||= Logger.new(STDOUT)
end

configure do
  enable :sessions
  use Rack::Csrf, :raise => true
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

# models
module Model
  class User
    attr_reader :user_id, :username, :email, :password

    def initialize(opts)
      @user_id = opts[:user_id]
      @username = opts[:username]
      @email = opts[:email]
      @password = opts[:password]
    end

    def ==(other)
      @user_id == other.user_id && @username == other.username && @email == other.email
    end
  end
end


# forms
module Form
  class RegisterUser
    RegisterUserSchema =  Dry::Schema.Params do
      required(:username) { filled? & size?(5..100) }
      required(:email) { filled? & size?(1..100) & format?(/.*@.*/) }
      required(:password) { filled? & size?(5..100) }
    end

    def initialize(db)
      @db = db
    end

    def call(params) 
      errors = Hash.new([]).merge(RegisterUserSchema.(params).errors(full:true).to_h)
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
    LoginUserSchema = Dry::Schema.Params do
      required(:password) { filled? }
      required(:email) { filled? }
    end

    def call(params)
      errors = LoginUserSchema.(params).errors(full:true).to_h
      if errors.empty?
        Success(params)
      else
        Failure([:login_invalid, errors])
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
      Success(id)
    rescue => e 
      logger.warn(e)
      Failure(:server_error)
    end

    def find(user_id)
      record = @db[:users].where(:user_id => user_id).first
      if record
        Some(Model::User.new(record))
      else
        None()
      end
    end

    def find_by_email(email)
      record = @db[:users].where(email: email).first
      if record
        Some(Model::User.new(record))
      else
        None()
      end
    end
  end
end

# services
module Service
  class RegisterUser
    def initialize(repo, uuidgen)
      @repo = repo
      @uuidgen = uuidgen
    end

    def call(params)
      password = BCrypt::Password.create(params['password']) .to_s
      user_id = @uuidgen.generate
      user = Model::User.new({user_id: user_id, email: params['email'], username: params['username'], password: password})
      value = @repo.create(user)
      case value
      when Success 
        Success(user)
      when Failure 
        value
      else
        raise "Unhandled case"
      end
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
end

# sinatra

set(:protected) do |_|
  condition do
    unless current_user
      redirect '/login', 303
    end
  end
end

helpers do
  def current_user
    @current_user ||= session[:user_id] && Repo::User.new(DB).find(session[:user_id]).or(nil)
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
  Dry::Matcher::ResultMatcher.(form.(params).bind(-> (params) { svc.call(params) })) do |m|
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
  Dry::Matcher::ResultMatcher.(form.(params).bind(->(params){ svc.call(params) })) do |m|
    m.success(Model::User) do |user|
      session[:user_id] = user.user_id
      flash[:success] = "Welcome back #{user.username}"
      redirect '/', 303
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

get '/', :protected => true do
  title "dashboard"
  erb :dashboard
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
  </style>
</head>
<body>
  <div class="container">

    <% flash.keys.each do |type| %>
      <div class="flash flash-<%= type %>">
        <%= flash[type] %>
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
<form method="post" action="/login">
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
