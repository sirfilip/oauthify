require 'bundler'
Bundler.setup

require 'logger'

require 'sinatra'
require 'sequel'
require 'dry/schema'
require 'dry/monads/all'
require "dry/matcher/result_matcher"
require 'bcrypt'
require 'uuid'
require "rack/csrf"


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
class User
  attr_reader :user_id, :username, :email, :password

  def initialize(opts)
    @user_id = opts[:user_id]
    @username = opts[:username]
    @email = opts[:email]
    @password = opts[:password]
  end
end


# forms
module Form
  class RegisterUser
    include Dry::Monads[:result]

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
end

# repos
module Repo
  class User
    def initialize(db)
      @db = db
    end
    
    def create(user)
      @db[:users].insert(user_id: user.user_id, username: user.username, email: user.email, password: user.password)
    end

    def find(user_id)
    end
  end
end

# services
module Service
  class RegisterUser
    include Dry::Monads[:result]

    def initialize(repo, uuidgen)
      @repo = repo
      @uuidgen = uuidgen
    end

    def call(params)
      password = BCrypt::Password.create(params['password']) 
      user_id = @uuidgen.generate
      user = User.new({user_id: user_id, email: params['email'], username: params['username'], password: password})
      @repo.create(user)
      Success(user)
    rescue => e
      logger.warn(e.message) 
      Failure(:server_error)
    end
  end
end

# sinatra

helpers do
  def errors
    @errors ||= {}
  end

  def csrf_token
    Rack::Csrf.csrf_token(env)
  end

  def csrf_tag
    Rack::Csrf.csrf_tag(env)
  end
end

get '/register' do
  @title = 'register'
  erb :register
end

post '/register' do
  @title = 'register'
  form = Form::RegisterUser.new(DB)
  repo = Repo::User.new(DB)
  svc = Service::RegisterUser.new(repo, UUID.new)
  Dry::Matcher::ResultMatcher.(form.(params).bind(-> (params) { svc.call(params) })) do |m|
    m.success(User) do |_u|
      redirect '/login', 303
    end
    m.failure(:registration_invalid) do |_f,  errors|
      @errors = errors
      erb :register
    end
  
    m.failure(:server_error) do
      halt 500, 'Server Error'
    end
  end
end

get '/login' do
  @title = 'login'
  erb :login
end

post '/login' do
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
    <%= yield %>
  </div>
</body>
</html>

@@register
<h2>Register</h2>
<%= errors.inspect %>
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
<form method="post" action="/login">
  <%= csrf_tag %>
  <div class="row">
    <label for="email">
    <input type="text" name="email" id="email" class="u-full-width" />
  </div>

  <div class="row">
    <label for="password">
    <input type="password" name="password" id="password" class="u-full-width" />
  </div>

  <input type="submit" value="Login" />
</form>
