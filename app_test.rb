ENV['APP_ENV'] = 'test'

require 'minitest/autorun'
require 'minitest/pride' # optional but why would you not
require 'mocha/minitest'
require "database_cleaner/sequel"
require 'capybara'
require 'capybara/dsl'
require './app'

DatabaseCleaner[:sequel].strategy = :truncation

describe 'Project' do
  before(:each) do 
    DatabaseCleaner[:sequel].start 
  end

  after(:each) do
    DatabaseCleaner[:sequel].clean
  end

  describe Repo::User do
    let(:repo) { Repo::User.new(DB) }
    let(:user) { Model::User.new({
      username: 'username',
      email: 'username@example.com',
      password: 'pass',
      user_id: '123',
    })}

    it 'creates user' do
      repo.create(user).value!
    end

    describe '#find' do
      it 'returns Some(user) when found' do 
        repo.create(user)
        other = repo.find(user.user_id).value!
        assert user == other
      end

      it 'returns none wien user is not found' do
        result = repo.find(user.user_id).value_or do
          "not found error"
        end
        assert result == "not found error"
      end
    end

    describe '#find_by_email' do
      it 'returns Some(user) when found' do 
        repo.create(user)
        other = repo.find_by_email(user.email).value!
        assert user == other
      end

      it 'returns none wien user is not found' do
        result = repo.find(user.email).value_or do
          "not found error"
        end
        assert result == "not found error"
      end
    end
  end

  describe Form::RegisterUser do
    it 'validates username' do 
      f = Form::RegisterUser.new(DB)
      tests = [
        { 
          username: '',
          error: 'username must be filled',
        },
        {
          username: 'a' * 4,
          error: "username length must be within 5 - 100",
        },
        {
          username: 'a' * 101,
          error: "username length must be within 5 - 100",
        },
      ]
      tests.each do |t|
        result = f.({'username': t[:username]})
        assert_equal result.failure[0], :registration_invalid
        assert_includes result.failure[1][:username], t[:error]
      end
    end

    it 'validates email' do 
      f = Form::RegisterUser.new(DB)
      tests = [
        { 
          email: '',
          error: 'email must be filled',
        },
        {
          email: 'a' * 101,
          error: "email length must be within 1 - 100",
        },
        {
          email: 'non valid email',
          error: 'email is in invalid format',
        }
      ]

      tests.each do |t|
        result = f.({'email': t[:email]})
        assert_equal result.failure[0], :registration_invalid
        assert_includes result.failure[1][:email], t[:error]
      end
    end

    it 'validates password' do 
      f = Form::RegisterUser.new(DB)
      tests = [
        { 
          password: '',
          error: 'password must be filled',
        },
        {
          password: 'a' * 101,
          error: "password length must be within 5 - 100",
        },
        {
          password: 'a' * 4,
          error: "password length must be within 5 - 100",
        },
      ]

      tests.each do |t|
        result = f.({'password': t[:password]})
        assert_equal result.failure[0], :registration_invalid
        assert_includes result.failure[1][:password], t[:error]
      end
    end

    it 'ensures email uniqueness' do
      begin
        email = 'test@example.com'
        DB[:users].insert(:email => email, :username => '', user_id: '')
        f = Form::RegisterUser.new(DB)
        result = f.({'email' => email})
        assert_equal result.failure[0], :registration_invalid
        assert_includes result.failure[1][:email], 'email is already taken'
      ensure
        DB[:users].delete
      end
    end
  end

  describe Form::LoginUser do
    it 'requires both email and password to be set' do
      form = Form::LoginUser.new
      tests = [
        {
          email: '',
          password: '',
          errors: {
            email: ['email must be filled'],
            password: ['password must be filled'],
          },
        },
        {
          email: 'asdfasd',
          password: '',
          errors: {
            password: ['password must be filled'],
          },
        },
        {
          email: '',
          password: 'asdfasdf',
          errors: {
            email: ['email must be filled'],
          },
        },
      ]
      tests.each do |test|
        failure = form.(test).failure
        assert_equal :login_invalid, failure[0] 
        assert_equal test[:errors], failure[1]
      end
    end
  end

  describe Service::RegisterUser  do
    it 'creates user' do
      repo = Repo::User.new(DB)
      svc = Service::RegisterUser.new(repo, stub(:generate => '123'))
      user = svc.({
        'username' => 'test',
        'email'    => 'test@example.com',
        'password' => 'pass',
      }).value!
      assert user.password != 'pass', 'Password is encrypted'
      assert user.user_id == '123', 'User id is properly generated'
      found = Model::User.new(DB[:users].where(user_id: user.user_id).first)
      assert found == user
    end

    it 'fails to create user on db error' do
      repo = Repo::User.new(DB)
      svc = Service::RegisterUser.new(repo, stub(:generate => '123'))
      svc.({
        'username' => 'test',
        'email'    => 'test@example.com',
        'password' => 'pass',
      })
      assert svc.({
        'username' => 'test',
        'email'    => 'test@example.com',
        'password' => 'pass',
      }).failure == :server_error
    end
  end

  describe Service::LoginUser do
    it 'responds with Failure wrong username and password if creds are invalid' do
      svc = Service::LoginUser.new(Repo::User.new(DB))
      assert "wrong email and password combination", svc.({email: 'wrong_email@example.com', password: 'password'}) 
    end

    it 'responds with success user if username and password are valid' do
      user = Service::RegisterUser.new(Repo::User.new(DB), UUID.new).({'username' => 'tester', 'password' => 'password', 'email' => 'tester@example.com'}).value!
      res = Service::LoginUser.new(Repo::User.new(DB)).({'email' => 'tester@example.com', 'password' => 'password'})
      assert res.success?, "Successful login"
      assert user == res.value!, "Got the registered user"
    end
  end
end

# integration
Capybara.app = Sinatra::Application
describe 'Integration' do
  include Capybara::DSL

  before(:each) do 
    DatabaseCleaner[:sequel].start 
  end

  after(:each) do
    DatabaseCleaner[:sequel].clean
  end
  
  describe 'Register Page' do
    it 'has the right fields' do
      visit '/register'
      assert page.has_css?('input[name=email]')
      assert page.has_css?('input[name=username]')
      assert page.has_css?('input[name=password]')
    end

    #TODO add security tests
    describe 'valid registration' do
      it 'creates user' do
        visit '/register'
        fill_in('username', with: 'username')
        fill_in('email', with: 'valid_email@example.com')
        fill_in('password', with: 'password')
        click_button('Register')

        assert_equal '/login', current_path
      end

      it 'shows the right errors' do
        visit '/register'
        fill_in('username', with: 'username')
        fill_in('email', with: 'invalid-email')
        fill_in('password', with: 'password')
        click_button('Register')

        assert_equal '/register', current_path
        assert page.has_content?("Email is in invalid format")
      end
    end
  end

  describe 'Login Page' do
    it 'has the right fields' do
      visit '/login'
      assert page.has_css?('input[name=email]')
      assert page.has_css?('input[name=password]')
    end

    describe 'invalid login creds' do
      it 'shows the right error message' do
        tests = [
          {
            email: '',
            password: '',
            errors: [
              'Email must be filled',
              'Password must be filled',
            ]
          },
          {
            email: 'some@email',
            password: 'password',
            errors: [
              'Wrong email and password combination',
            ],
          },
        ]

        tests.each do |test|
          visit '/login'
          fill_in('email', with: test[:email])
          fill_in('password', with: test[:password])
          click_button('Login')
          test[:errors].each do |error|
            assert page.has_content?(error), "Shows the right error #{error}"
          end
        end
      end
    end

    describe 'valid login' do
      let(:user) { { username: 'tester', email: 'tester@example.com', password: 'password' } }
      before(:each) do
        visit '/register'
        fill_in('username', with: user[:username])
        fill_in('email', with: user[:email])
        fill_in('password', with: user[:password])
        click_button('Register')
      end

      it 'redirects to dashboard' do
        fill_in('email', with: user[:email])
        fill_in('password', with: user[:password])
        click_button('Login')
        assert_equal '/', current_path, "Navigates to home page"
        assert page.has_content?("Welcome back #{user[:username]}"), "Welcomes the logged in user"
      end
    end
  end
end
