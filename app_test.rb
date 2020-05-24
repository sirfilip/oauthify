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

  describe Form::CreateClient do
    it 'returns the right error messages' do
      form = Form::CreateClient.new
      tests = [
        {
          name: '',
          callback_url: '',
          errors: {
            name: ['name must be filled'],
            callback_url: ['callback_url must be filled'],
          },
        },
      ]
      tests.each do |test|
        failure = form.({'name' => test[:name], 'callback_url' => test[:callback_url]}).failure
        assert_equal :invalid_client, failure[0], "Has the right failure"
        assert_equal test[:errors], failure[1], "Returns the correct errors"
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

  describe Service::CreateClient do
    it 'creates client' do
      svc = Service::CreateClient.new(Repo::Client.new(DB), UUID.new)
      result = svc.({
        'name' => 'client_name',
        'callback_url' => 'https://example.com',
        'user_id' => 1,
      })
      assert result.success?, "Result is successful"
      client = result.value!
      assert !client.id.nil?, "id is generated"
      assert !client.client_id.nil?, "client id is generated"
      assert !client.client_secret.nil?, "client secret is present"
    end
  end
end

# integration
Capybara.app = Sinatra::Application
describe 'Integration' do
  include Capybara::DSL

  let(:user) { Model::User.new(username: 'tester', email: 'tester@example.com', password: 'password') }

  def login(user)
    visit '/login'
    fill_in('email', with: user.email)
    fill_in('password', with: user.password)
    click_button('Login')
  end

  def logout
    visit '/logout'
  end

  def register(user)
    visit '/register'
    fill_in('username', with: user.username)
    fill_in('email', with: user.email)
    fill_in('password', with:user.password)
    click_button('Register')
  end

  def create_client(params)
    visit '/clients/new'
    fill_in('name', with: params[:name])
    fill_in('callback_url', with: params[:callback_url])
    click_button('Submit')
  end

  let(:register!) {
    register user
  }
  
  let(:login!) {
    register!
    login user
  }

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
        fill_in('username', with: user.username)
        fill_in('email', with: user.email)
        fill_in('password', with: user.password)
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
      it 'redirects to dashboard' do
        register!
        fill_in('email', with: user.email)
        fill_in('password', with: user.password)
        click_button('Login')
        assert_equal '/', current_path, "Navigates to home page"
        assert page.has_content?("Welcome back #{user.username}"), "Welcomes the logged in user"
      end
    end
  end

  describe 'Logout' do
    it 'logs user out' do
      login!
      visit '/logout'
      assert '/login', current_path
      assert page.has_content?('Logged out successfully!')
      visit '/'
      assert '/login', current_path
      assert page.has_content?('Members only')
    end
  end

  describe 'Dashboard Page' do
    it 'is protected' do
      visit '/'
      assert_equal '/login', current_path
    end

    it 'shows a link to add new client' do
      login!
      visit '/'
      click_link("Add new client")
      assert_equal "/clients/new", current_path
      logout
    end

    it 'shows clients owned by the current user' do
      other = Model::User.new({ username: 'other', email: 'other@example.com', password: 'password'})
      register other
      login other
      create_client({ name: 'other client', callback_url: 'https://other.example.com'})
      logout
      login!
      create_client({name: 'client name', callback_url: 'https://example.com'})
      visit '/'
      assert page.has_content?('client name'), 'Shows owned clients name'
      assert page.has_content?('https://example.com'), 'Shows owned clients callback url'
      assert !page.has_content?('other client'), 'Does not show other clients name'
      assert !page.has_content?('https://other.example.com'), 'Does not show other clients callback url'
      logout
    end

    it 'can delete a client' do
      login!
      create_client({name: 'client name', callback_url: 'https://example.com'})
      click_link("Delete")
      assert page.has_content?("Client successfully deleted")
      logout
    end

    it 'does not allow to delete clients not in ownership' do
      login!
      create_client({name: 'client name', callback_url: 'https://example.com'})
      delete_client_url = page.find("td a")[:href]
      logout
      other = Model::User.new({ username: 'other', email: 'other@example.com', password: 'password'})
      register other
      login other
      visit delete_client_url
      assert page.has_content?("You are not allowed to perform delete on client name"), 'It does not allow to delete clients that are not owned by us'
      logout
    end
  end

  describe "Clients New Page" do
    before(:each) do
      login!
    end

    after(:each) do
      logout
    end

    it 'has the right fields' do
      visit '/clients/new'
      assert page.has_css?('input[name=name]')
      assert page.has_css?('input[name=callback_url]')
    end

    it 'shows the correct errors' do
      visit '/clients/new'
      tests = [
        {
          name: '',
          callback_url: '',
          errors: [
            'Name must be filled',
            'Callback_url must be filled',
          ],
        },
      ]

      tests.each do |test|
        fill_in('name', with: test[:name])
        fill_in('callback_url', with: test[:callback_url])
        click_button('Submit')
        test[:errors].each do |err|
          assert page.has_content?(err), "Shows the right error message: #{err}"
        end
      end
    end

    it 'creates client' do 
      visit '/clients/new'
      fill_in('name', with: 'Test Client')
      fill_in('callback_url', with: 'https://example.com')
      click_button('Submit')
      assert_equal '/', current_path, "Redirected to dasboard"
      assert page.has_content?("Client successfully created")
    end
  end
end
