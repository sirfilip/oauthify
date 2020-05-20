ENV['APP_ENV'] = 'test'

require 'minitest/autorun'
require './app'

# unit 
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

describe Service::RegisterUser  do

end

# integration
