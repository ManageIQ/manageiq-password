require "bundler/setup"

if ENV['CI']
  require 'simplecov'
  SimpleCov.start
end

require "manageiq-password"
require "manageiq/password/rspec_matchers"

Dir[File.expand_path(File.join(__dir__, 'support/**/*.rb'))].each { |f| require f }

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.before do
    @old_key_root = ManageIQ::Password.key_root
    ManageIQ::Password.key_root = File.join(__dir__, "support")
  end

  config.after do
    ManageIQ::Password.key_root = @old_key_root
  end
end
