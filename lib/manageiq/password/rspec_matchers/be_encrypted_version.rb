require "manageiq-password"

RSpec::Matchers.define :be_encrypted_version do |expected|
  match do |actual|
    ManageIQ::Password.split(actual).first == expected.to_s
  end

  failure_message do |actual|
    actual_version = ManageIQ::Password.split(actual).first
    actual_version_text = actual_version ? "encrypted with version #{actual_version}" : "not encrypted"
    "expected: #{actual.inspect} to be encrypted with version #{expected} but is #{actual_version_text}"
  end

  failure_message_when_negated do |actual|
    "expected: #{actual.inspect} not to be encrypted with version #{expected}"
  end

  description do
    "expect to be encrypted with a particular version of miq password (e.g.: 2)"
  end
end
