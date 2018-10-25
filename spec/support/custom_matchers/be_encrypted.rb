# See also be_decrypted
# decryption doesn't always join unicode characters together correctly. this should not cause an issue
RSpec::Matchers.define :be_encrypted do |expected|
  match do |actual|
    ManageIQ::Password.encrypted?(actual) && (
      expected.nil? ||
      ManageIQ::Password.decrypt(actual) == expected
    )
  end

  failure_message do |actual|
    "expected: #{actual.inspect} to be encrypted#{" and decrypt to #{expected}" if expected}"
  end

  failure_message_when_negated do |actual|
    "expected: #{actual.inspect} not to be encrypted#{" and decrypt to #{expected}" if expected}"
  end

  description do
    "expect to be an encrypted v2 password (with optional encrypted value)"
  end
end
