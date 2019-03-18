RSpec::Matchers.define :be_encrypted do |expected|
  match do |actual|
    ManageIQ::Password.encrypted?(actual) && (
      expected.nil? ||
      ManageIQ::Password.decrypt(actual) == expected
    )
  end

  # On negation, we don't want to check the expected at all, otherwise it can
  #   result in false positives. It doesn't make sense to check a decrypted value
  #   anyway, since we are claiming that we don't expect it to be encrypted.
  match_when_negated do |actual|
    !ManageIQ::Password.encrypted?(actual)
  end

  failure_message do |actual|
    "expected: #{actual.inspect} to be encrypted#{" and decrypt to #{expected.inspect}" if expected}"
  end

  failure_message_when_negated do |actual|
    "expected: #{actual.inspect} not to be encrypted"
  end

  description do
    "expect to be an encrypted v2 password (with optional encrypted value)"
  end
end
