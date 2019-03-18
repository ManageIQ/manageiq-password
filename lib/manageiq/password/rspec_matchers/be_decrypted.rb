RSpec::Matchers.define :be_decrypted do |expected|
  match do |actual|
    actual == expected
  end

  failure_message do |actual|
    "expected: #{actual.inspect} to be decrypted to #{expected.inspect}"
  end

  failure_message_when_negated do |actual|
    "expected: #{actual.inspect} to not equal #{expected.inspect}"
  end

  description do
    "expect to be decrypted from a string"
  end
end
