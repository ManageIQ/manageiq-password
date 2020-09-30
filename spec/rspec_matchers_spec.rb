RSpec.describe "RSpec::Matchers" do
  let(:decrypted) { "p4$$w0rd" }
  let(:encrypted) { ManageIQ::Password.encrypt(decrypted) }

  describe "be_decrypted" do
    it("on decrypted")     { expect(decrypted).to     be_decrypted(decrypted) }
    it("on not encrypted") { expect(encrypted).to_not be_decrypted(decrypted) }

    it("fails on not decrypted") do
      expect do
        expect(decrypted).to_not be_decrypted(decrypted)
      end.to raise_error(RSpec::Expectations::ExpectationNotMetError)
    end

    it("fails on not decrypted") do
      expect do
        expect(encrypted).to be_decrypted(decrypted)
      end.to raise_error(RSpec::Expectations::ExpectationNotMetError)
    end
  end

  describe "be_encrypted" do
    it("on encrypted") { expect(encrypted).to     be_encrypted }
    it("on decrypted") { expect(decrypted).to_not be_encrypted }

    it("fails on not encrypted") do
      expect do
        expect(encrypted).to_not be_encrypted
      end.to raise_error(RSpec::Expectations::ExpectationNotMetError)
    end

    it("fails on not decrypted") do
      expect do
        expect(decrypted).to be_encrypted
      end.to raise_error(RSpec::Expectations::ExpectationNotMetError)
    end

    it("on encrypted with check") { expect(encrypted).to be_encrypted(decrypted) }

    it("fails on not encrypted with check") do
      expect do
        expect(encrypted).to_not be_encrypted("invalid argument")
      end.to raise_error(ArgumentError)
    end

    it("fails on encrypted with check that fails") do
      expect do
        expect(encrypted).to be_encrypted("will matter")
      end.to raise_error(RSpec::Expectations::ExpectationNotMetError)
    end

    it("fails on not decrypted with check") do
      expect do
        expect(decrypted).to be_encrypted(decrypted)
      end.to raise_error(RSpec::Expectations::ExpectationNotMetError)
    end
  end
end
