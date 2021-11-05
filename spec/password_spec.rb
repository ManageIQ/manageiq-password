require 'tempfile'

RSpec.describe ManageIQ::Password do
  it "has a version number" do
    expect(ManageIQ::Password::VERSION).not_to be nil
  end

  MIQ_PASSWORD_CASES = [
    [
      "test",
      "v2:{DUb5th63TM+zIB6RhnTtVg==}",
    ], [
      "password",
      "v2:{gURYNPfZP3cu4+bw9pznMQ==}",
    ], [
      "ca$hcOw",
      "v2:{Dq/TWvwTfQJDverzajStpA==}",
    ], [
      "Tw45!&zQ",
      "v2:{27X41c6xqCCdVcw4LlQ1Qg==}",
    ], [
      "`~!@\#$%^&*()_+-=[]{}\\|;:\"'<>,./?",
      "v2:{zad43i0dQB+8z45ZYMVmpFcagbt40T0aFddhHlj6YtPgoOJ5N3uBYAp8WwuZQkar}",
    ], [
      "abc\t\n\vzabc",
      "v2:{8iZNC6jMX5jtqSXejeLWBA==}",
    ], [
      "äèíôúñæþß",
      "v2:{hPJ7QZBjjq9W2UydkaEvjnqM839QQ9FxJNOZT0ugOVk=}",
    ], [
      # Japanese chars for good morning
      "\343\201\223\343\201\253\343\201\241\343\202\217",
      "v2:{efZNQ1asaxeZtemcvhxuMQ==}",
    ], [
      # Chinese for "password"
      "\345\257\206\347\240\201",
      "v2:{tXN4DnLCrre7HVB+2zEbMg==}",
    ], [
      # Turkish characters known for encoding issues
      "şŞ",
      "v2:{IIdPQA3FbwJv/JmGapatwg==}",
    ], [
      # Old v1 keys are now considered like plaintext
      "v1:{Wv/+DC0XBqnIbRCIAI+CSQ==}",
      "v2:{WNOvFRtE80WHrw8f04SDhE4/LQJjgBcsMOjcrHlZB3s=}",
    ], [
      # Old v0 keys are now considered like plaintext
      "yaLmATw79aaeXOiu/297Hw==",
      "v2:{+4V6MIdimJtprWnViWbBoZYePTvPXtLnhOmKn+j0AxY=}",
    ]
  ]

  MIQ_PASSWORD_CASES.each do |(pass, enc)|
    context "with #{pass.inspect}" do
      it(".encrypt") { expect(ManageIQ::Password.encrypt(pass)).to     be_encrypted(pass) }
      it("#encrypt") { expect(ManageIQ::Password.new.encrypt(pass)).to be_encrypted(pass) }

      it(".decrypt") { expect(ManageIQ::Password.decrypt(enc)).to     be_decrypted(pass) }
      it("#decrypt") { expect(ManageIQ::Password.new.decrypt(enc)).to be_decrypted(pass) }

      it(".decrypt plaintext") { expect { ManageIQ::Password.decrypt(pass) }.to     raise_error ManageIQ::Password::PasswordError }
      it("#decrypt plaintext") { expect { ManageIQ::Password.new.decrypt(pass) }.to raise_error ManageIQ::Password::PasswordError }

      it(".encrypt(.decrypt)") { expect(ManageIQ::Password.decrypt(ManageIQ::Password.encrypt(pass))).to         be_decrypted(pass) }
      it(".encStr/.decrypt")   { expect(ManageIQ::Password.decrypt(ManageIQ::Password.new(pass).encStr)).to      be_decrypted(pass) }
      it("#encrypt(#decrypt)") { expect(ManageIQ::Password.new.decrypt(ManageIQ::Password.new.encrypt(pass))).to be_decrypted(pass) }

      it(".try_encrypt")           { expect(ManageIQ::Password.try_encrypt(pass)).to be_encrypted(pass) }
      it(".try_encrypt encrypted") { expect(ManageIQ::Password.try_encrypt(enc)).to  eq(enc) }

      it(".try_decrypt")           { expect(ManageIQ::Password.try_decrypt(enc)).to  be_decrypted(pass) }
      it(".try_decrypt plaintext") { expect(ManageIQ::Password.try_decrypt(pass)).to eq(pass) }

      it(".recrypt") { expect(ManageIQ::Password.recrypt(enc)).to     eq(enc) }
      it("#recrypt") { expect(ManageIQ::Password.new.recrypt(enc)).to eq(enc) }

      %w[DB_PASSWORD MiqPassword ManageIQ::Password].each do |pass_method|
        enc_erb  = "<%= #{pass_method}.decrypt(\"#{enc}\") %>"
        pass_erb = "<%= #{pass_method}.decrypt(\"#{pass}\") %>"

        context "erb #{pass_method}" do
          it(".decrypt") { expect(ManageIQ::Password.decrypt(enc_erb)).to     be_decrypted(pass) }
          it("#decrypt") { expect(ManageIQ::Password.new.decrypt(enc_erb)).to be_decrypted(pass) }

          it(".decrypt plaintext") { expect { ManageIQ::Password.decrypt(pass_erb) }.to     raise_error ManageIQ::Password::PasswordError }
          it("#decrypt plaintext") { expect { ManageIQ::Password.new.decrypt(pass_erb) }.to raise_error ManageIQ::Password::PasswordError }

          it(".try_decrypt") { expect(ManageIQ::Password.try_decrypt(enc_erb)).to be_decrypted(pass) }

          it(".recrypt") { expect(ManageIQ::Password.recrypt(enc_erb)).to     eq(enc) }
          it("#recrypt") { expect(ManageIQ::Password.new.recrypt(enc_erb)).to eq(enc) }
        end
      end
    end
  end

  describe ".decrypt" do
    it "should decrypt passwords with newlines" do
      expect(ManageIQ::Password.decrypt("v2:{zad43i0dQB+8z45ZYMVmpFcagbt40T0aFddhHlj6YtPgoOJ5N3uBYAp8WwuZ\nQkar}")).to(
        eq("`~!@\#$%^&*()_+-=[]{}\\|;:\"'<>,./?")
      )
    end

    it "fails on a bad encrypted key" do
      expect { ManageIQ::Password.decrypt("v2:{55555}") }.to raise_error ManageIQ::Password::PasswordError
    end
  end

  context ".encrypted?" do
    [
      "password",                         # Normal case
      "abcdefghijklmnopqrstuvwxyz123456", # 32 character password will not end in a "=" after Base64 encoding
    ].each do |pass|
      it "with #{pass.inspect}" do
        expect(ManageIQ::Password.encrypted?(pass)).to be_falsey
        expect(ManageIQ::Password.encrypted?(ManageIQ::Password.encrypt(pass))).to be_truthy
      end
    end

    it "should handle blanks" do
      expect(ManageIQ::Password.encrypted?(nil)).to be_falsey
      expect(ManageIQ::Password.encrypted?("")).to  be_falsey
    end
  end

  context "encrypting / decrypting blanks" do
    it ".decrypt" do
      expect(ManageIQ::Password.decrypt(nil)).to     be_nil
      expect(ManageIQ::Password.decrypt("")).to      be_empty
      expect(ManageIQ::Password.decrypt("v2:{}")).to be_empty
    end

    it ".encrypt" do
      expect(ManageIQ::Password.encrypt(nil)).to be_nil
      expect(ManageIQ::Password.encrypt("")).to  eq("v2:{}")
    end

    it ".recrypt" do
      expect(ManageIQ::Password.recrypt(nil)).to     be_nil
      expect(ManageIQ::Password.recrypt("")).to      eq("v2:{}")
      expect(ManageIQ::Password.recrypt("v2:{}")).to eq("v2:{}")
    end

    it ".try_decrypt" do
      expect(ManageIQ::Password.try_decrypt(nil)).to     be_nil
      expect(ManageIQ::Password.try_decrypt("")).to      be_empty
      expect(ManageIQ::Password.try_decrypt("v2:{}")).to be_empty
    end

    it ".try_encrypt" do
      expect(ManageIQ::Password.try_encrypt(nil)).to     be_nil
      expect(ManageIQ::Password.try_encrypt("")).to      eq("v2:{}")
      expect(ManageIQ::Password.try_encrypt("v2:{}")).to eq("v2:{}")
    end
  end

  describe ".recrypt" do
    let(:prior_key) { ManageIQ::Password::Key.new("aes-256-cbc", "JZjTdiuOzWlTHUkBZSGj9BmWEoswxvImWuwD/xN87s0=") }

    it "with password encrypted with a prior key" do
      enc = ManageIQ::Password.encrypt("password", prior_key)
      expect(ManageIQ::Password.recrypt(enc, prior_key)).to be_encrypted("password")
    end

    it "with password encrypted with the current key but given a prior key" do
      enc = ManageIQ::Password.encrypt("password")
      expect(ManageIQ::Password.recrypt(enc, prior_key)).to be_encrypted("password")
    end

    it "fails on a bad encrypted key" do
      expect { ManageIQ::Password.recrypt("v2:{55555}") }.to raise_error(ManageIQ::Password::PasswordError)
    end
  end

  context ".md5crypt" do
    it "with an unencrypted string" do
      expect(ManageIQ::Password.md5crypt("password")).to eq("$1$miq$Ho9GNOzRsxMpJSsgwG/y01")
    end

    it "with an encrypted string" do
      expect(ManageIQ::Password.md5crypt(ManageIQ::Password.encrypt("password"))).to eq("$1$miq$Ho9GNOzRsxMpJSsgwG/y01")
    end
  end

  context ".sysprep_crypt" do
    it "with an unencrypted string" do
      expect(ManageIQ::Password.sysprep_crypt("password")).to eq(
        "cABhAHMAcwB3AG8AcgBkAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAUABhAHMAcwB3AG8AcgBkAA=="
      )
    end

    it "with an encrypted string" do
      expect(ManageIQ::Password.sysprep_crypt(ManageIQ::Password.encrypt("password"))).to eq(
        "cABhAHMAcwB3AG8AcgBkAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAUABhAHMAcwB3AG8AcgBkAA=="
      )
    end
  end

  it ".sanitize_string" do
    expect(ManageIQ::Password.sanitize_string("some :password: v2:{XAWlcAlViNwB} and another :password: v2:{egr+hObB}"))
      .to eq("some :password: ******** and another :password: ********")
    expect(ManageIQ::Password.sanitize_string("some :encoded_password: v2%3A%7BXAWlcAlViNwB%7D and another :encoded_password: v2%3A%7Begr%2BhObB%7D"))
      .to eq("some :encoded_password: ******** and another :encoded_password: ********")
  end

  it ".sanitize_string!" do
    x = "some :password: v2:{XAWlcAlViNwBkJYjH35Rbw==} and another :password: v2:{egr+hObBeS+OC/hBDYnwgg==}"
    ManageIQ::Password.sanitize_string!(x)
    expect(x).to eq("some :password: ******** and another :password: ********")
  end

  context ".key_root / .key_root=" do
    it "defaults key_root" do
      expect(ENV).to receive(:[]).with("KEY_ROOT").and_return("/certs")
      ManageIQ::Password.key_root = nil
      expect(ManageIQ::Password.key_root).to eq("/certs")
    end

    it "overrides key_root" do
      expect(ENV).not_to receive(:[])
      ManageIQ::Password.key_root = "/abc"
      expect(ManageIQ::Password.key_root).to eq("/abc")
    end

    it "clears existing keys" do
      key = ManageIQ::Password.key
      ManageIQ::Password.key_root = nil

      expect(Kernel).to receive(:warn).with(/v2_key doesn't exist/)
      expect(ManageIQ::Password.key).to be_nil
    end
  end

  describe ".key" do
    it "warns when v2_key file is missing" do
      ManageIQ::Password.key_root = nil

      expect(Kernel).to receive(:warn).with(/v2_key doesn't exist/)
      expect(ManageIQ::Password.key).to be_nil
    end

    it "when v2_key file present" do
      expect(ManageIQ::Password.key.to_s).to eq "5ysYUd3Qrjj7DDplmEJHmnrFBEPS887JwOQv0jFYq2g="
    end
  end

  it ".key=" do
    _key = ManageIQ::Password.key
    new_key = ManageIQ::Password.generate_symmetric

    ManageIQ::Password.key = new_key
    expect(ManageIQ::Password.key).to eq new_key
  end
end
