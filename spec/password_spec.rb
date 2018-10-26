require 'tempfile'

RSpec.describe ManageIQ::Password do
  it "has a version number" do
    expect(ManageIQ::Password::VERSION).not_to be nil
  end

  before do
    @old_key_root = ManageIQ::Password.key_root
    ManageIQ::Password.key_root = File.join(__dir__, "support")
  end

  after do
    # clear legacy keys and reset key_root changes (from specs or before block)
    ManageIQ::Password.key_root = @old_key_root
  end

  MIQ_PASSWORD_CASES = [
    [
      "test",
      "v1:{KSOqhNiOWJbR0lz7v6PTJg==}",
      "v2:{DUb5th63TM+zIB6RhnTtVg==}",
      "xy0OjTrp19xhSxel52NMHw==",
    ], [
      "password",
      "v1:{Wv/+DC0XBqnIbRCIAI+CSQ==}",
      "v2:{gURYNPfZP3cu4+bw9pznMQ==}",
      "yaLmATw79aaeXOiu/297Hw==",
    ], [
      "ca$hcOw",
      "v1:{abvh5pIq6ptkKmBViuE0Yw==}",
      "v2:{Dq/TWvwTfQJDverzajStpA==}",
      "gS2DsdUxA3txmmKUc1vw0Q==",
    ], [
      "Tw45!&zQ",
      "v1:{jNSGHSwQsx36gSNEPD06jA==}",
      "v2:{27X41c6xqCCdVcw4LlQ1Qg==}",
      "5IbEEtGt4/G6nk6YB0Lz8Q==",
    ], [
      "`~!@\#$%^&*()_+-=[]{}\\|;:\"'<>,./?",
      "v1:{ziplwo+PA+gmKTNpJTRQtfRk+nPL2A2g3nnHdRRv86fBjyziiQ1V//g5u+dJ\nRyjl}",
      "v2:{zad43i0dQB+8z45ZYMVmpFcagbt40T0aFddhHlj6YtPgoOJ5N3uBYAp8WwuZQkar}",
      "JilJmiBufmyWjlAGLStE7+KEfwxCzZOS38ZSjH8JXEPCqdeQzWsXEddlqvzL\n0PpW",
    ], [
      "abc\t\n\vzabc",
      "v1:{t8hWgGHCP252inUcPgRK/A==}",
      "v2:{8iZNC6jMX5jtqSXejeLWBA==}",
      "HBfmhrLRwYVE3+DHM2fGuQ==",
    ], [
      "äèíôúñæþß",
      "v1:{gQ/3aP6FayuFJvbpyUkplJ8pnDJ+JI6ZKXAv5PqrRSk=}",
      "v2:{hPJ7QZBjjq9W2UydkaEvjnqM839QQ9FxJNOZT0ugOVk=}",
      "gI04s1uq9whj+UADjZak7m5mK7NywVAznAEf2dEIZJ4=",
    ], [
      # Japanese chars for good morning
      "\343\201\223\343\201\253\343\201\241\343\202\217",
      "v1:{eVFIO7k12XP4lh+ptRd9Sw==}",
      "v2:{efZNQ1asaxeZtemcvhxuMQ==}",
      "noF/l4uF2E6vMFdPENOlng==",
    ], [
      # Chinese for "password"
      "\345\257\206\347\240\201",
      "v1:{VsQ8kvHZ5/w3kshaYgIZZw==}",
      "v2:{tXN4DnLCrre7HVB+2zEbMg==}",
      "UPYMlD0o/uClT/k7XV7GLA==",
    ], [
      # Turkish characters known for encoding issues
      "şŞ",
      "v1:{2QALyJaer8Fvhsmx1z1dBQ==}",
      "v2:{IIdPQA3FbwJv/JmGapatwg==}",
      "Cgs5o1yzQZCgywLsSJnxfw=="
    ]
  ]

  MIQ_PASSWORD_CASES.each do |(pass, enc_v1, enc_v2, enc_v0)|
    context "with #{pass.inspect}" do
      before do
        ManageIQ::Password.add_legacy_key("v0_key", :v0)
        ManageIQ::Password.add_legacy_key("v1_key", :v1)
      end

      it(".encrypt")        { expect(ManageIQ::Password.encrypt(pass)).to             be_encrypted(pass) }
      it(".decrypt v1")     { expect(ManageIQ::Password.decrypt(enc_v1)).to           be_decrypted(pass) }
      it(".decrypt erb")    { expect(ManageIQ::Password.decrypt(erberize(enc_v0))).to be_decrypted(pass) }
      it(".decrypt legacy") { expect(ManageIQ::Password.decrypt(enc_v0)).to           be_decrypted(pass) }

      it("#decrypt")        { expect(ManageIQ::Password.new.decrypt(enc_v2)).to           be_decrypted(pass) }
      it("#decrypt v1")     { expect(ManageIQ::Password.new.decrypt(enc_v1)).to           be_decrypted(pass) }
      it("#decrypt v1 erb") { expect(ManageIQ::Password.new.decrypt(erberize(enc_v1))).to be_decrypted(pass) }
      it("#decrypt erb")    { expect(ManageIQ::Password.new.decrypt(erberize(enc_v0))).to be_decrypted(pass) }

      it(".encrypt(.decrypt)") { expect(ManageIQ::Password.decrypt(ManageIQ::Password.encrypt(pass))).to         be_decrypted(pass) }
      it(".encStr/.decrypt")   { expect(ManageIQ::Password.decrypt(ManageIQ::Password.new(pass).encStr)).to      be_decrypted(pass) }
      it("#encrypt(#decrypt)") { expect(ManageIQ::Password.new.decrypt(ManageIQ::Password.new.encrypt(pass))).to be_decrypted(pass) }

      it("#try_encrypt (non-encrypted)") { expect(ManageIQ::Password.try_encrypt(pass)).to   be_encrypted(pass) }
      it("#try_encrypt erb")             { expect(ManageIQ::Password.try_encrypt(erberize(enc_v0))).to eq(erberize(enc_v0)) }
      it("#try_encrypt DB_PASSWORD")     do
        enc = erberize(enc_v0, 'DB_PASSWORD')
        expect(ManageIQ::Password.try_encrypt(enc)).to eq(enc)
      end
      it("#try_encrypt MiqPassword")     do
        enc = erberize(enc_v0, 'MiqPassword')
        expect(ManageIQ::Password.try_encrypt(enc)).to eq(enc)
      end
      it("#try_encrypt (encrypted v1)")  { expect(ManageIQ::Password.try_encrypt(enc_v1)).to eq(enc_v1) }
      it("#try_encrypt (encrypted v2)")  { expect(ManageIQ::Password.try_encrypt(enc_v2)).to eq(enc_v2) }

      it("#try_decrypt")                 { expect(ManageIQ::Password.try_decrypt(enc_v2)).to           be_decrypted(pass) }
      it("#try_decrypt v1")              { expect(ManageIQ::Password.try_decrypt(enc_v1)).to           be_decrypted(pass) }
      it("#try_decrypt v1 erb")          { expect(ManageIQ::Password.try_decrypt(erberize(enc_v1))).to be_decrypted(pass) }
      it("#try_decrypt erb")             { expect(ManageIQ::Password.try_decrypt(erberize(enc_v0))).to be_decrypted(pass) }
      it("#try_decrypt DB_PASSWORD")     { expect(ManageIQ::Password.try_decrypt(erberize(enc_v0, "DB_PASSWORD"))).to be_decrypted(pass) }
      it("#try_decrypt MiqPassword")     { expect(ManageIQ::Password.try_decrypt(erberize(enc_v0, "MiqPassword"))).to be_decrypted(pass) }
      it("#try_decrypt (non-encrypted)") { expect(ManageIQ::Password.try_decrypt(pass)).to             eq(pass) }

      it("#split[ver]")            { expect(ManageIQ::Password.split(enc_v2).first).to           eq("2") }
      it("#split[ver] v1")         { expect(ManageIQ::Password.split(enc_v1).first).to           eq("1") }
      it("#split[ver] erb")        { expect(ManageIQ::Password.split(erberize(enc_v0)).first).to eq("0") }
      it("#split[ver] legacy")     { expect(ManageIQ::Password.split(enc_v0).first).to           be_nil  }
      # bug: currently, split is not smart enough to detect legacy from non-encrypted strings
      it("#split (non-encrypted)") { expect(ManageIQ::Password.split(pass).first).to             be_nil }

      it("#recrypt v2")     { expect(ManageIQ::Password.new.recrypt(enc_v2)).to eq(enc_v2) }
      it("#recrypt v1")     { expect(ManageIQ::Password.new.recrypt(enc_v1)).to eq(enc_v2) }
      it("#recrypt legacy") { expect(ManageIQ::Password.new.recrypt(enc_v0)).to eq(enc_v2) }
    end
  end

  context ".encrypted?" do
    [
      "password",                         # Normal case
      "abcdefghijklmnopqrstuvwxyz123456", # 32 character password will not end in a "=" after Base64 encoding
    ].each do |pass|
      it "with #{pass.inspect}" do
        expect(ManageIQ::Password.encrypted?(pass)).to                      be_falsey
        expect(ManageIQ::Password.encrypted?(ManageIQ::Password.encrypt(pass))).to be_truthy
      end
    end

    it "should handle blanks" do
      expect(ManageIQ::Password.encrypted?(nil)).to be_falsey
      expect(ManageIQ::Password.encrypted?("")).to  be_falsey
    end
  end

  context "encrypting / decrypting blanks" do
    it "should not decrypt blanks" do
      expect(ManageIQ::Password.decrypt(nil)).to     be_nil
      expect(ManageIQ::Password.decrypt("")).to      be_empty
      expect(ManageIQ::Password.decrypt("v1:{}")).to be_empty
      expect(ManageIQ::Password.decrypt("v2:{}")).to be_empty

      expect(ManageIQ::Password.try_decrypt(nil)).to     be_nil
      expect(ManageIQ::Password.try_decrypt("")).to      be_empty
      expect(ManageIQ::Password.try_decrypt("v1:{}")).to be_empty
      expect(ManageIQ::Password.try_decrypt("v2:{}")).to be_empty
    end

    it "should not encrypt blanks" do
      expect(ManageIQ::Password.encrypt(nil)).to be_nil
      expect(ManageIQ::Password.encrypt("")).to  eq("v2:{}")

      expect(ManageIQ::Password.try_encrypt(nil)).to be_nil
      expect(ManageIQ::Password.try_encrypt("")).to  eq("v2:{}")
    end

    it "should not split blanks" do
      expect(ManageIQ::Password.send(:split, "").first).to be_nil
    end

    it "should not recrypt blanks" do
      expect(ManageIQ::Password.new.recrypt(nil)).to be_nil
      expect(ManageIQ::Password.new.recrypt("")).to  be_empty
    end

    it "should fail on recrypt bad password" do
      expect { ManageIQ::Password.new.recrypt("v2:{55555}") }.to raise_error(ManageIQ::Password::PasswordError)
    end

    it "should decrypt passwords with newlines" do
      expect(ManageIQ::Password.decrypt("v2:{zad43i0dQB+8z45ZYMVmpFcagbt40T0aFddhHlj6YtPgoOJ5N3uBYAp8WwuZ\nQkar}")).to(
        eq("`~!@\#$%^&*()_+-=[]{}\\|;:\"'<>,./?")
      )
    end
  end

  context "with missing v1_key" do
    it "should report decent error when decryption with missing an encryption key" do
      expect do
        described_class.decrypt("v1:{KSOqhNiOWJbR0lz7v6PTJg==}")
      end.to raise_error(ManageIQ::Password::PasswordError, /can not decrypt.*v1_key/)
    end
  end

  context ".md5crypt" do
    it "with an unencrypted string" do
      expect(ManageIQ::Password.md5crypt("password")).to eq("$1$miq$Ho9GNOzRsxMpJSsgwG/y01")
    end

    it "with an encrypted string" do
      ManageIQ::Password.add_legacy_key("v1_key", :v1)
      expect(ManageIQ::Password.md5crypt("v1:{Wv/+DC0XBqnIbRCIAI+CSQ==}")).to eq("$1$miq$Ho9GNOzRsxMpJSsgwG/y01")
    end
  end

  context ".sysprep_crypt" do
    it "with an unencrypted string" do
      expect(ManageIQ::Password.sysprep_crypt("password")).to eq(
        "cABhAHMAcwB3AG8AcgBkAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAUABhAHMAcwB3AG8AcgBkAA==")
    end

    it "with an encrypted string" do
      ManageIQ::Password.add_legacy_key("v1_key", :v1)
      expect(ManageIQ::Password.sysprep_crypt("v1:{Wv/+DC0XBqnIbRCIAI+CSQ==}")).to eq(
        "cABhAHMAcwB3AG8AcgBkAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAUABhAHMAcwB3AG8AcgBkAA==")
    end
  end

  it ".sanitize_string" do
    expect(ManageIQ::Password.sanitize_string("some :password: v1:{XAWlcAlViNwB} and another :password: v2:{egr+hObB}"))
      .to eq("some :password: ******** and another :password: ********")
    expect(ManageIQ::Password.sanitize_string("some :enocded_password: v1%3A%7BXAWlcAlViNwB%7D and another :enocded_password: v2%3A%7Begr%2BhObB%7D"))
      .to eq("some :enocded_password: ******** and another :enocded_password: ********")
  end

  it ".sanitize_string!" do
    x = "some :password: v1:{XAWlcAlViNwBkJYjH35Rbw==} and another :password: v2:{egr+hObBeS+OC/hBDYnwgg==}"
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

    it "clears all_keys" do
      v0 = ManageIQ::Password.add_legacy_key("v0_key", :v0)
      v1 = ManageIQ::Password.add_legacy_key("v1_key", :v1)
      v2 = ManageIQ::Password.v2_key

      expect(ManageIQ::Password.all_keys).to match_array([v2, v1, v0])

      ManageIQ::Password.key_root = nil

      expect(Kernel).to receive(:warn).with(/v2_key doesn't exist/)
      expect(ManageIQ::Password.all_keys).to be_empty
    end
  end

  describe ".clear_keys" do
    it "removes legacy keys from all_keys" do
      v0 = ManageIQ::Password.add_legacy_key("v0_key", :v0)
      v1 = ManageIQ::Password.add_legacy_key("v1_key", :v1)
      v2 = ManageIQ::Password.v2_key

      expect(ManageIQ::Password.all_keys).to match_array([v2, v1, v0])

      ManageIQ::Password.clear_keys

      v2 = ManageIQ::Password.v2_key
      expect(ManageIQ::Password.all_keys).to match_array([v2])
    end
  end

  context ".v2_key" do
    it "when missing" do
      ManageIQ::Password.key_root = "."
      expect(Kernel).to receive(:warn).with(/v2_key doesn't exist/)
      expect(ManageIQ::Password.v2_key).not_to be
    end

    it "when present" do
      expect(ManageIQ::Password.v2_key.to_s).to eq "5ysYUd3Qrjj7DDplmEJHmnrFBEPS887JwOQv0jFYq2g="
    end
  end

  describe ".add_legacy_key" do
    let(:v0_key)  { ManageIQ::Password::Key.new("AES-128-CBC", Base64.encode64("9999999999999999"), Base64.encode64("5555555555555555")) }
    let(:v1_key)  { ManageIQ::Password.generate_symmetric }

    it "ignores bad key filename" do
      expect(ManageIQ::Password.all_keys.size).to eq(1)
      ManageIQ::Password.add_legacy_key("some_bogus_name")
      expect(ManageIQ::Password.all_keys.size).to eq(1)
    end

    it "supports raw key" do
      expect(ManageIQ::Password.all_keys.size).to eq(1)
      ManageIQ::Password.add_legacy_key(v1_key, :v1)
      expect(ManageIQ::Password.all_keys.size).to eq(2)
    end

    it "supports absolute path" do
      with_key do |dir, filename|
        ManageIQ::Password.add_legacy_key("#{dir}/#{filename}")
      end
      expect(ManageIQ::Password.all_keys.size).to eq(2)
    end

    it "supports relative path" do
      with_key do |dir, filename|
        Dir.chdir dir do
          expect(ManageIQ::Password.all_keys.size).to eq(1)
          ManageIQ::Password.add_legacy_key(filename)
          expect(ManageIQ::Password.all_keys.size).to eq(2)
        end
      end
    end

    it "supports root_key path (also warns if v2 key not found)" do
      with_key do |dir, filename|
        ManageIQ::Password.key_root = dir
        # NOTE: no v2_key in this key_root
        expect(Kernel).to receive(:warn).with(/doesn't exist/)
        expect(ManageIQ::Password.all_keys.size).to eq(0)
        ManageIQ::Password.add_legacy_key(filename)
        expect(ManageIQ::Password.all_keys.size).to eq(1)
      end
    end
  end

  describe "#recrypt" do
    context "#with ambigious keys" do
      let(:old_key) { ManageIQ::Password::Key.new("aes-256-cbc", "JZjTdiuOzWlTHUkBZSGj9BmWEoswxvImWuwD/xN87s0=") }
      let(:v2_key)  { ManageIQ::Password::Key.new("aes-256-cbc", "5ysYUd3Qrjj7DDplmEJHmnrFBEPS887JwOQv0jFYq2g=") }
      let(:v1_key)  { ManageIQ::Password.generate_symmetric }

      before do
        ManageIQ::Password.v2_key = v2_key
        ManageIQ::Password.add_legacy_key(v1_key, :v1)
        ManageIQ::Password.add_legacy_key(old_key)
      end

      it "recrypts legacy v2 encrypted password" do
        expect(ManageIQ::Password.new.recrypt(ManageIQ::Password.new.encrypt("password", "v2", old_key))).to be_encrypted("password")
      end

      it "recrypts legacy v1 encrypted password" do
        expect(ManageIQ::Password.new.recrypt(ManageIQ::Password.new.encrypt("password", "v1"))).to be_encrypted("password")
      end

      it "recrypts regular v2 encrypted password" do
        expect(ManageIQ::Password.new.recrypt(ManageIQ::Password.new.encrypt("password"))).to be_encrypted("password")
      end
    end

    context "#with no legacy v2 key" do
      it "recrypts regular v2 encrypted password" do
        expect(ManageIQ::Password.new.recrypt(ManageIQ::Password.new.encrypt("password"))).to be_encrypted("password")
      end
    end
  end

  private

  def with_key
    Dir.mktmpdir('test-key-root') do |d|
      ManageIQ::Password.generate_symmetric("#{d}/my-key")
      yield d, "my-key"
    end
  end

  def erberize(password, passmethod = "ManageIQ::Password")
    "<%= #{passmethod}.decrypt(\"#{password}\") %>"
  end
end
