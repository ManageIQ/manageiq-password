require 'awesome_spawn'
require 'fileutils'

RSpec.describe "manageiq-password" do
  let(:exe)     { Pathname.new(__dir__).join("..", "exe", "manageiq-password") }
  let(:keyfile) { Pathname.new(__dir__).join("support", "v2_key") }
  let(:cli)     { "#{exe} --key #{keyfile}" }

  let(:password)  { "password" }
  let(:encrypted) { "v2:{gURYNPfZP3cu4+bw9pznMQ==}" }
  let(:junk)      { "v2:{anVuaw==}" }

  describe "--decrypt" do
    it "without a trailing \\n" do
      result = AwesomeSpawn.run!("#{cli} --decrypt", :in_data => encrypted)
      expect(result.output).to eq(password)
      expect(result.error).to  be_empty
    end

    it "with a trailing \\n" do
      result = AwesomeSpawn.run!("#{cli} --decrypt", :in_data => "#{encrypted}\n")
      expect(result.output).to eq(password)
      expect(result.error).to  be_empty
    end

    it "accepts a short option" do
      result = AwesomeSpawn.run!("#{cli} -d", :in_data => encrypted)
      expect(result.output).to eq(password)
      expect(result.error).to  be_empty
    end

    it "is the default mode" do
      result = AwesomeSpawn.run!(cli, :in_data => encrypted)
      expect(result.output).to eq(password)
      expect(result.error).to  be_empty
    end

    it "with a password that is not decryptable" do
      result = AwesomeSpawn.run("#{cli} --decrypt", :in_data => junk)
      expect(result.output).to      be_empty
      expect(result.error).to       include("bad decrypt")
      expect(result.exit_status).to eq(1)
    end

    context "with a junk keyfile" do
      before { File.write("/tmp/junk_key", "junk") }
      after  { FileUtils.rm_f("/tmp/junk_key") }

      it "should fail" do
        result = AwesomeSpawn.run("#{exe} --key /tmp/junk_key --decrypt", :in_data => encrypted)
        expect(result.output).to      be_empty
        expect(result.error).to       include("Invalid v2 key file")
        expect(result.exit_status).to eq(1)
      end
    end
  end

  describe "--encrypt" do
    it "without a trailing \\n" do
      result = AwesomeSpawn.run!("#{cli} --encrypt", :in_data => password)
      expect(result.output).to eq(encrypted)
      expect(result.error).to  be_empty
    end

    it "with a trailing \\n" do
      result = AwesomeSpawn.run!("#{cli} --encrypt", :in_data => "#{password}\n")
      expect(result.output).to eq(encrypted)
      expect(result.error).to  be_empty
    end

    it "accepts a short option" do
      result = AwesomeSpawn.run!("#{cli} -e", :in_data => password)
      expect(result.output).to eq(encrypted)
      expect(result.error).to  be_empty
    end

    context "with a junk keyfile" do
      before { File.write("/tmp/junk_key", "junk") }
      after  { FileUtils.rm_f("/tmp/junk_key") }

      it "should fail" do
        result = AwesomeSpawn.run("#{exe} --key /tmp/junk_key --encrypt", :in_data => encrypted)
        expect(result.output).to      be_empty
        expect(result.error).to       include("Invalid v2 key file")
        expect(result.exit_status).to eq(1)
      end
    end
  end

  describe "--encrypt/--decrypt roundtrip" do
    it "without a trailing \\n" do
      result = AwesomeSpawn.run!("#{cli} --encrypt | #{cli} --decrypt", :in_data => password)
      expect(result.output).to eq(password)
      expect(result.error).to  be_empty
    end

    it "with a trailing \\n" do
      result = AwesomeSpawn.run!("#{cli} --encrypt | #{cli} --decrypt", :in_data => "#{password}\n")
      expect(result.output).to eq(password)
      expect(result.error).to  be_empty
    end
  end

  describe "--key" do
    context "with an invalid path" do
      before { FileUtils.rm_f("/tmp/junk_key") }

      it "should fail" do
        result = AwesomeSpawn.run("#{exe} --key /tmp/junk_key", :in_data => encrypted)
        expect(result.output).to      be_empty
        expect(result.error).to       include("Cannot read v2 key file")
        expect(result.exit_status).to eq(1)
      end
    end
  end

  describe "--help" do
    it "shows help" do
      result = AwesomeSpawn.run!("#{cli} --help")
      expect(result.output).to be_empty
      expect(result.error).to  start_with("Usage: ")
    end

    it "accepts a short option (-h)" do
      result = AwesomeSpawn.run!("#{cli} -h")
      expect(result.output).to be_empty
      expect(result.error).to  start_with("Usage: ")
    end

    it "accepts a short option (-?)" do
      result = AwesomeSpawn.run!("#{cli} -?")
      expect(result.output).to be_empty
      expect(result.error).to  start_with("Usage: ")
    end
  end

  describe "DEBUG=true" do
    it "with --decrypt" do
      result = AwesomeSpawn.run!("#{cli} --decrypt", :in_data => encrypted, :env => {"DEBUG" => "true"})
      expect(result.output).to eq(password)
      expect(result.error).to  match(/^Mode:\s+decrypt$/)
    end

    it "with --encrypt" do
      result = AwesomeSpawn.run!("#{cli} --encrypt", :in_data => password, :env => {"DEBUG" => "true"})
      expect(result.output).to eq(encrypted)
      expect(result.error).to  match(/^Mode:\s+encrypt$/)
    end
  end
end
