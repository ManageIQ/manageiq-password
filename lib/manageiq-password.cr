require "base64"
require "digest"
require "openssl"
require "random/secure"
require "yaml"

module ManageIQ
  class Password
    class PasswordError < RuntimeError; end

    REGEXP = /v2:\{([^}]*)\}/
    REGEXP_START_LINE = /^#{REGEXP}/
    MASK = "********".freeze

    property encStr : String?

    class_setter key : Key?

    def initialize(str = nil)
      return unless str

      @encStr = encrypt(str)
    end

    def encrypt(str, key = self.class.key)
      return str if str.nil?

      enc = key.encrypt64(str).delete("\n") unless str.empty?
      self.class.wrap(enc)
    end

    def decrypt(str, key = self.class.key)
      enc = self.class.unwrap(str)
      return enc if enc.nil? || enc.empty?

      begin
        key.decrypt64(enc).encode("UTF-8")
      rescue
        raise PasswordError.new("cannot decrypt encrypted string")
      end
    end

    def self.encrypt(*args)
      new.encrypt(*args)
    end

    def self.decrypt(*args)
      new.decrypt(*args)
    end

    def self.encrypted?(str)
      return false if str.nil? || str.empty?
      !!unwrap(str)
    end

    def self.key_root
      @@key_root ||= ENV["KEY_ROOT"]
    end

    def self.key_root=(key_root)
      @@key = nil
      @@key_root = key_root
    end

    def self.key=(key)
      @@key = key
    end

    def self.key
      @@key ||= load_key_file("v2_key") || begin
        key_file = File.expand_path("v2_key", key_root)
        msg = <<-EOS
  #{key_file} doesn't exist!
  On an appliance, it should be generated on boot by evmserverd.

  If you're a developer, you can copy the #{key_file}.dev to #{key_file}.

  Caution, using the developer key will allow anyone with the public developer key to decrypt the two-way
  passwords in your database.
  EOS
        STDERR.puts msg
        Key.new(nil, nil, nil, true)
      end
    end

    def self.generate_symmetric(filename = nil)
      Key.new.tap { |key| store_key_file(filename, key) if filename }
    end

    protected def self.wrap(encrypted_str)
      "v2:{#{encrypted_str}}"
    end

    protected def self.unwrap(str)
      _unwrap(str) || _unwrap(extract_erb_encrypted_value(str))
    end

    private def self._unwrap(str)
      return str if str.nil? || str.empty?

      match = str.match(REGEXP_START_LINE)
      match[1] if match
    end

    protected def self.store_key_file(filename, key)
      File.write(filename, key.to_h.to_yaml, File::Permissions(0o440))
    end

    protected def self.load_key_file(filename)
      return filename if filename.responds_to?(:decrypt64)

      # if it is an absolute path, or relative to pwd, leave as is
      # otherwise, look in key root for it
      filename = File.expand_path(filename, key_root) unless File.exists?(filename)
      return nil unless File.exists?(filename)

      yaml_data = YAML.parse(File.read(filename))

      algorithm = yaml_data[":algorithm"]?.to_s
      key       = yaml_data[":key"]?.to_s
      iv        = yaml_data[":iv"]?.to_s if yaml_data[":iv"]?

      Key.new(algorithm, key, iv)
    end

    protected def self.extract_erb_encrypted_value(value)
      return $1 if value =~ /\A<%= (?:MiqPassword|DB_PASSWORD|ManageIQ::Password)\.decrypt\(['"]([^'"]+)['"]\) %>\Z/
    end

    class Key
      GENERATED_KEY_SIZE = 32

      property  algorithm : String?
      property  iv        : String?
      property  key       : String?
      property  raw_iv    : String
      property  raw_key   : String
      property? fake_key = true

      def self.generate_key(password = nil, salt = nil)
        password ||= Random::Secure.random_bytes(GENERATED_KEY_SIZE)
        Base64.strict_encode(Digest::SHA256.digest("#{password}#{salt}")[0, GENERATED_KEY_SIZE])
      end

      def initialize(algorithm = nil, key = nil, iv = nil, fake_key = false)
        @algorithm = algorithm || "aes-256-cbc"
        @key       = key || generate_key
        @raw_key   = Base64.decode_string(@key.as(String))
        @iv        = iv
        @raw_iv    = Base64.decode_string(iv || "")
      end

      def encrypt(str)
        apply(:encrypt, str)
      end

      def encrypt64(str)
        Base64.strict_encode(encrypt(str))
      end

      def decrypt(str)
        apply(:decrypt, str)
      end

      def decrypt64(str)
        decrypt(Base64.decode_string(str))
      end

      def to_s
        @key
      end

      def to_h
        {
          :algorithm => @algorithm,
          :key       => @key
        }.tap do |h|
          h[:iv] = @iv if @iv
        end
      end

      private def generate_key
        raise "key can only be generated for the aes-256-cbc algorithm" unless @algorithm == "aes-256-cbc"
        self.class.generate_key
      end

      private def apply(mode, str)
        c = OpenSSL::Cipher.new(@algorithm.to_s)
        mode = :encrypt ? c.encrypt : c.decrypt

        c.key = @raw_key
        c.iv  = @raw_iv if @iv

        io = IO::Memory.new
        io.write(c.update(str))
        io.write(c.final)
        io.rewind

        io.gets_to_end
      end
    end
  end
end

require "option_parser"

DEFAULT_KEY_FILE = File.join(Dir.current, "certs", "v2_key")

options = {
  :mode    => "decrypt",
  :debug   => ENV["DEBUG"]? || false,
  :keyfile => DEFAULT_KEY_FILE
}

OptionParser.parse do |opts|
  opts.banner = "Usage: #{File.basename(PROGRAM_NAME)} [--encrypt|--decrypt] [--key KEYFILE] [string]"

  opts.separator ""
  opts.separator "Encrypts/Decrypts [string] (can be a value or passed from STDIN)"
  opts.separator "using ManageIQ::Password."
  opts.separator ""
  opts.separator "Options:"

  opts.on("-d",       "--decrypt", "Decrypt the value (default)") { options[:mode] = "decrypt" }
  opts.on("-e",       "--encrypt", "Encrypt the value")           { options[:mode] = "encrypt" }

  opts.on("-k KEY",   "--key=KEY", "Path to the key file (default: #{DEFAULT_KEY_FILE})") do |path|
    options[:keyfile] = path
  end

  opts.on("--debug",               "Print debugging info") { options[:debug] = true  }

  opts.on("-h",       "--help",    "Display help") do
    puts opts
    exit
  end
end

ManageIQ::Password.key_root = File.dirname(options[:keyfile].as(String))

puts <<-DEBUG if options[:debug]
==============================================================================
Mode:         #{options[:mode]}
Key File:     #{options[:keyfile]}
Algorithm:    #{ManageIQ::Password.key.algorithm}
IV (Base64):  #{ManageIQ::Password.key.iv}
IV (Hex):     #{ManageIQ::Password.key.raw_iv.to_s.to_slice.hexstring}
Key (Base64): #{ManageIQ::Password.key.key}
Key (Hex):    #{ManageIQ::Password.key.raw_key.to_slice.hexstring}
==============================================================================
DEBUG

str   = ARGV.shift?
str ||= ARGF.gets_to_end.strip

case options[:mode]
when "decrypt" then
  puts ManageIQ::Password.decrypt(str)
when "encrypt"  then
  puts ManageIQ::Password.encrypt(str)
else
  STDERR.puts "ERROR: Invalid mode: #{options[:mode]}"
	exit 1
end
