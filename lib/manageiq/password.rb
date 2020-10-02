require "manageiq/password/version"
require "manageiq/password/password_mixin"

require 'openssl'
require 'base64'
require 'yaml'

module ManageIQ
  class Password
    class PasswordError < StandardError; end

    REGEXP = /v2:\{([^}]*)\}/
    REGEXP_PASSWORD = /v2(:\{[^}]*\}|%3A%7B.*?%7D)/ # for "v2:{...}" or its URL encoded string
    REGEXP_START_LINE = /^#{REGEXP}/
    MASK = '********'.freeze

    attr_reader :encStr

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
        key.decrypt64(enc).force_encoding('UTF-8')
      rescue
        raise PasswordError, "cannot decrypt encrypted string"
      end
    end

    def recrypt(str, prior_key = nil)
      return str if str.nil?

      decrypted_str   = decrypt(str, prior_key) if prior_key rescue nil
      decrypted_str ||= decrypt(str)
      encrypt(decrypted_str)
    end

    def self.encrypt(*args)
      new.encrypt(*args)
    end

    def self.decrypt(*args)
      new.decrypt(*args)
    end

    def self.recrypt(*args)
      new.recrypt(*args)
    end

    def self.encrypted?(str)
      return false if str.nil? || str.empty?
      !!unwrap(str)
    end

    def self.md5crypt(str)
      cmd = "openssl passwd -1 -salt \"miq\" \"#{try_decrypt(str)}\""
      `#{cmd}`.split("\n").first
    end

    def self.sysprep_crypt(str)
      Base64.encode64("#{try_decrypt(str)}AdministratorPassword".encode("UTF-16LE")).delete("\n")
    end

    def self.sanitize_string(s)
      s.gsub(REGEXP_PASSWORD, MASK)
    end

    def self.sanitize_string!(s)
      s.gsub!(REGEXP_PASSWORD, MASK)
    end

    def self.try_decrypt(str)
      encrypted?(str) ? decrypt(str) : str
    end

    def self.try_encrypt(str)
      encrypted?(str) ? str : encrypt(str)
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
        Kernel.warn msg
        nil
      end
    end

    def self.generate_symmetric(filename = nil)
      Key.new.tap { |key| store_key_file(filename, key) if filename }
    end

    protected

    def self.wrap(encrypted_str)
      "v2:{#{encrypted_str}}"
    end

    def self.unwrap(str)
      _unwrap(str) || _unwrap(extract_erb_encrypted_value(str))
    end

    private_class_method def self._unwrap(str)
      return str if str.nil? || str.empty?
      str.match(REGEXP_START_LINE)&.public_send(:[], 1)
    end

    def self.store_key_file(filename, key)
      File.write(filename, key.to_h.to_yaml)
    end

    def self.load_key_file(filename)
      return filename if filename.respond_to?(:decrypt64)

      # if it is an absolute path, or relative to pwd, leave as is
      # otherwise, look in key root for it
      filename = File.expand_path(filename, key_root) unless File.exist?(filename)
      return nil unless File.exist?(filename)

      Key.new(*YAML.load_file(filename).values_at(:algorithm, :key, :iv))
    end

    def self.extract_erb_encrypted_value(value)
      return $1 if value =~ /\A<%= (?:MiqPassword|DB_PASSWORD|ManageIQ::Password)\.decrypt\(['"]([^'"]+)['"]\) %>\Z/
    end

    class Key
      GENERATED_KEY_SIZE = 32

      def self.generate_key(password = nil, salt = nil)
        password ||= OpenSSL::Random.random_bytes(GENERATED_KEY_SIZE)
        Base64.strict_encode64(Digest::SHA256.digest("#{password}#{salt}")[0, GENERATED_KEY_SIZE])
      end

      def initialize(algorithm = nil, key = nil, iv = nil)
        @algorithm = algorithm || "aes-256-cbc"
        @key       = key || generate_key
        @raw_key   = Base64.decode64(@key)
        @iv        = iv
        @raw_iv    = iv && Base64.decode64(iv)
      end

      def encrypt(str)
        apply(:encrypt, str)
      end

      def encrypt64(str)
        Base64.strict_encode64(encrypt(str))
      end

      def decrypt(str)
        apply(:decrypt, str)
      end

      def decrypt64(str)
        decrypt(Base64.decode64(str))
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

      private

      def generate_key
        raise "key can only be generated for the aes-256-cbc algorithm" unless @algorithm == "aes-256-cbc"
        self.class.generate_key
      end

      def apply(mode, str)
        c = OpenSSL::Cipher.new(@algorithm)
        c.public_send(mode)
        c.key = @raw_key
        c.iv  = @raw_iv if @raw_iv
        c.update(str) << c.final
      end
    end
  end
end

# Backward compatibility previous class names
DB_PASSWORD = MiqPassword = ManageIQ::Password
