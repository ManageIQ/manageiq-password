lib = File.expand_path("../../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'manageiq/password'
require 'optparse'

DEFAULT_KEY_FILE = File.join(Dir.pwd, "certs", "v2_key")

options = {
  :mode    => "decrypt",
  :debug   => !!ENV["DEBUG"],
  :keyfile => DEFAULT_KEY_FILE
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename($0)} [--encrypt|--decrypt] [--key KEYFILE] [string]"

  opts.separator ""
  opts.separator "Encrypts/Decrypts [string] (can be a value or passed from STDIN)"
  opts.separator "using ManageIQ::Password."
  opts.separator ""
  opts.separator "Options:"

  opts.on("-d",       "--decrypt", "Decrypt the value (default)") { options[:mode] = "decrypt" }
  opts.on("-e",       "--encrypt", "Encrypt the value")           { options[:mode] = "encrypt" }

  opts.on("-k",       "--key=KEY", "Path to the key file (default: #{DEFAULT_KEY_FILE})") do |path|
    options[:keyfile] = path
  end

  opts.on(            "--debug", "Print debugging info") { options[:debug] = true  }

  opts.on("-h", "-?", "--help", "Display help") do
    puts opts
    exit
  end
end.parse!

ManageIQ::Password.key_root = File.dirname(options[:keyfile])

puts <<-DEBUG if options[:debug]
==============================================================================
Mode:         #{options[:mode]}
Key File:     #{options[:keyfile]}
Algorithm:    #{ManageIQ::Password.key.algorithm}
IV (Base64):  #{ManageIQ::Password.key.iv}
IV (Hex):     #{ManageIQ::Password.key.raw_iv.to_s.unpack("*H*").first}
Key (Base64): #{ManageIQ::Password.key.key}
Key (Hex):    #{ManageIQ::Password.key.raw_key.to_s.unpack("*H*").first}
==============================================================================
DEBUG

str   = ARGV.shift
str ||= ARGF.read.strip

case options[:mode]
when "decrypt" then
  puts ManageIQ::Password.decrypt(str)
when "encrypt"  then
  puts ManageIQ::Password.encrypt(str)
else
	warn "ERROR: Invalid mode: #{options[:mode]}"
	exit 1
end
