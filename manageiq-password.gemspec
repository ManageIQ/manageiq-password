lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "manageiq/password/version"

Gem::Specification.new do |spec|
  spec.name          = "manageiq-password"
  spec.version       = ManageIQ::Password::VERSION
  spec.authors       = "ManageIQ Authors"

  spec.summary       = %q{A simple encryption util for storing passwords in a database.}
  spec.homepage      = "https://github.com/ManageIQ/manageiq-password"
  spec.licenses      = ["Apache-2.0"]

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "manageiq-style"
  spec.add_development_dependency "rake",          ">= 12.3.3"
  spec.add_development_dependency "rspec",         "~> 3.0"
  spec.add_development_dependency "simplecov"
end
