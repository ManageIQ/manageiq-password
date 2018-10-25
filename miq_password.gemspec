
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "miq_password/version"

Gem::Specification.new do |spec|
  spec.name          = "miq_password"
  spec.version       = MiqPassword::VERSION
  spec.authors       = ["Adam Grare"]
  spec.email         = ["agrare@redhat.com"]

  spec.summary       = %q{A simple encryption util for storing passwords in a database.}
  spec.homepage      = "https://github.com/ManageIQ/miq_password"
  spec.license       = "Apache-2.0"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
