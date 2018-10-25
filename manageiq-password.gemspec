
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "manageiq/password/version"

Gem::Specification.new do |spec|
  spec.name          = "manageiq-password"
  spec.version       = ManageIQ::Password::VERSION
  spec.authors       = [
    "Jason Frey",
    "Oleg Barenboim",
    "Joe Rafaniello",
    "Keenan Brock",
    "Brandon Dunne",
    "Adam Grare"
  ]
  spec.email         = [
    "jfrey@redhat.com",
    "obarenbo@redhat.com",
    "jrafanie@redhat.com",
    "kbrock@redhat.com",
    "bdunne@redhat.com",
    "agrare@redhat.com"
  ]

  spec.summary       = %q{A simple encryption util for storing passwords in a database.}
  spec.homepage      = "https://github.com/ManageIQ/manageiq-password"
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
