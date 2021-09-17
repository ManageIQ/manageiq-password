require "bundler/gem_tasks"
require "rspec/core/rake_task"

require "rake/clean"

CLEAN.include "exe/manageiq-password.crystal"

RSpec::Core::RakeTask.new(:spec)

namespace :crystal do
  file "lib/manageiq-password.cr"
  directory "pkg"

  file "pkg/manageiq-password.crystal" => %w[pkg lib/manageiq-password.cr] do |t|
    sh "crystal build --release lib/manageiq-password.cr -o #{t.name}"
  end

  desc "Build the crystal cli"
  task :build   => "pkg/manageiq-password.crystal"

  desc "Re-build crystal cli"
  task :rebuild => [:clean, :build]
end

task :default => :spec
