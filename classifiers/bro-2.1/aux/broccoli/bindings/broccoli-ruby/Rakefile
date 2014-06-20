require 'rake/rdoctask'
require 'rake/packagetask'
require 'rake/testtask'

PKG_VERSION = "1.5.2"
PKG_NAME = "broccoli"
PKG_FILE_NAME = "#{PKG_NAME}-#{PKG_VERSION}"
RELEASE_NAME = "#{PKG_NAME}-#{PKG_VERSION}"

desc 'Generate documentation.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = "#{PKG_NAME} -- An interface to the Broccoli library used for communicating with the Bro intrusion detection system."
  rdoc.options << '--line-numbers' << '--inline-source' << '-o' << './html'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include('lib/**/*.rb')
end