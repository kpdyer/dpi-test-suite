require 'mkmf'

if ex = find_executable("broccoli-config")
  $CFLAGS << " " + `#{ex} --cflags`.chomp
  $LDFLAGS << " " + `#{ex} --libs`.chomp
else
  raise "You need to have 'broccoli-config' in your path!"
end

if have_header("broccoli.h") and
   # check the broccoli library for the existence 
   # of the new event registration function
   have_library("broccoli", "bro_event_registry_add_compact") and
   have_library("ssl")
  create_makefile("broccoli_ext")
end
