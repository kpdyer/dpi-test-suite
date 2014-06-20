bc = `which broccoli-config`
unless bc.length > 0
  puts "You need to have broccoli-config in your path!"   
  exit(-1)
end