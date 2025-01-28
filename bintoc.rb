#!/usr/bin/ruby
# Cod3d By 0xNinjaCyclone

open( "stub.bin", "rb" ) { |f|
    print "BYTE x64_stub[] =   "
    while buf = f.read( 16 )
        print "\n#{ ' ' * 4 * 5 }\""
        buf.bytes.map { |e| 
            print "\\x%0.2x" % e 
        }
        print '"'
    end
    puts ';';
}
