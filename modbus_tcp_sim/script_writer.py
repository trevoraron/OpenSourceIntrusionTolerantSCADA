#!/usr/bin/env python

import math
import time
import sys
import fileinput

read = [ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xab, 0xcd, 0xef ]
write = [ 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00 ]
s = [ 0, 0, 0, 0, 0, 0, 0, 0, 0 ]

# Default amplitude of sine wave
if len(sys.argv) == 2:
    amplitude = int( sys.argv[1], 0 )
else:
    amplitude = 20

while True:
    # Calculate function values
    for i in xrange(0, len(read)):
        if amplitude:
            s[i] = read[i] % amplitude
            read[i] += 1

    # Modify data lines of ini file
    for line in fileinput.input( "mtss.ini", inplace=True ):
        # Find & modify read values
        if "read0x00000" in line:
            print "read0x00000=%02x %02x %02x %02x %02x %02x" % (s[0], s[1], s[2], s[3], s[4], s[5])
        elif "read0x04000" in line:
            print "read0x04000=%02x %02x %02x" % (s[6], s[7], s[8])
        else:
            # Find and get write values
            if "write0x" in line:
                ptr = line.index( "=" )
                index = int( line[ptr-1] ) * 2
                vals = line[ptr+1:].split()
                write[index] = int( vals[0], 16 )
                write[index+1] = int( vals[1], 16 )

                # Update amplitude
                amplitude = write[0] << 16
                amplitude += write[1]

            print line,

    # Print the newly modified version to stdout
    file = open( "mtss.ini", "r" )
    print file.read()
    file.close()

    time.sleep(1)
