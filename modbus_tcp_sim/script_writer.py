#!/usr/bin/env python

import math
import time
import sys
import fileinput

v = [ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xbc, 0xab, 0xcd, 0xef ]
s = [ 0, 0, 0, 0, 0, 0, 0, 0, 0 ]

# Default amplitude of sine wave
if len(sys.argv) == 2:
    amplitude = int( sys.argv[1], 0 )
else:
    amplitude = 20

while True:
#for x in range(0,1):
    # Calculate sine values
    for i in xrange(0, len(v)):
        s[i] = v[i] % amplitude
        v[i] += 1

    # Modify data lines of ini file
    for line in fileinput.input( "mtss.ini", inplace=True ):
        if "read0x00000" in line:
            print "read0x00000=%02x %02x %02x %02x %02x %02x" % (s[0], s[1], s[2], s[3], s[4], s[5])
        elif "read0x04000" in line:
            print "read0x04000=%02x %02x %02x" % (s[6], s[7], s[8])
        else:
            print line,

    # Print the newly modified version to stdout
    file = open( "mtss.ini", "r" )
    print file.read()
    file.close()

    time.sleep(1)

