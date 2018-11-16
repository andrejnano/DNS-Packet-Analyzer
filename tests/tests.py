
from testclass import *

def LoadTestSet(tests):

    # expected legit commands 
    tests.add("<no-args>", "./dns-export", 0)
    # tests.add("-i", "./dns-export -i en0", 0)
    # tests.add("-i -s", "./dns-export -i en0 -s syslogserver", 0)
    # tests.add("-i -s -t", "./dns-export -i en0 -s syslogserver -t 10", 0)
    # tests.add("-i -t", "./dns-export -i en0 -t 10", 0)
    tests.add("-r", "./dns-export -r example.pcap", 0)
    tests.add("-r -s", "./dns-export -r example.pcap -s syslogserver", 0)

    # invalid commands
    tests.add("-i -r", "./dns-export -i en0 -r example.pcap", 1)
    tests.add("-i -r -s", "./dns-export -i en0 -r example.pcap -s syslogserver", 1)
    tests.add("-i -r -s -t", "./dns-export -i en0 -r example.pcap -s syslogserver -t 20", 1)
    tests.add("-i -t -r", "./dns-export -i en0 -t 20 -r example.pcap", 1)
    tests.add("-r -s -t", "./dns-export -r example.pcap -s syslogserver -t 20", 1)
    tests.add("-r -t", "./dns-export -r example.pcap -t 20", 1)
    tests.add("-s", "./dns-export -s syslogserver", 1)
    tests.add("-s -t", "./dns-export -s syslogserver -t 20", 1)
    tests.add("-t", "./dns-export -t 20", 1)


