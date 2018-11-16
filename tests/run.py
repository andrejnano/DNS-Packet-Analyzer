#!/usr/bin/env python3

# Testing for the dns-export project [ISA 2018/19 @ FIT VUTBR]
# Author: Andrej Nano [xnanoa00]

from subprocess import *
from os import path
from testclass import TestSet
from tests import LoadTestSet

test_set = TestSet()
LoadTestSet(test_set)

progress_counter = 0

print('Going to run tests...\n')

# run all tests
for test in test_set:
    
    process = run(test.command.split(), stdout=PIPE, stderr=PIPE, timeout=3)

    if process.returncode == test.returncode:
        test_set.success()
        print('✔︎ Test {:>2} success: [{}]'.format(progress_counter, test.description))
    else:
        print('✕ Test {:>2} failed: [{}] :: Expected exit code {} got {}'.format(progress_counter, test.description, test.returncode, process.returncode))

    progress_counter += 1


print(str(test_set))
