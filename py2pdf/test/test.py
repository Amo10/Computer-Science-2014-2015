#!/usr/bin/env python

"""test.py - Test script for py2pdf 0.5.

The main idea is: take one or more Python files 
and run py2pdf over them for test purposes.

Dinu Gherman
"""


import sys
from py2pdf import *


### Main.

def main(path):
    "Call py2pdf on one Python source file."

    p = PythonPDFPrinter()
    p.process(path)
      

if __name__=='__main__':
    try:
        for f in sys.argv[1:]:
            main(f)
    except IndexError:
        print "No python file(s) specified..."
        sys.exit(0)
