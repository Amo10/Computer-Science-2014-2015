README

This folder contains a demo script that can be used to
generate a whole bunch of sample PDF files according to
different wishes (coded into the script).

The idea is to run py2pdf with an argument specifying 
the name of a sample Python source file and see all 
kind of different PDF output without struggeling to get
an initial set of options right to do the same.

demo.py contains a set of test functions named test<#>
which will be called in alphabetical order for the input
file. If you ommit the input file demo.py will run on
itself. 

One of the tests uses an option config file. By conven-
tion this has to be named <inputFile>-config.txt if you
want to use the test function as-is. But of course, you
are free to add your own functions.

The folder contains a set of PDFs generated from demo.py
while running on itself.

Run the following command to get all demo files generated:

  python demo.py

