README -- py2pdf 0.5 -- Dedicated to Astor Piazzolla.

SUMMARY

py2pdf is a Python module that will pretty-print Python 
source code into PDF documents. 0.5 is meant to be a quite 
useful release, although many things are likely to change, 
especially about internal APIs. Therefore, better use it 
like shown in the demo script and don't use too much in-
ternals directly. The command line options will probably
not change much, though.

Questions, praise, criticism, suggestions are welcome at
the address below if meant to be of private nature. But 
please be aware of potential delays in my response time
which is due to much travelling. If you want to 'go pub-
lic' or want to address issues of general interest please
try the reportlab-users mailing list at egroups.com:
reportlab-users@egroups.com.

Have fun!

Dinu Gherman
gherman@europemail.com
2000-05-08


FEATURES:
- Python syntax color highlighting in PDF
- rendering arbitrary ASCII files in PDF
- monochrome and color display/printing
- different font names and sizes
- different paper formats and sizes
- line numbering
- PDF bookmarks for classes, methods, functions
- multi-file output (one file per page)
- 100% pure Python, fully platform independent

APPLICABILITY:
- Python syntax color highlighting in PDF
- in theory usable for any other language 
- pretty-printing in a printer-friendly format
- teaching, reviewing, documenting Python code
- writing course material (e.g. sample solutions)
- providing printing engine to Python IDE developers
- providing 'uncorruptable' source code to publishers 
- writing PDF code fragments to be used with pdflatex
- debugging Python code with indentation problems (later)

DEPENDENCIES:
- JvR's PyFontify v. 0.3 (ideally 0.3.3)
- optionally: Marc-Andre's mxTextTools
- ReportLab libraries v. 0.92 (2000-04-10)

KNOWN BUGS:
- Using stdin/stdout on Windows might show unexpected behavior.
