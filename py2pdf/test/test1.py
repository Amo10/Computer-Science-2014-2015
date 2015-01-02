#if 1: print 'This should be comment!!'
# else: print 'But only this one really is!!'

# Seems to be a problem with PyFontify, needing a 
# whitespace after a hash? py2html using PyFontify
# shows the same behaviour. Haven't tested yet with
# mxTextTools...

# Just has fixed the bug in PyFontify.py 0.3.3...