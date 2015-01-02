# This is to test very long lines and the way py2pdf
# wraps them onto new lines and/or pages.

# This test should be performed with all default values of py2pdf applied.
# I.e. Courier as mono-space font with a size of 8 points.

for c in 'A rather not very very long string.':
    print c,
    
print

for c in 'A string that is supposed to be long,' + 'but not long enough to span' + ' more than a normal line, ' + 'which is why it has been split into substrings' + 'that are concatenated again.\n\n': # As we see the strings all keep their original lengths!
    print c,
    
print

for ch in 'Now, this is a really long string that is not composed from others using string concatenation with the plus operator, but is simple one big chunk!':
    print ch,

print

for ch in 'Now,-this-too-is-a-really-long-string-but-it-does-not-contain-a-single-blank-that-could-be-used-to-split-it-in-any-meaningful-way!':
    print ch,

print

def aVeryLongFunctioName_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789():
    pass
    
def aFunctionWithAnEvenLongerName_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789(): # Never do that in real life!
    pass
    
