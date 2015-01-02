# This is to test "complex" code.

class C:
    """Some doc 'string' goes here, "hopefully
    
    one" that is more 'ueful', too.
    
    Blurb...
    """
    
    def __init__(self, a, b, c=None, d="""Nonsensical 
string"""):
        print d
        
        if a > b <= 0 and c: print 'yep1a'; print 'yep1b'
        else: 
            if 1: print map(lambda x: x+1, range(10))
            else: print 0
    
    def foo(self):
        if 1: pass; pass
        def bar(): pass

c1 = C(2, 0, 1)
c2 = C(2, 1, 1)