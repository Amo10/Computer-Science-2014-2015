# This is to test PDF outlines. We use some rather non-sensical
# code below that must be syntactically correct!


def foo0():
    return

class Bar0:
    def __init__(self):
      pass
    def __str__(self):
        return ''
        
def foo1():
  if 1:
    return
  else:
      pass
      pass
    
def foo2():
        def foo2a():
          return
        def foo2b():
            return
        return foo2a()

def foo3(): pass

class Bar1:
    def __init__(self):
        pass
    def __str__(self):
        def bar1():
            class Bar1a: pass
            class Bar1b: pass
            return ''
        return bar1()
        
if __name__ == '__main__':
    def foo4():
          pass
    
    foo0()
    foo1()
    foo2()
    foo3()
    foo4()
    
    b0 = Bar0()
    b1 = Bar1()
    
    print 'Syntax ok.'
