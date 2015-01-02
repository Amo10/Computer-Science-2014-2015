# root.py - roots, Newton's way.

# some constants used in the program.
DIGITS = 5                  # number of digits to display
DX    = 10 ** -7            # dx is used in calculating the derivative
ERROR = 10 ** -(DIGITS + 1) # margin of error

def main():
    print("*** Roots by Newton's Method. ***""")
    print("Enter a,b to find the bth root of a.")
    print("Enter q to quit.")
    while 1:
        a = input("? ")
        if a == 'q':
            break
        a, b = a.split(',')
        display_root(int(a),int(b))
        
def display_root(a, b):
    """Takes a and b, calls root and displays answer as an integer if possible.
    Otherwise displays it rounded to DIGITS digits."""
    c = root(a, b)
    d = round(c)
    if d ** b == a:
        print(d)
    else:
        k = "%." + str(DIGITS) + 'f'
        print(k % c)

def root(x, n):
    """Takes integers x & n and returns the nth root of x.
    Passes a function to newton() and a guess of 1."""
    return newton(lambda y: x - y ** n, 1)

def newton(f, guess):
    """Takes a function and a guess.
    Calls fixed_point on the average damped version of f()."""
    df = deriv(f)
    return fixed_point(av_damp(lambda x: (x - (f(x) / df(x)))), guess)

def deriv(f):
    """Takes a function and returns its derivative."""
    return lambda x: (f(x + DX) - f(x)) / DX

def fixed_point(f, new):
    """Takes a function and a guess.
    Returns the fixed point of the function."""
    old = 0
    while not close_enough(old, new):
        old, new = new, f(new)
    return new

def close_enough(old, new):
    """Returns True if old & new differ by less than ERROR."""
    return abs(old - new) < ERROR

def av(x, y):
    """Returns average of x and y."""
    return (x+y)/2

def av_damp(f):
    """Takes a function and returns average-damped version."""
    return lambda x: av(f(x), x)

# main
if __name__ == "__main__":
    main()
