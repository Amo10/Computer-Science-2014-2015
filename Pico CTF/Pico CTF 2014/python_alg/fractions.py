# fractions.py 
# An implementation of rational number arithmetic

def main():
    print("*** Rational Numbers ***")
    print("Enter 'q' to quit.")
    while 1:
        try:
            temp = input(">> ")
            if temp == 'q':
                return
            print(rat_to_string(evaluate(parse(temp.split()))))
        except ValueError:
            print("Huh?")

# the lambda expressions allow us to use variables to stand for functions
def evaluate(my_list):
    """Takes a list and performs arithmetic until list is length 1."""
    ops = [('*', lambda x,y: times(x,y)),
           ('/', lambda x,y: times(x,reciprocal(y))),
           ('+', lambda x,y: add(x,y)),
           ('-', lambda x,y: add(x,minus(y)))]
    while len(my_list) > 1:
        for key, f in ops:
            if key in my_list:
                i = my_list.index(key)
                my_list[i-1: i+2] = [f(my_list[i - 1], my_list[i +1])]
                break
    return my_list[0]                    

def parse(some_list):
    """Takes a list and returns a list of fractions and operators."""
    ops = ['*', '/', '+', '-']
    new = []
    for item in some_list:
        if item in ops:
            new.append(item)
        else:
            new.append(make_rat(item.split('/')))
    return new

def make_rat(k):
    """Returns a list representing k as a (simplified) fraction."""
    if len(k) == 2:
        a, b = numer(k), denom(k)
        d = gcd(a, b)
        return [a//d, b//d]
    else:
        return [int(k[0]), 1]
    
def numer(x):
    """Returns the numerator of x."""
    return int(x[0])

def denom(x):
    """Returns the denominator of x"""
    return int(x[1])

# we use gcd to simplify fractions
def gcd(a,b):
    """Takes two integers and returns gcd."""
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

# rules for fraction arithmetic        
def add(a, b):
    """Takes 2 fractions and returns the sum as a fraction."""
    return make_rat([numer(a) * denom(b) + numer(b) * denom(a), denom(a) * denom(b)])

def times(a, b):
    """Takes 2 fractions and returns the procuct as a fraction."""
    return make_rat([numer(a) * numer(b) , denom(a) * denom(b)])

def reciprocal(y):
    """Returns reciprocal of y; used in division."""
    return [denom(y), numer(y)]

def minus(y):
    """Returns 0 - y; used in subtraction."""
    return [-numer(y), denom(y)]

# if the result is top heavy, it will be printed as a whole number and a fraction.
def rat_to_string(rat):
    """Turns a rational number into a string."""
    n, d = numer(rat), denom(rat)
    if d == 1:
        return str(n)
    string = ""
    if n > d:
        w, n = divmod(n, d)
        string = str(w) + " "
    return string + str(n) + "/" + str(d)

if __name__ == "__main__":
    main()
