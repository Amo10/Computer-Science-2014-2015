# ramanujan_hcn.py
# a look at Ramanujan's discoveries about HCNs.

def main():
    print("*** Ramanujan's Highly Composite Numbers ***")
    print("Enter a number and I will show you the next 5 HCNs.")
    print("Enter 0 to quit.")
    while 1:
        try:
            a = (int(input(">> ")))
            if a != 0:
                next_5(a+1)
            else:
                return
        except ValueError:
            print("Huh?")
        
def next_5(x):
    """Takes a number and looks for next 5 HCNs, printing as it goes."""
    a = 0
    y = 2
    while a < 10:
        y = is_hcn(x, y)
        if y:
            print(pretty(x, y, factor(x)))
            a += 1
        x += 1

def is_hcn(x, y = 2):
    """Brute-force check to see if x is an HCN."""
    divs = divisors(x)
    for i in range(y, x):
        if not divs > divisors(i):
            return False
    return divs

def pretty(x, d, f):
    """Takes a dictionary and prints it out."""
    l= [str(x) + ": " + str(d)+ " divisors \nPrime Factors: "]
    for x in iter(f):
        l.append(str(x) + '^' + str(f[x]))
    string = l[0]
    for item in l[1:-1]:
        string = string + item + " x "
    return string + l[-1]

def divisors(x):
    """Takes a number and returns the number of divisors."""
    a = 0
    for i in range(1, x+1):
        if x % i == 0:
            a += 1
    return a

def factor(n):
    """Takes an integer and returns a dictionary of prime factors."""
    i = 2
    factors = {}
    while n != 1:
        while n % i == 0:
            n = n // i
            if i not in factors:
                factors[i] = 1
            else:
                factors[i] += 1
        i += 1
    return factors

def roundness(x):
    f = factor(x)
    r = 0
    for key in iter(f):
        r += f[key]
    return r

if __name__ == "__main__":
    main()
