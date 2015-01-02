# cesaro.py
# Uses monte-carlo method to calculate pi.

import random, math

def main():
    print("*** Cesaro's method for pi. ***")
    while 1:
        t = int(input("How many trials? "))
        if t == 0:
            return
        else:
            print(math.sqrt(6 / monte_carlo(cesaro, t)))
        
def monte_carlo(f, t):
    """Takes a function and a number of trials.
    Returns the ratio of passed trials to the total number of trials."""
    passed = 0
    for i in range(t):
        if f():
            passed += 1
    return passed / t

def cesaro():
    """Returns true if two random numbers are coprime."""
    return 1 == gcd(random.randint(1, 999999), random.randint(1, 999999))

def gcd(a,b):
    """Takes two integers and returns gcd."""
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

if __name__ == "__main__":
    main()
