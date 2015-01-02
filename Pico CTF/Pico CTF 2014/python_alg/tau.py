# tau.py - arctan(1) * 8 = tau = 2pi
from decimal import *

def main():
        print("*** Pi and Tau ***")
        print("Type the number of decimal places of Tau you require.")
        ans = input("For Pi, type a comma and the number of decimal places.\n? ")
        try:
                prec = int(ans)
                c = "Tau"
                k = 8
        except ValueError:
                try:
                        c, prec = ans.split(',')
                        c = "Pi"
                        k = 4
                        prec = int(prec)
                except ValueError:
                        print("Oops.")
                        return 1
        getcontext().prec = prec + 2
        print("Calculating", c, ". . .")
        print(str(euler(1, Decimal(2)) * k)[:-1])
        
def arctan(n):
    """Uses Gregory's formula for calculating atan."""
    copy_of_n = n
    atan = None
    i = 3
    while atan != n:
            atan = n
            n = n - copy_of_n ** i / i + copy_of_n ** (i + 2) / (i + 2)
            i += 4
    return n

def euler(a, b):
    """Uses Euler's formula and Fibonacci numbers."""
    euler = 0
    check = None
    while check != euler:
            check = euler
            euler += arctan(1/b)
            a = b + a
            b = b + a
    return euler

# main
if __name__ == "__main__":
    main()

