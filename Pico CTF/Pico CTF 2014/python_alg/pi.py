# pi.py - arctan(1) * 4 = pi
from decimal import *
getcontext().prec = 100

def arctan(n):
    """Uses Gregory's formula for calculating atan."""
    temp = n
    atan = 0
    i = 3
    while atan != n:
        atan = n
        n = n - (temp ** i) / i + (temp ** (i + 2) / (i + 2))
        i += 4
    return n

def euler(a, b):
    """Uses Euler's formula and fibonacci numbers."""
    euler = 0
    temp = 1 # this is to make sure the while runs at least once!
    while temp != euler:
        temp = euler
        euler += arctan(1/b)
        a = b + a
        b = b + a
    return euler
    
#main
print(euler(1, Decimal(2)) * 4)
