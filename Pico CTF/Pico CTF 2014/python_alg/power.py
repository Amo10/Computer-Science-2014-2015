# power.py - demonstrates raising numbers to integer powers
# by successive squaring.

def power(x, y):
    """"Takes a real number x and an integer y and returns x^y."""
    z = 1
    while y != 0:
        if y % 2 == 0:
            x *= x
            y //= 2
        else:
            z *= x
            y -= 1
    return z

# main
print(" *** exponentiation by successive squaring ***")
print("This program will raise x to the power of y\n(as long as y is a whole number!)")
a = float(input("x: "))
b = int(input("y: "))
print("Result: ", power(a, b))
