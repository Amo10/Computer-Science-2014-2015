# gcd.py Euclid's algorithm for Greatest Common Divisor

def main():
    print(" *** Greatest Common Divisor ***")
    again = 'y'
    while again == 'y':
        x = int(input("x: "))
        y = int(input("y: "))
        print(gcd(x, y))
        again = input("Again? ")

def gcd(a,b):
    """Takes two integers and returns gcd."""

    if b == 0:
        return a
    else:
        return gcd(b, a % b)

if __name__ == "__main__":
    main()
