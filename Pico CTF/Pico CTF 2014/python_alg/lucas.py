# lucas.py
# Lucas-Lehmer numbers to test Mersenne Primes.

def main():
    print("*** Lucas-Lehmer numbers ***")
    while 1:
        n = int(input("\nEnter a prime: "))
        if n < 2:
            break
        mer = mersenne(n)
        print("Mersenne(" + str(n) + ") = " + str(mer))
        luc = lucas(n)
        print("Lucas-Lehmer(" + str(n) + ") = " + str(luc))
        if divides(luc, mer):
            print("Prime")
        else:
            print("Composite.")


def mersenne(p):
    """Returns the Mersenne Number generated from p."""
    return 2 ** p -1

def divides(x, y):
    """Returns true if y divides x."""
    return x % y == 0
    
def next_lucas(p):
    """Calculates the next Lucas-Lehmer number."""
    return p * p - 2

def lucas(n):
    """Returns the Lucas_Lehmer number of n."""
    k = 4
    if n < 2:
        return -1
    if n != 2:
        for i in range(3, n + 1):
            k = next_lucas(k)
    return k

if __name__ == "__main__":
    main()
