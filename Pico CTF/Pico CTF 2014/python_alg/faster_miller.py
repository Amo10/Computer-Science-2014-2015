# faster_miller.py The Miller-Rabin Primality test
# Some Carmichael numbers: 561, 1105, 1729, 2465, 2821, 6601.
# Some Mersenne Primes:(2^13)-1, (2^17)-1, (2^19)-1,(2^31)-1,(2^61)-1,(2^89)-1,

import random, math

TESTS = 5  # default number of times to run the test.

def main():
    print("*** Primes ***")
    print("\nUsage:")
    print("1: To test a number, just enter it. ")
    print("2: For a list, enter a start number and how many you want (separated by a comma).")
    print("3: To test a Mersenne Number, type 'm', a comma and the exponent.")
    print("4: For five twin primes, type 't', a comma and the start number.")
    print("For the Goldbach Conjecture, type 'g', a comma and an even number.")
    print("Any other input will cause the program to quit.")

    while 1:
        my_string = input("? ")
        try:
            ans = is_prime(int(my_string))
            print(ans)
        except ValueError:
            try:
                p, t = my_string.split(',')
                try:
                    p = int(p)
                    t = int(t)
                    if even(p):
                        p += 1
                    print(next_p(p, t, []))
                except ValueError:
                    try:
                        if p == 'm':
                            p = mersenne(int(t))
                            print("Mersenne Number: ", p)
                            print(is_prime(p))
                        elif p == 't':
                            print(twins(int(t)))
                        elif p == 'g':
                            print(goldbach(int(t)))


                    except ValueError:
                        break
            except:
                break        

def is_prime(x, t = TESTS):
    """Takes a number and the number of times to tun the test."""
    if x < 2:
        return False
    elif x < 4:
        return True
    elif even(x):
        return False
    else:
        s, d = as_2sd(x - 1)
        return do_tests(x, s, d, t)

def even(n):
    """Returns True for even numbers."""
    return n % 2 == 0

def do_tests(n, s, d, t):
    """Returns True only if the number passes t tests."""
    for i in range(t):
        if is_composite(n, s, d):
            return False
    return True

def as_2sd(d):
    """Returns a number in the form (2 ^ s) * d."""
    s = 0
    while even(d):
        s += 1
        d //= 2
    return [s, d]
   
def is_composite(n, s, d):
    """Miller-Rabin test. Returns True if n is composite."""
    a = random.randint(2, n)
    if pow(a, d, n) == 1:
        return False
    for r in range(s):
        ind = (2 ** r) * d
        if pow(a, ind, n) == n - 1:
            return False
    return True

def next_p(a, b, primes):
    """Runs tests until a list of primes length b can be returned."""
    if b == 0:
        return primes
    elif is_prime(a):
        primes.append(a)
        return next_p(a + 2, b - 1, primes)
    else:
        return next_p(a + 2, b, primes)
        

def twins(n):
    """Looks for 10 twin primes greater than n."""
    print("Searching for twin primes.")
    if even(n):
        n += 1
    twins = []
    while len(twins) < 5:
        if is_prime(n) and is_prime(n+2):
            twins.append((n, n + 2))
        n += 2
    return twins


def goldbach(n):
    small_p = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 41, 43, 47]
    """Looks for the two primes whose sum is n."""
    if not even(n):
        print("I need an even number.")
    for i in range(2, n):
        if i in small_p or is_prime(i):
            j = n - i
            if j in small_p or is_prime(j):
                return [i, j]

def mersenne(p):
    """Returns the Mersenne Number generated from p."""
    return 2 ** p -1

# main
if __name__ == "__main__":
    main()
