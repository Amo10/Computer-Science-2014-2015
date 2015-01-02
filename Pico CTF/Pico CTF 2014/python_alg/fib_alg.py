# fib_alg.py Using the algebraic method.

def main():
    print(fib(int(input("Fibonacci of: "))))

def square(x):
    """Returns x times x."""
    return x * x

def even(x):
    """Returns True only if x is even."""
    return x % 2 == 0

def fib(x):
    """This function launches fib_iter() with the correct starting values for
        a, b, p and q. The user-supplied number is used as a counter."""
    return fib_iter(1, 0, 0, 1, x)

def fib_iter(a, b, p, q, count):
    """This function uses successive squaring and the
        algebraic method of finding Fibonacci numbers."""
    if count == 0:
        return b
    elif even(count):
        return fib_iter(a, b, square(p) + square(q), square(q) + 2 * p * q, count / 2)
    else:
        return fib_iter(b * q + a * q + a * p,
                b * p + a * q, p, q, count - 1)

# main
if __name__ == "__main__":
    main()
