# fib_r.py - calculates the Fibonacci series, recursively,
# using command line arguments

import sys

def main():
    if (len(sys.argv) != 2):
        usage()
    else:
        try:
            num = int(sys.argv[1])
            print("Fibonacci of", num, "is", fib(num))
        except ValueError:
            usage()
def usage():
    """Tells user how to run the program."""
    print("Usage: for some positive integer, n:\nfib_r.py n")
   
def fib(n):
    """Takes an integer n and returns the nth Fibonacci number"""
    if n < 2:
        return n
    else:
        return fib(n - 1) + fib(n - 2)

# main
if __name__ == "__main__":
    main()
