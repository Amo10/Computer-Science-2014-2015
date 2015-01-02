# fib.py - calculates the fibonacci series.

a = 0
b = 1
print("Fibonacci")
print(a, b, end=" ")

for i in range(10):
    c = b + a
    print(c, end= " ")
    a, b = b, c

    
