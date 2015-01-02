# fib1.py - calculates the fibonacci series.
# using a list


print("Fibonacci")
fib = [0, 1]

for i in range(10):
    fib.append(fib[i] + fib[i+1])

print(fib)


    
