# fib2.py - calculates the fibonacci series.
# using a function


def fibonacci(number):
    fib = [0, 1]
    for i in range(number):
        fib.append(fib[i] + fib[i+1])
    return(fib[i])

print("Fibonacci")
request = int(input("Which item in the series? "))
print(fibonacci(request))
    
