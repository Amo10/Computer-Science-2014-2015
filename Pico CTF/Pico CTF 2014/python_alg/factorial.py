# factorial.py
# using a recursive function to calculate n!

def factorial(num):
    """This function keeps calling itself, until it gets to 1."""
    if num == 0:
        return 1
    else:
        return num * factorial(num-1) 

# main
n = int(input("Factorial of: "))
print(str(n) + "! = " + str(factorial(n)))
