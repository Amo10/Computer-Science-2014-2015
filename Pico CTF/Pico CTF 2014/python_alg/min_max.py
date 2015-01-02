# min_max.py
# Demonstrates algorithms for minimum and maximum.

def my_min(x, y):
    """"Takes two numbers and returns the smallest."""
    return (x + y - abs(x - y)) / 2

def my_max(x, y):
    """Takes two numbers and returns the largest."""
    return (x + y + abs(x - y)) / 2

# main
if __name__ == "__main__":
    print("*** Minimum and Maximum ***")
    a = float(input("a: "))
    b = float(input("b: "))
    print("Maximum of a & b: ", my_max(a, b))
    print("Minimum of a & b: ", my_min(a, b))
