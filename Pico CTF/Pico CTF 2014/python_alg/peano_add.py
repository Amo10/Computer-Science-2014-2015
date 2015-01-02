# peano_add.py - the algorithm for addition 
# using only "-1" and "+1".

def inc(x):
    """Returns x + 1"""
    return x+1

def dec(x):
    """Returns x - 1"""
    return x-1

def peano(x, y):
    """Takes two integers and adds them using Peano addition."""
    if x == 0:
        return y
    else:
        return peano (dec(x), inc(y))

# main
if __name__ == "__main__":
    print("Peano Addition.")
    a = int(input("First number: "))
    b = int(input("Second number: "))
    print(peano(a, b))
