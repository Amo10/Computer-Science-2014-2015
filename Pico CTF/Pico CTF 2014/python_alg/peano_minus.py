# peano_minus.py - the algorithm for subtraction 
# using only "-1" and "+1".

def peano_minus(x, y):
    """Takes two integers and subtracts second from first using Peano algorithm."""
    if y == 0:
        return x
    else:
        return peano_minus (x-1, y-1)


# main
if __name__ == "__main__":
    print("Peano Subtraction.")
    a = int(input("First number: "))
    b = int(input("Second number: "))
    print(peano_minus(a, b))
