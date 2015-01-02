# peano_div.py - the algorithm for division 
# using only "-1" and "+1".

def peano_minus(x, y):
    """Takes two integers and subtracts second from first."""
    if y == 0:
        return x
    else:
        return peano_minus(x-1, y-1)

def divide(x, y, result):
    """Repeatedly subtracts y from x.
    'result' stores the number of subtractions made."""
    # check to see if we are finished
    if x < y:
        if x == 0:
            # return the answer as a list.
            return [result, 0]
        else:
            # this is for when there is a remainder
            return [result, x]
    else:
        # call the subtraction algorithm
        x = peano_minus(x, y)
        # recursively call 'divide', with result incremented by one.
        return divide(x, y, result + 1)

# main
if __name__ == "__main__":
    print("Peano Division.")
    a = int(input("First number: "))
    b = int(input("Divided by: "))
    ans = divide(a, b, 0)
    if ans[1] == 0:
        print(ans[0])
    else:
        print(ans[0], "remainder", ans[1])
