# prime_factors.py Finds prime factors of an integer    

def main():
    display(factor(int(input("Number: "))))

def factor(n):
    """Takes an integer and returns a list of prime factors."""
    i = 2
    factors = []
    while n != 1:
        while n % i == 0:
            n = n // i
            factors.append(i)
        i += 1
    return factors

def display(some_list):
    """Takes a list of factors and prints to the screen."""
    print(some_list[0], end = "")
    if len(some_list) > 1:
        for j in some_list[1:]:
            print(" * " + str(j), end = "")
    else:
        print()
# main
if __name__ == "__main__":
    main()
