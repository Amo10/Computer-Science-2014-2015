# pascal.py Pascal's Triangle

def main():
    print("*** Pascal's Triangle ***")
    a, b = input("Enter row and column, separated by a comma.\n? ").split(',')
    print(pascal(int(a), int (b)))

def print_triangle(x):
    for r in range(x + 1):
        for c in range(r+1):
            print(pascal(r, c), end=" ")
        print()


def pascal(r, c):
    """Takes row and column and returns the number at that position."""
    if c == 0 or r == c:
        return 1
    else:
        return pascal(r - 1, c - 1) + pascal(r - 1, c)

if __name__ == "__main__":
    main()
