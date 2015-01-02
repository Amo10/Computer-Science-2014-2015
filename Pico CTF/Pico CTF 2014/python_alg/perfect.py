# perfect.py - looks for perfect and friendly numbers

def main():
    while 1:
        print("""*** Friendly and Perfect Numbers ***
    1. Friendly
    2. Perfect
    0. Quit""")
        choice = int(input("? "))
        if not choice:
            return
        elif choice == 1:
            friendly()
        elif choice == 2:
            perfect()
        else:
            print("Oops.")

def perfect():
    """Prints Perfect Numbers and, optionally, their proper divisors."""
    ans = input("Show divisors (y/n)? ")  # it's a lot slower if you do!
    mersenne = [2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607,
                1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213,
                19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091,
                756839, 859433, 1257787, 1398269, 2976221, 3021377, 6972593,
                13466917, 20996011, 24036583, 25964951]
    for p in mersenne:
        a = euler(p)
        print(a)
        if ans == 'y':
            print(proper(a))
        if 'n' == input("More? "):
            return          

def euler(p):
    """Uses Euler's formula and the Mersenne Primes to get a Perfect Number."""
    return 2 ** (p-1) * (2 ** p -1)
       
def friendly():
    """Prints pairs of friendly numbers."""
    a = 1
    while 1:
        a += 1
        div_sum = sum(proper(a))
        if a < div_sum and a == sum(proper(div_sum)):
            print(a, div_sum)
            if 'n' == input("More? "):
                return       

def proper(n):
    """Returns a list of the proper divisors of n."""
    my_list = [1]
    for i in range(2, n // 2 + 1):
        if n % i == 0:
            my_list.append(i)
    return my_list

if __name__ == "__main__":
    main()
