def main():
    a = [4, 36]
    for i in range(2):
        for j in range(i,i+1):
            for k in range(1, j+2):
                for m in range(1, k+3):
                    a.append(2**m * 3**k * 5**j * 7**i)
                        
    a.sort()
    x = 2
    for n in a:
        d = divisors(n)
        #if d > x:
        print(pretty(n, d, factor(n)))
            #x = d


def factor(n):
    """Takes an integer and returns a dictionary of prime factors."""
    i = 2
    factors = {}
    while n != 1:
        while n % i == 0:
            n = n // i
            if i not in factors:
                factors[i] = 1
            else:
                factors[i] += 1
        i += 1
    return factors

def pretty(n, d, f):
    """Takes a dictionary and prints it out."""
    my_list = [str(n)+ ": " + str(d)+ " divisors \nPrime Factors: "]
    for x in iter(f):
        my_list.append(str(x) + '^' + str(f[x]))
    string = ""
    for item in my_list[1:-1]:
        string = string + item + " x "
    return my_list[0] + string + my_list[-1]

def divisors(x):
    """Takes a number and returns the number of divisors."""
    a = 0
    for i in range(1, x+1):
        if x % i == 0:
            a += 1
    return a

# main
if __name__ == "__main__":
    main()
