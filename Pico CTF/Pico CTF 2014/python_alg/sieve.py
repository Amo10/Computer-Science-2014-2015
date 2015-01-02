# sieve.py The Sieve of Eratosthenes

def main():
    print("*** Sieve of Eratosthenes ***")
    nums = [True] * (int(input("Numbers up to: ")) + 1)
    print("\nPrimes:")
    display(sieve(nums))

def sieve(my_list):
    """Takes the list and sieves the indexes.
    Composite index values marked "False"."""
    limit = int(len(my_list) ** 0.5) + 1 
    for i in range(2, limit):
        if my_list[i]:
            for j in range(i*i, len(my_list), i):
                my_list[j] = False
    return my_list

def display(some_list):
    """Takes the list and prints the indices of elements marked True.
    Prompts for user to press enter at intervals (for readability."""
    for (index, is_prime) in enumerate(some_list[2:], 2):
        if is_prime:
            print(index, end = " ")
        if index % 100 == 0:
            print()
        if index % 1000 == 0:
            input("Press enter.")

if __name__ == "__main__":
    main()
