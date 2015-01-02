# prime number generator - uses prime divisors

# import math so we can use ceil and sqrt
from math import *

def get_divisors(divisors, upper_limit, start):
    i = 0
    while divisors[len(divisors) - 1] < upper_limit:
        if divisors[i] * divisors[i] > start:
            divisors.append(start)
            start += 2
            i = 0
        if start % divisors[i] == 0:
            start += 2
            i = 0
        else:
            i += 1

def get_primes(divisors, target, user_num, start):
    i = 0
    while len(target) < user_num:
        temp = ceil(sqrt(start))
        if temp > divisors[len(divisors) - 1]:
            print("Need more divisors.")
            # increase the range of divisors
            get_divisors(divisors, ceil(ceil(temp) * 1.5), divisors[len(divisors) -1] + 1)   
        if divisors[i] * divisors[i] > start:
            target.append(start)
            start += 2
            i = 0
        if start % divisors[i] == 0:
            start += 2
            i = 0
        else:
            i += 1

n_primes = int(input("How many primes: "))
start_n = int(input("Start number: "))

# set up a couple of lists.
p_divs = [3]
p_nums = []

# add 2 to the list if we are starting low
if start_n < 2:
    start_n = 3
    p_nums.append(2)

# skip the start num if it is even
if start_n % 2 == 0:
    start_n += 1

div_limit = ceil(sqrt(start_n))
if div_limit < 10:
    div_limit = 10

# get some prime divisors
get_divisors(p_divs, div_limit, 5)
# print(p_divs)

get_primes(p_divs, p_nums, n_primes, start_n)
print(p_nums)
