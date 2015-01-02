from Random_Number_List2 import *

from termcolors import cprint , colored
#from numpys import percentile

import statistics
def main():
    cprint("     Standard Deviation: FAIL", 'red')
    '''test_file("rand10002.txt")
    test_file("rand1000.txt")
    test_file("rand10000.txt")
    test_file("Randomnumbers.txt")
    test_file("randomnumbers copy.txt")'''

def test_file(text):
    print ("\n          ",text,'\n')
    randnum = readlist(text)
    standard_d_check(randnum)
    mode_check(randnum)
    median_check(randnum)
    high_check(randnum)
    low_check(randnum)
    mean_check(randnum)
    percentile_check(randnum,25)
    percentile_check(randnum,75)

    

def standard_d_check(randnum):
    if abs(standard_d(randnum)-statistics.pstdev(randnum)) < .0000000000001:
        cprint("     Standard Deviation: PASS", 'green')
    else:
        cprint("     Standard Deviation: FAIL", 'red')
        print ("          It should be:",statistics.pstdev(randnum), "\n          But it was:",standard_d(randnum))

def mode_check(randnum):
    if get_mode(randnum) == statistics.mode(randnum):
        cprint("     Mode: PASS", 'green')
    else:
        cprint ("     Mode: FAIL", 'red')
        
def percentile_check(randnum,i):
    if get_percentile(randnum,i) == percentile(randnum,i):
        cprint(("     Percentile",i,": PASS"), 'green')
    else:
        cprint (("     Percentile",i,": FAIL"), 'red')

def median_check(randnum):
    if get_median(randnum) == statistics.median(randnum):
        cprint("     Median: PASS", 'green')
    else:
        cprint("     Median: FAIL", 'red')

def high_check(randnum):
    if get_high(randnum) == max(randnum):
        cprint("     Max: PASS", 'green')
    else:
        cprint("     Max: FAIL", 'red')

def low_check(randnum):
    if get_low(randnum) == min(randnum):
        cprint("     Min: PASS", 'green')
    else:
        cprint("     Min: FAIL", 'red')

def mean_check(randnum):
    if get_mean(randnum) == statistics.mean(randnum):
        cprint("     Mean: PASS", 'green')
    else:
        cprint("     Mean: FAIL", 'red')


if __name__ == "__main__":
	main()
