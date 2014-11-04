#Andrew

import math
import random
def estimatepi(trials, times):
    insidecounter = 0
    outsidecounter = 0
    for g in range(1):
            for i in range(1000000000):
                    randx = float(random.random())
                    randy = float(random.random())
                    x = 2*randx-1
                    y = 2*randy-1
                    if math.sqrt(x**2+y**2)<= 1:
                            insidecounter = insidecounter +1
                    else:
                            outsidecounter = outsidecounter +1
                    pi = (insidecounter/(insidecounter+outsidecounter))*4
            print(g,"%", pi)
            a_pi = pi
    for h in range(times - 1):
        insidecounter = 0
        outsidecounter = 0
        for g in range(1):
            for i in range(1000000000):
                randx = float(random.random())
                randy = float(random.random())
                x = 2*randx-1
                y = 2*randy-1
                if math.sqrt(x**2+y**2)<= 1:
                    insidecounter = insidecounter +1
                else:
                    outsidecounter = outsidecounter +1
                pi = (insidecounter/(insidecounter+outsidecounter))*4
            print(g,"%", pi)
        a_pi = (a_pi+pi)/2
        print("WOOOOO",g,a_pi)
def main():
    estimatepi(100000,10)
main()
