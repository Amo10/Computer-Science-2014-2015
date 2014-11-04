#Tamir
#Andrew

import turtle
import math
import random
def estimatepi(t, trials):
        t = turtle.Turtle()
        t.speed(-10)
        insidecounter = 0
        outsidecounter = 0
        for i in range(trials):
            randx = float(random.random())
            randy = float(random.random())
            x = 2*randx-1
            y = 2*randy-1
            t.up()
            t.setpos(x,y)
            if t.distance(0,0) < 1:
                t.dot(6, "white")
                insidecounter = insidecounter +1
            else:
                t.dot(6, "black")
                outsidecounter = outsidecounter +1
            pi = (insidecounter/(insidecounter+outsidecounter))*4
            print(i, pi)
def main():
    wn = turtle.Screen()
    wn.bgcolor("coral")
    wn.setworldcoordinates(-1,-1,1,1)
    estimatepi("hello", 2000)
    wn.exitonclick()
main()
