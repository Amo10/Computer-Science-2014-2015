import turtle               # allows us to use the turtles library
import math
wn = turtle.Screen()        # creates a graphics window
alex = turtle.Turtle()      # create a turtle named alex
for x in range(180):
     y = 10*math.sin(x)
     alex.goto(x,y)
wn.exitonclick
