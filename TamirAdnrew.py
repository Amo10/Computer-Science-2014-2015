#Andrew
#Tamir

import turtle
wn = turtle.Screen()
biff = turtle.Turtle()
side = 3
for i in range(0,side):
    biff.forward(100)
    biff.left(360/side)
wn.exitonclick()
wn = turtle.Screen()
biff = turtle.Turtle()
side = 4
for i in range(0,side):
    biff.forward(100)
    biff.left(360/side)
wn.exitonclick()
wn = turtle.Screen()
biff = turtle.Turtle()
side = 5
for i in range(0,side):
    biff.forward(100)
    biff.left(180-(360/(side*2)))
wn.exitonclick()
wn = turtle.Screen()
biff = turtle.Turtle()
side = 6
times = int(side/2)
for i in range(0,times):
    biff.forward(100)
    biff.left(180-360/side)
    biff.forward(100)
    biff.right(360/side)
    biff.forward(100)
    biff.left(180-360/side)
    biff.forward(100)
    biff.right(360/side)
wn.exitonclick()
wn = turtle.Screen()
biff = turtle.Turtle()
side = 7
for i in range(0,side):
    biff.forward(220)
    biff.left(180-(360/(side*2)))
wn.exitonclick()
wn = turtle.Screen()
biff = turtle.Turtle()
side = 8
times = int(side/2)
for i in range(0,side):
    biff.forward(45)
    biff.right(180-135)
    biff.forward(45)
    biff.left(90)
 
wn.exitonclick()
wn = turtle.Screen()
biff = turtle.Turtle()
side = 9
for i in range(0,side):
    biff.forward(220)
    biff.left(180-(360/(side*2)))
wn.exitonclick()
