import turtle
wn = turtle.Screen()
biff = turtle.Turtle()
wn = turtle.Screen()
biff = turtle.Turtle()
side = 8
times = int(side/2)
for i in range(0,times):
    biff.forward(45)
    biff.right(180-135)
    biff.forward(45)
    biff.left(90)
    biff.forward(45)
    biff.right(180-135)
    biff.forward(45)
    biff.left(90)
wn.exitonclick()
