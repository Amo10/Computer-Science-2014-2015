import turtle

def square(t, sz):
    for i in range(4):
        t.forward(sz)
        t.left(90)

wn = turtle.Screen()       # Set up the window and its attributes
wn.bgcolor("lightgreen")

alex = turtle.Turtle()     # create alex
alex.color("blue")
alex.pensize(1)
alex.speed(0)
for i in range(20):
    square(alex, 100)
    alex.right(18)


wn.exitonclick()
