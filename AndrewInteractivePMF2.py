import turtle

def square(t, sz):
    t.down()
    for i in range(4):
        t.forward(sz)
        t.left(90)
    t.up()
    t.backward(10)
    t.right(90)
    t.forward(10)
    t.left(90)

wn = turtle.Screen()       # Set up the window and its attributes
wn.bgcolor("lightgreen")

alex = turtle.Turtle()     # create alex
alex.color('hotpink')
alex.speed(0)
alex.pensize(3)
for i in range(1,6):
    square(alex, i*20)


wn.exitonclick()

