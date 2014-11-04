import turtle

wn = turtle.Screen()
def drawSprite(t, length = 120, n=15):
    t = turtle.Turtle()
    t.shape("triangle")
    angle = 360 / n

    for i in range(n):
        t.right(angle)
        t.forward(length)
        t.stamp()
        t.right(180)
        t.forward(length)
        t.right(180)
    t.shape("circle")
    wn.exitonclick()
drawSprite("turt")
"""
import turtle

def drawSprite(t, length = 120, nl=15):
    t.right(90)
    t.forward(length)
    t.left(180)
    t.forward(length)
    for i in range((nl-1)):
        t.right(90)
        t.forward(int(length/(nl-2)))
        t.right(90)
        t.forward(length)
        t.left(180)
        t.forward(length)
    for i in range(3):
        t.forward((nl-1)*int(length/(nl-2)))
        t.left(90)

wn = turtle.Screen()       # Set up the window and its attributes
wn.bgcolor("lightgreen")

alex = turtle.Turtle()     # create alex
alex.color("blue")
alex.pensize(1)
alex.speed(0)
drawSprite(alex)


wn.exitonclick()"""

