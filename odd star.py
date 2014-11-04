import turtle
tom = turtle.Turtle()
wn = turtle.Screen()
def odd_star(n, length=100,color="red"):
    tom.color(color)
    tom.begin_fill()
    for i in range(n):
        tom.forward(length)
        tom.left(180-180/n)
    tom.end_fill()
odd_star(131,300)
