import turtle
wn = turtle.Screen()
board = turtle.Turtle()
my_data = {}
foo = "hello"
def peice(name, x = 0, y =0):
    x = x*length/8
    y = -y*length/8
    my_data[name] = turtle.Turtle()
    my_data[name].right(90)
    my_data[name].color("red")
    my_data[name].width(10)
    my_data[name].up()
    my_data[name].goto(x -length/2+length/16, y+length/2-length/16)
board.speed(0)
length = 400
n = 8
peice("p1w", 1, 3)
board.up()
board.back(length/2)
board.right(-90)
board.forward(length/2)
board.right(90)
board.down()
x = int(n/2)
board.begin_fill()
for i in range(x):
    board.forward(length)
    board.right(90)
    board.forward(length/n)
    board.right(90)
    board.forward(length)
    board.right(-90)
    board.forward(length/n)
    board.right(-90)
#board.forward(length/n)
#board.right(-90)
for i in range(x):
    board.forward(length/n)
    board.right(-90)
    board.forward(length)
    board.right(90)
    board.forward(length/n)
    board.right(90)
    board.forward(length)
    board.right(-90)
board.right(180)
board.forward(length)
board.right(90)
board.forward(length)
    
board.end_fill()
'''(0.00, 0.00)
(150.00, 0.00)
(43.93, -106.07)
(43.93, 43.93)
(150.0, -62.13)
(0.00, -62.13)
(106.07, 43.93)
(106.07, -106.07)
(0.00, 0.00)'''

