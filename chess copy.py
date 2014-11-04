import turtle
wn = turtle.Screen()
board = turtle.Turtle()
my_data = {}
foo = "hello"
def piece(name, x = 0, y =0, c="w", t="p"):
    x = (x-1)*length/8
    y = (-y+1)*length/8
    my_data[name] = turtle.Turtle()
    my_data[name].speed(0)
    my_data[name].right(90)
    my_data[name].width(10)
    my_data[name].up()
    my_data[name].shapesize(1.75, 1.75, 2)
    my_data[name].goto(x -length/2+length/16, y+length/2-length/16)
    if c == "w":
        my_data[name].color("black")
        my_data[name].fillcolor("white")
    else:
        my_data[name].color("white")
        my_data[name].fillcolor("black")
        my_data[name].right(180)
    if t == "q":
        my_data[name].shape("circle")
    elif t == "k":
        my_data[name].shape("square")
    elif t == "r":
        my_data[name].shape("turtle")
    elif t == "b":
        my_data[name].shape("triangle")
    elif t == "kn":
        my_data[name].shape("arrow")
            
board.speed(0)
length = 400
n = 8
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

for i in range(1,9):
    piece(("p",i,"w"), i, 2, "w")
    piece(("p",i,"b"), i, 7, "b")
x=1
for t in ["r", "kn", "b", "k", "q"]:
    piece((t, 1,"w"), x, 1, "w", t)
    piece((t, 1,"b"), x, 8, "b", t)
    x+=1
for t in ["b", "kn", "r"]:
    piece((t, 2,"w"), x, 1, "w", t)
    piece((t, 2,"b"), x, 8, "b", t)
    x+=1    
def move(s):
    t = input("Piece Type:")
    i = int(input("Piece Number:"))
    x = int(input("X Position:"))
    y = int(input("Y Position:"))
    my_data[t, i, s].goto((x-1)*length/8-length/2+length/16, (y-1)*length/8-length/2+length/16)
while i in range(10):
    w = True
    while w ==True:
        print("White move")
        move("w")
        w = False
    else:
        print("Black move")
        move("b")
        w = True
    
'''(0.00, 0.00)
(150.00, 0.00)
(43.93, -106.07)
(43.93, 43.93)
(150.0, -62.13)
(0.00, -62.13)
(106.07, 43.93)
(106.07, -106.07)
(0.00, 0.00)'''

