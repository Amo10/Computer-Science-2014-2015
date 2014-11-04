import turtle

#--------This function draws a square, starting from the top, left corner and
#--------moving clockwise
def draw_square(length=25):
    for i in range(4):
        alex.forward(length)
        alex.right(90)
#--------------------------------------------------------

#--------This function should draw n squares in a row across the screen
def draw_row(n,length=25):
    for i in range(n):
        draw_square(length)
        alex.forward(length)


#--------------------------------------------------------
#--------This function should move your turtle from the end of one row to the
#--------start of the next row
def move_to_next_row(length,row):
    alex.right(90)
    alex.forward(length)
    alex.right(90)
    alex.forward(length*row)
    alex.right(180)


#--------------------------------------------------------
wn = turtle.Screen()
wn.bgcolor("gray")

#--------Ask for the size height and width of the screen.  Assign these values to the
#--------variables height and width
#--------Make sure your variables have the correct type!

height = int(float(input("input height:")))
width = int(float(input("input width:")))

#--------This line will make the Turtle Window the correct size.

wn.screensize(width,height)
wn.setup(width*1.15,height*1.15)
#--------Ask for the sidelength for a square and the number of of rows and columns
#--------of squares that should be drawn.  Assign these values to the variables
#--------length,row,col
correct = False
while correct == False:
    try:
        length = int(input("enter a side length:"))
        correct = True
    except:
        print("enter an int!")
        correct = False
correct = False
while correct == False:
    try:
        row = int(input("enter a row length:"))
        correct = True
    except:
        print("enter an int!")
        correct = False
correct = False
while correct == False:
    try:
        col = int(input("enter a col length:"))
        correct = True
    except:
        print("enter an int!")
        correct = False

alex = turtle.Turtle()
alex.color("blue")
alex.pensize(5)
alex.speed(0)

#--------Move your turtle to the upper left corner of the screen
alex.up()
alex.setpos(-(width*1.1)/2, ((height*1.1)/2))
alex.down()
#---------------------------------------------------------
#draw_row(10)
#row = 10
#col = 10
#length = 25
for i in range(row):
    draw_row(col,length)
    move_to_next_row(length,row)


wn.exitonclick()
