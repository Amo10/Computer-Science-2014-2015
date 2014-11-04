from turtle import *
from random import random, randint
from time import sleep

MAXLEN = 30
MAXWID = 25

def randomcolor():
    return random(), random(), random()

def pause(x,y):
    global running
    running = not running
    if running:
        title("RUNNING... - CLICK TO HALT")
    else:
        title("HALTED... - CLICK TO CONTINUE")
       
def squares(x,y):
    clear()
    title("RUNNING... - CLICK TO HALT")
    onscreenclick(pause)
    for cycle in range(randint(3, 5)):
        bgcolor(randomcolor())
        for rect in range(randint(5,10)):
            shapesize(3 + random()*MAXLEN, 3 + random()*MAXWID,
                       randint(3, 10))
            color(randomcolor(), randomcolor())
            stamp()
            update()
            sleep(1)
            update()
            while not running:   # now pausing
                sleep(0.5)
                update()
        sleep(1)
        clearstamps()
    bgcolor("white")
    pencolor("black")
    write("Click to exit!", align="center", font=("Arial", 24, "bold"))
    title("")
    exitonclick()
   
   
reset()
title("Python turtle graphics: random rectangle generator")
hideturtle()
resizemode("user")
shape("square")
running = True
onscreenclick(squares)
listen()
write("Click me!", align="center", font=("Arial", 24, "bold"))
mainloop()
