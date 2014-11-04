import turtle
turtle = turtle.Turtle()
def striangle(depth,base):
   turtle.down()
   for i in 0,1,2:
         striangle(depth - 1,base)
         turtle.up()
         turtle.forward(base*2**depth)
         turtle.left(120)
         turtle.down()

turtle.reset()
striangle(6,5)
