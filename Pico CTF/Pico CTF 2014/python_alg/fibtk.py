# fibtk.py
# a GUI version of the Fibonacci program, using recursion.

def start_fib():
    num = input_box.get()
    txt.delete(0.0, END)
    try:
        num = int(num)
    except:
        txt.insert(0.0, "I need an integer.")
    txt.insert(0.0, str(fibonacci(num)))

def fibonacci(num):
    if num <2:
        return num
    else:
        num = fibonacci(num-1) + fibonacci(num-2)
        return num

from tkinter import *
root = Tk()
root.title("Fibonacci")
root.geometry("300x100")
app = Frame(root)
app.grid()

input_lbl = Label(app, text = "Enter a number: ")
input_lbl.grid(row = 0, column = 0, pady = 5)

input_box = Entry(app, width = 10)
input_box.grid(row = 0, column = 1, pady = 5)

bttn = Button(app, text = "go!")
bttn["command"] = start_fib
bttn.grid(row = 1, column = 0, pady = 5)

txt = Text(app, width = 15, height = 2)
txt.grid(row=1, column = 1, pady = 5)
    
root.mainloop()
    
