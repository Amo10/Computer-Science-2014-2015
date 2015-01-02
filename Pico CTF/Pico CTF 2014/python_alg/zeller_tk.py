# zeller_tk.py GUI version of Zeller's congruence.

def submit(*ignore):
    days = ["Sunday", "Monday", "Tuesday", "Wednesday",
            "Thursday", "Friday", "Saturday"]
    date = split_date(input_box.get())
    if len(date) != 3:
        display("Please try again!") 
    else:
        display(days[convert(date)])  

def display(msg):
    txt.delete(0.0, END)
    txt.insert(0.0, msg)

def split_date(date_string):
    try:
        date = date_string.split('/')
        for i in range(3):
            date[i] = int(date[i])
        return date
    except (IndexError, ValueError):
        return []

def convert(date):
    day = date[0]
    (century, year) = divmod(date[2], 100)
    month = ((date[1] - 3) % 12) + 1 
    if month == 11 or month == 12:
        year -= 1
    a = int(2.6 * month - 0.2)
    b = year // 4
    c = century // 4
    d = 2 * century
    day_name = day + a + year + b + c - d
    return day_name % 7
    
from tkinter import *
root = Tk()
root.title("Zeller's Congruence")
root.geometry("250x100")
app = Frame(root)
app.grid()
root.bind('<Return>', submit)

input_lbl = Label(app, text = "Date\n(dd/mm/yy)")
input_lbl.grid(row = 0, column = 0, pady = 5)

input_box = Entry(app, width = 10)
input_box.grid(row = 0, column = 1, pady = 5)

bttn = Button(app, text = "Day:")
bttn["command"] = submit
bttn.grid(row = 1, column = 0, pady = 5)

txt = Text(app, width = 20, height = 1)
txt.grid(row=1, column = 1, pady = 5)
    
root.mainloop()
