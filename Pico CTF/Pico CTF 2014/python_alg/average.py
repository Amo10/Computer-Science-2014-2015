# average.py accepts variable numbers of arguments or a list.

def average(x, *args):
    """"Takes a list or a series of arguments and returns the average."""
    if type(x) == list:
        total = sum(x)
        return total/len(x)             
    else:
        x += sum(args)
        return x / (len(args) +1)
