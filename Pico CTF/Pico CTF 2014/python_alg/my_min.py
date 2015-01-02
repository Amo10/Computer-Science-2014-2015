# my_min.py
# variable numbers of arguments.

def my_min(x, *args):
    """"Takes a list or a series of argument ans returns the minimum."""
    if type(x) != list:                     # if we are not dealing with a list ...
        m = x                                   # store x as the first potential minumum.
        my_args = []                        # make an empty list.
        for item in args:                   # add the other arguments (if any)
            my_args.append(item)    # to the list.
    else:
        my_args = x[1:]                # if we were passed a list,
        m = x[0]                            # split it into m and my_args.
    for n in my_args:                            # iterate over the list
        m = (m + n - abs(m - n)) / 2     # repeatedly finding the minimum.
    return m


