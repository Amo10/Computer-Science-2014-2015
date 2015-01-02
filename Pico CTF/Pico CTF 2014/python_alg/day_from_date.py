# day_from_date.py
# Uses Christian Zeller's congruence as given in Arthur Engel's
# "Elementary Mathematics from an Algorithmic Standpoint."

def main():
    days = ["Sunday", "Monday", "Tuesday", "Wednesday",
            "Thursday", "Friday", "Saturday"]
    print("*** Day of Week ***")
    again = 'y'
    while again !='n':
        date = split_date(get_date())
        while len(date) != 3:
            print("Please try again.")
            split_date(get_date())  
        print(days[convert(date)])
        again = input("Again? ")

def get_date():
    """Simple input function. Returns a string."""
    date_string = input("Date (dd/mm/yyyy): ")
    return date_string

def split_date(date_string):
    """Takes a string and tries to make it into a list.
        Returns an empty list if the data is entered incorrectly."""
    try:
        date = date_string.split('/')
        for i in range(3):
            date[i] = int(date[i])
        return date
    except (IndexError, ValueError):
        return []

def convert(date):
    """Takes the date as a list and computes the day of the week."""
    day = date[0]
    (century, year) = divmod(date[2], 100)
    # in the formula, March is month 1
    month = ((date[1] - 3) % 12) + 1 
    # January and February are therefore in the previous year!
    if month == 11 or month == 12:
        year -= 1
    a = int(2.6 * month - 0.2)
    b = year // 4
    c = century // 4
    d = 2 * century
    return (day + a + year + b + c - d) % 7

# main part of program
main()
