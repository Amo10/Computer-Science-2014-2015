#Andrew Morris
#Brandin Pal
##YOLO SWAG

from random import choice
name = input("Please enter your name: ")
restart = "y"
while restart =="y":
    counter = 0
    guessc = 0
    restart = "n"
    print("Welcome" ,name, "!" )
    while counter < 4:
        color = choice(["C","I","A","B"])
        colorg = input ("Please guess a colour (C, I, B or, A): ")
        while colorg != color:
            guessc += 1
            print("Your guess is wrong!")
            colorg = input ("Please guess another colour (C, I, B or, A): ")
        if colorg == "I":
            colorg = "Indigo"
        elif colorg == "C":
            colorg = "Cerulean"
        elif colorg == "B":
            colorg = "Blue"
        else:
            colorg = "Aqua"
        if counter == 0:
            print("You guessed the first colour!!! Woo")
            color1 = colorg
        elif counter == 1:
            print("You guessed the second colour!!! Woo")
            color2 = colorg
        elif counter == 2:
            print("You guessed the thrid colour!!! Woo")
            color3 = colorg
        else:
            print("You guessed the fourth colour!!! Woo")
            color4 = colorg
            guessc += 4
        counter += 1
    print("You win")
    print("It took you" , guessc, "guesses!")
    print("The patern was", color1, color2, color3, color4)
    restart = input("restart y or n:")
exit()
