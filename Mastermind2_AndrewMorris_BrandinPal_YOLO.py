#Andrew Morris
#Brandin Pal
#Wallis Manning

from random import choice
name = input("Please enter your name: ")
restart = "y"
while restart =="y":
    counter = 0
    guessc = 0
    restart = "n"
    print("Welcome" ,name, "!" )
    while counter < 4:
        color = choice([1,2,3,4])
        got_a_number = False
        while got_a_number == False:
            try:
                colorg = int(input ("Please guess a number (1, 2, 3 or, 4)"))
                got_a_number = True
            except:
                print("Please enter a INT!!")
                got_a_number = False
                guessc += 2
        while colorg != color:
            guessc += 1
            print("Your guess is wrong!")
            got_a_number = False
            while got_a_number == False:
                try:
                    colorg = int(input ("Please guess a number (1, 2, 3 or, 4): "))
                    got_a_number = True
                except:
                    print("Please enter a INT!!")
                    got_a_number = False
                    guessc += 2
        if counter == 0:
            print("You guessed the first number!!! Woo")
            color1 = colorg
        elif counter == 1:
            print("You guessed the second number!!! Woo")
            color2 = colorg
        elif counter == 2:
            print("You guessed the thrid number!!! Woo")
            color3 = colorg
        else:
            print("You guessed the fourth number!!! Woo")
            color4 = colorg
            guessc += 4
        counter += 1
    print("You win")
    print("It took you" , guessc, "guesses!")
    print("The patern was", color1, color2, color3, color4)
    restart = input("restart y or n:")
exit()
