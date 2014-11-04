from random import randint

while True:
    # main program
    while True:
        continue
        answer = input("Run again? (y/n): ")
        if answer in ("y", "n"):
            if answer in ('y'):
                #continue
                counter = 0
                secret = randint(1,10)
                print ("Welcome")
                guess = 0
                while guess != secret:
                    g = input("Guess the number:")
                    counter += 1
                    try:
                        guess = int(g)
                    except ValueError:
                       print("That's not an int!")
                       continue
                    if guess == secret:
                        print("You win!")
                        print("You made ", counter, " guesses.")
                    elif guess > secret:
                        print("Too high!")
                    else:
                        print("Too low")
                print("Game Over")
            else:
                print ("Goodbye")
                exit()
        else:
            print("Invalid input.")
    
        
