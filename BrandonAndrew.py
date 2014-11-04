#Brandon
#Andrew
from random import randint
answer = randint (1, 10)
guess = 0
counter = 0
while guess != answer:
    g = input("Guess a number 1-10: ")
    guess = int(g)
    counter = counter + 1
    if guess == answer:
        print("You win!")
        print("You made ", counter, " guesses.")
    elif guess > answer:
        print("Too high. Try again!")
    else:
        print("Too low. Try again!")              
print("Game Over!")


    
