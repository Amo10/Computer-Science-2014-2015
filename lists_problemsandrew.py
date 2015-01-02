#Andrew Morris
def readfile(filename):
    words = []
    file = open(filename,'r')
    for i in file:
        words.append(i.strip())

    return words

def count_of_length(x,wordlist):
    counter = 0 
    for i in wordlist:
        if len(i) == x:
            counter = counter +1
    """This function takes an integer, x, and a list of words, wordlist.
    It returns the number of words in wordlist that are exactly x characters long."""
    return counter

def longest_word(wordlist):
    """This function takes a list of words, wordlist, and returns the longest word.
    If multiple words have the same longest length, it returns the first word in the
    list with that length.  It does not return the length of the word!
    """
    longword_length = max(len(w) for w in wordlist)
    for i in wordlist:
        if len(i) == longword_length:
            return i

def main():
    my_list = readfile('practicewords.txt')
    print('We have loaded',len(my_list),'words into memory.')
    length = int(input('What word length are you interested in? '))
    print('There are',count_of_length(length, my_list),'words of length',length)
    print('The largest word in your list is',longest_word(my_list))

    #Write code to ask for a word length.  Go through my_list and for every item that
    #has that length, reverse the word.  You should write a function that will reverse
    #a word.
    def reverse_word(position):
        reversed_word = my_list[position][-1::-1]
        return reversed_word
    reversed_words = []
    word_length = int(input('What word length are you interested in reversing? '))
    for i in range(len(my_list)):
        if len(my_list[i]) == word_length:
            reversed_words.append(reverse_word(i))
    print("reversed words:",reversed_words)

    #Write code that asks the user to type a complete sentence.  This sentence will be
    #stored in the variable sentence.  Use the split method to make a list of the words.
    #Use your list to print every other word from the sentence.
    sentence = input("Enter a sentence: ")
    everyother = sentence.split()
    print(everyother[0::2])

main()
