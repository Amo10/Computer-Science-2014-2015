#Andrew Morris
from string import ascii_letters
import urllib.request

def readbook(file):
    ## Open the file and add every word to a list that will be returned
    book = open(file,'r')
    my_list = []
    for line in book:
        line=line.strip()
        my_list.extend(line.split())

    book.close()
    return my_list

def getWords(file):
    ## Open the file and add every word to a list that will be returned
    ## All punctuation should be removed from the words before being added to the list
    ## All the words should be in lowercase only
    book = open(file,'r')
    my_list = []
    for line in book:
        line=line.strip()
        for word in line.split():
            clean_word = ''
            for i in word:
                if i in ascii_letters:
                    clean_word = clean_word + i.lower()
            my_list.append(clean_word)        

    book.close()
    return my_list

def getDistinctWords(file):
    ## Like getWords, but every word should appear at most once in the list
    book = open(file,'r')
    my_list = []
    for line in book:
        line=line.strip()
        for word in line.split():
            clean_word = ''
            for i in word:
                if i in ascii_letters:
                    clean_word = clean_word + i.lower()
            if not clean_word in my_list:
                my_list.append(clean_word)
                
    book.close()
    return my_list
    pass

def findLongest(my_list):
    ## Find the longest word in a list and return it
    ## This returns the first word found with the longest length
    longLength = 0
    longWord = ''
    print(max(my_list))
    for word in my_list:
        if len(word) > longLength:
            longWord = word
            longLength = len(word)
    return longWord

def findMostFrequent(file,words,number):
    count = []
    for x in words:
        count.append([file.count(x),x])
    count.sort(reverse=True)
    return [word[1] for word in count[:number]]

def five_letter_count(words):
    count = 0
    for x in words:
        if len(x) == 5:
            count = count + 1
    return count

def main():
    words1 = readbook('ParadiseLostBook1.txt')
    print(len(words1))
    print(words1[:13])
    words2 = getWords('ParadiseLostBook1.txt')
    print(len(words2))
    print(words2[:13])
    words3 = getDistinctWords('ParadiseLostBook1.txt')
    print(len(words3))
    print(words3[:13])
    longest = findLongest(words3)
    print("Most frequent word:",findMostFrequent(words2,words3,1))
    ### How many different 5 letter words are used?
    number5words = five_letter_count(words3)
    print("Number of different 5 letter words are used:",number5words)
    ### How many times are words of the length 5 used?
    number5 = five_letter_count(words2)
    print("Number of times times are words of the length 5 used:",number5)
    ### What are the 10 most frequently used words in Paradise Lost?
    print("10 most frequently used words:",findMostFrequent(words2,words3,10))

        
if __name__ == '__main__':
    main()
