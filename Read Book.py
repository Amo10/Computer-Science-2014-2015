import string
def readbook(file):
    book = open(file,'r')
    my_list = []
    for line in book:
        line = line.strip()
        my_list.extend(line.split())
        for i in range(len(my_list)):
            my_list[i] = ''.join(x for x in my_list[i] if x in set(string.ascii_letters))
            my_list[i] = my_list[i].lower()
    book.close()
    return my_list

def getDistinctWords(file):
    book = open(file,'r')
    my_list = []
    for line in book:
        line = line.strip()
        my_list.extend(line.split())
        for i in range(len(my_list)):
            my_list[i] = ''.join(x for x in my_list[i] if x in set(string.ascii_letters))
            my_list[i] = my_list[i].lower()
    book.close()
    uniqueWords = [] 
    for i in my_list:
          if not i in uniqueWords:
                uniqueWords.append(i);
    return uniqueWords

def findlongest(file):
    book = open(file,'r')
    my_list = []
    for line in book:
        line = line.strip()
        my_list.extend(line.split())
        for i in range(len(my_list)):
            my_list[i] = ''.join(x for x in my_list[i] if x in set(string.ascii_letters))
            my_list[i] = my_list[i].lower()
    book.close()
    uniqueWords = [] 
    for i in my_list:
          if not i in uniqueWords:
                uniqueWords.append(i);
    
    longword_length = max(len(w) for w in uniqueWords)
    for i in uniqueWords:
        if len(i) == longword_length:
            return i

#print(readbook("hello.txt"))
print(getDistinctWords("hello.txt"))
#print(findlongest("hello.txt"))
