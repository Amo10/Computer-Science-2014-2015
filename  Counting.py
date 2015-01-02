startint = input("Input Starting Int:")
endint = input("Input Ending Int:")
numlist = {}
i = int(startint)
lessi = True
while lessi == True:
    if i < int(endint):
        numlist[i] = list(str(i))
        i = i + 1
    else:
        lessi = False
for i in numlist:
   number = True
   for z in range(len(numlist[i])-1):
      if (int(numlist[i][z])+1) == (int(numlist[i][z+1])) or (int(numlist[i][z])-1) == (int(numlist[i][z+1])):
          pass
      else:
         number = False
   if number == True:
       print(numlist[i])
