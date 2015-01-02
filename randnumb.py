def main():
	randnum = readlist('randomnumbers.txt')
	print(sorted(randnum))
	print(median(randnum))
	
def readlist(file):
	read = open(file,'r')
	numbers = []
	for line in read:
		numbers.append(int(line.strip()))
	return numbers
	
def median(randnum):
	if len(randnum)%2 == True:
		for a in range(int(len(randnum)/2)):
			ahigh = 0
			alow = 100
			for num in randnum:
				if num > ahigh:
					ahigh = num
				if num < alow:
					alow = num
			randnum.remove(ahigh)
			randnum.remove(alow)
		avg = 0
		print(randnum)
		for i in randnum:
			avg += i
		return avg
	else:
		for a in range(int(len(randnum)/2-1)):
			ahigh = 0
			alow = 100
			for num in randnum:
				if num > ahigh:
					ahigh = num
				if num < alow:
					alow = num
			randnum.remove(ahigh)
			randnum.remove(alow)
		avg = 0 
		print(randnum)
		for i in randnum:
			avg += i
		avg = avg/2
		return avg
			

	
if __name__ == "__main__":
	main()
