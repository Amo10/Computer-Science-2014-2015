#Playing with randoms
#Aidan Brooks

import turtle

filein = open('randomnumbers.txt','r')
numlist = []
numdict = {}
for line in filein:
    value = int(line.strip())
    numlist.append(value)
    if value in numdict:
        numdict[value] += 1
    else:
        numdict[value] = 1
filein.close()


def get_low(numlist):
    low = 10**1000
    for i in numlist:
        if i < low:
            low = i
    return low

def get_high(numlist):
    high = 0
    for i in numlist:
        if i > high:
            high = i
    return high



def get_median(numlist):
    clone = numlist[:]
    if len(clone)%2 == 0:
        for a in range((len(numlist)//2) -1):
            clo = get_high(numlist)+1
            chi = 0
            for i in clone:
                if i > chi:
                    chi = i
                if i < clo:
                    clo = i
            clone.remove(chi)
            clone.remove(clo)
        tot = 0
        for a in clone:
            tot = tot + a
        median = tot/2
    else:
        for a in range(int(len(numlist)//2)):
            clo = get_high(numlist)+1
            chi = 0
            for i in clone:
                if i > chi:
                    chi = i
                if i < clo:
                    clo = i
            clone.remove(chi)
            clone.remove(clo)
        tot = 0
        for a in clone:
            tot = tot + a
            median = tot
    return median



def get_mean(numlist):
    mean = 0
    for b in numlist:
        mean += b
    mean = mean/len(numlist)
    return mean


def get_mode(numlist,numdict):
    mode = 0
    for i in numdict:
        if numdict[i] > mode:
            mode = numdict[i]
    modelist = []
    for i in numdict:
        if numdict[i] == mode:
            modelist.append(i)
    return modelist

def get_sd(numlist):
    mean=get_mean(numlist)
    sigma2 = 0
    for x in numlist:
        sigma2 += (x-mean)**2
    sigma2 = sigma2/len(numlist)
    sigma = sigma2**(1/2)
    return sigma

def get_percentile_numlist(numlist):
    per=int(input("What percentile (non decimal) would you like to get?:"))
    clone=numlist[:]
    if len(numlist)%2 != 0:
        for i in range(int((len(clone)*(per/100))-1)):
            clone.remove(get_low(clone))
            
        ret=get_low(clone)
    else:
        for i in range(int((len(clone)*(per/100))-1)):
            clone.remove(get_low(clone))
        ret1=float(get_low(clone))
        clone.remove(get_low(clone))
        ret2=float(get_low(clone))
        ret = float((ret1+ret2)/2)
    print("The lowest number in the",per,"th percentile is:")
    return ret

def get_percentile_percent(numlist, per):
    clone=numlist[:]
    if len(numlist)%2 != 0:
        for i in range(int((len(clone)*(per/100))-1)):
            clone.remove(get_low(clone))
            
        ret=get_low(clone)
    else:
        for i in range(int((len(clone)*(per/100))-1)):
            clone.remove(get_low(clone))
        ret1=float(get_low(clone))
        clone.remove(get_low(clone))
        ret2=float(get_low(clone))
        ret = float((ret1+ret2)/2)
    return ret
            
                   
    

def main(numlist,numdict):
    print("The lowest umber is:", get_low(numlist))
    print("The highest number is:",get_high(numlist))
    print("The median is:",get_median(numlist))
    print("The mode is:",get_mode(numlist,numdict))
    print("The standard deviation is:",get_sd(numlist))
    print("The mean is:",get_mean(numlist))
    print(get_percentile_numlist(numlist))

    

'''inside1sd = 0
for x in numlist:
    if x>mean-sigma and x < mean+sigma:
        inside1sd += 1
print(inside1sd,"%")

inside2sd = 0
for x in numlist:
    if x>mean-2*sigma and x < mean+2*sigma:
        inside2sd += 1
print(inside2sd,"%")
'''

def get_non_outlier(numlist,outies):
    clone=numlist[:]
    non_outliers = []
    for i in clone:
        if not i in outies:
            non_outliers.append(i)
    return non_outliers

def get_outlier(numlist):
    clone=numlist[:]
    outliers = []
    for i in clone:
        if i > (1.5*(get_percentile_percent(numlist,75)-get_percentile_percent(numlist,25))+get_percentile_percent(numlist,75)) or i < (get_percentile_percent(numlist,25)-(1.5*(get_percentile_percent(numlist,75)-get_percentile_percent(numlist,25)))):
            outliers.append(i)
    return outliers

def get_low_non_outlier(non_outies):
    low = 100
    for i in non_outies:
        if i < low:
            low = i
    return low

def get_high_non_outlier(non_outies):
    high = 0
    for i in non_outies:
        if i > high:
            high = i
    return high

if __name__=='__main__':
    main(numlist,numdict)

    outies=get_outlier(numlist)
    print(outies)
    non_outies=get_non_outlier(numlist,outies)
    print(non_outies)

    robin = turtle.Turtle()
    wn = turtle.Screen()
    robin.ht()
    robin.speed(0)
    robin.up()
    robin.forward(3*get_low_non_outlier(non_outies))
    print((3*get_low_non_outlier(non_outies)))
    robin.down()
    robin.right(90)
    robin.forward(20)
    robin.forward(-40)
    robin.forward(20)
    robin.left(90)
    robin.forward((3*get_high_non_outlier(non_outies))-(3*get_low_non_outlier(non_outies)))
    robin.right(90)
    robin.forward(20)
    robin.forward(-40)
    robin.forward(20)
    robin.left(90)
    robin.forward(-((3*get_high_non_outlier(non_outies))-(3*get_low_non_outlier(non_outies))))
    robin.forward((3*get_percentile_percent(non_outies, 75))-(3*get_low_non_outlier(non_outies)))
    robin.left(90)
    robin.forward(60)
    robin.forward(-120)
    robin.forward(60)
    robin.right(90)
    robin.forward(-((3*get_percentile_percent(non_outies, 75))-(3*get_low_non_outlier(non_outies))))
    robin.color('blue')
    robin.begin_fill()
    robin.forward((3*get_median(non_outies))-(3*get_low_non_outlier(non_outies)))
    robin.left(90)
    robin.forward(60)
    robin.color('black')
    robin.write(get_median(non_outies))
    robin.color('blue')
    robin.right(90)
    robin.forward((3*get_percentile_percent(non_outies,75))-(3*get_median(non_outies)))
    robin.color('black')
    robin.write(get_percentile_percent(non_outies, 75))
    robin.color('blue')
    robin.right(90)
    robin.forward(120)
    robin.right(90)
    robin.forward((3*get_percentile_percent(non_outies,75))-(3*get_median(non_outies)))
    robin.right(90)
    robin.forward(60)
    robin.right(90)
    robin.end_fill()
    robin.color('black')
    robin.forward(-((3*get_median(non_outies))-(3*get_low_non_outlier(non_outies))))
    robin.forward((3*get_percentile_percent(non_outies, 25))-(3*get_low_non_outlier(non_outies)))
    robin.color('red')
    robin.begin_fill()
    robin.left(90)
    robin.forward(60)
    robin.color('black')
    robin.write(get_percentile_percent(non_outies,25))
    robin.color('red')
    robin.right(90)
    robin.forward((3*get_median(non_outies))-(3*get_percentile_percent(non_outies,25)))
    robin.right(90)
    robin.forward(120)
    robin.right(90)
    robin.forward((3*get_median(non_outies))-(3*get_percentile_percent(non_outies,25)))
    robin.right(90)
    robin.forward(60)
    robin.end_fill()
    robin.color('black')
    robin.right(90)
    robin.forward(-((3*get_percentile_percent(non_outies, 25))-(3*get_low_non_outlier(non_outies))))
    robin.up()
    robin.forward(-(3*get_low_non_outlier(non_outies)))
    for i in outies:
        robin.up()
        robin.forward(3*i)
        robin.dot(3)
        robin.write(i)
        robin.forward(-(3*i))
        robin.down()

    robin.up()
    robin.right(90)
    robin.forward(100)
    robin.left(90)
    robin.left(90)
    robin.forward(10)
    robin.forward(-10)
    robin.right(90)
    for i in range(3*((get_high(numlist)//30)+1)-1):
        robin.down()
        robin.left(90)
        robin.forward(10)
        robin.write(int(10*(i)))
        robin.forward(-10)
        robin.right(90)
        robin.up()
        robin.forward(30)
    robin.left(180)
    robin.forward(30)
    robin.down()
    robin.forward(30*(3*((get_high(numlist)//30)+1)-2))

