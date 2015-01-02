# Problem Set 4
# Name: 
# Collaborators: 
# Time: 

#
# Problem 1
#
from playing_with_randoms_Aidan import *
from random import gauss
from random import gammavariate

def getRandomReturnRate():
    """
    This function generates and returns a random rate of return for
    your retirement fund.  The rate will be given with two digits after
    the decimal point (i.e.  4.56 for 4.56%)
    The average rate will be near 11.5 (the historical average for the S&P 500)
    The standard deviation will also be near the historical standard deviation for the S&P 500
    """
    x = gauss(11.5,20)
    y = 2.0*gammavariate(1,2.0)
    ans = x/(y/2)**(1/2)
    while ans > 50 or ans < -50:
        x = gauss(11.5,20)
        y = 2.0*gammavariate(1,2.0)
        ans = x/(y/2)**(1/2)

    return round(x,2)

def nestEggFixed(salary, save, growthRate, years):
    initial_funds = float(salary)*save*.01
    retirement_funds = []
    retirement_funds.append(initial_funds)
    temp_fund = initial_funds
    for i in range(int(years)-1): 
        temp_fund=temp_fund*(1+(growthRate*.01))+initial_funds
        retirement_funds.append(temp_fund)
    return retirement_funds

    """
    - salary: the amount of money you make each year.
    - save: the percent of your salary to save in the investment account each
      year (an integer between 0 and 100).
    - growthRate: the annual percent increase in your investment account (an
      integer between 0 and 100).
    - years: the number of years to work.
    - return: a list whose values are the size of your retirement account at
      the end of each year.
    """
    # TODO: Your code here.

def testNestEggFixed():
    salary     = 10000
    save       = 10
    growthRate = 15
    years      = 5
    savingsRecord = nestEggFixed(salary, save, growthRate, years)
    print(savingsRecord)
    # Output should have values close to:
    # [1000.0, 2150.0, 3472.5, 4993.375, 6742.3812499999995]

    # TODO: Add more test cases here.

#
# Problem 2
#

def nestEggVariable(salary, save, growthRates):
    # TODO: Your code here.
    initial_funds = float(salary)*save*.01
    retirement_funds = []
    retirement_funds.append(initial_funds)
    temp_fund = initial_funds
    for i in range(len(growthRates)-1): 
        temp_fund=temp_fund*(1+(growthRates[i+1]*.01))+initial_funds
        retirement_funds.append(temp_fund)
    return retirement_funds
    """
    - salary: the amount of money you make each year.
    - save: the percent of your salary to save in the investment account each
      year (an integer between 0 and 100).
    - growthRate: a list of the annual percent increases in your investment
      account (integers between 0 and 100).
    - return: a list of your retirement account value at the end of each year.
    """

def testNestEggVariable():
    salary      = 10000
    save        = 10
    growthRates = [3, 4, 5, 0, 3]
    savingsRecord = nestEggVariable(salary, save, growthRates)
    print(savingsRecord)
    # Output should have values close to:
    # [1000.0, 2040.0, 3142.0, 4142.0, 5266.2600000000002]

    # TODO: Add more test cases here.

#
# Problem 3
#



def nestEggRandom(salary, save, years):
    # TODO: Your code here.
    initial_funds = float(salary)*save*.01
    retirement_funds = []
    retirement_funds.append(initial_funds)
    temp_fund = initial_funds
    for i in range(int(years)-1): 
        temp_fund=temp_fund*(1+(getRandomReturnRate()*.01))+initial_funds
        retirement_funds.append(temp_fund)
    return retirement_funds
    """
    - salary: the amount of money you make each year.
    - save: the percent of your salary to save in the investment account each
      year (an integer between 0 and 100).
    - years:  the number of years you work
    - return: a list of your retirement account value at the end of each year.
    Your account will grow by a random percentage each year, provided by the function
    getRandomReturnRate()
    Since we are using randomly generated return rates, there is no way to test this
    function against known values.
    """

    # TODO: Your code here.

def monteCarlo(num,salary,save,years,goal=0):
    temp_list=[]
    temp_high=0
    retire_list=[]
    list_success=[]
    for i in range(int(num)):
        temp_list=nestEggRandom(salary,save,years)
        temp_high=get_high(temp_list)
        retire_list.append(temp_high)
        if temp_high>goal:
            list_success.append(temp_high)
    success_num=len(list_success)
    success=(success_num/num)*100
    median=get_median(retire_list)
    Quart1=get_percentile_percent(retire_list, 25)
    Quart3=get_percentile_percent(retire_list, 75)
    low=get_low(retire_list)
    high=get_high(retire_list)
    retirement_funds={'minimum':low,'Q1':Quart1,'median':median,'Q3':Quart3,'maximum':high,'success_rate':success}
    return retirement_funds


    """
    - num: number of iterations to perform
    - salary: your initial salary
    - save: the percent of your salary to save in the investment account each
      year (an integer between 0 and 100).
    - years: the number of years to work.
    - goal: The target balance you want to acheive.  Defaults to zero
    - return: the five-number summary of your trials and the percent of trials where
      your balance is at least the goal in a dictionary.
    """
    # TODO: Your code here.



def nestEggRandom2(salary,save,years,growth):
    current_salary = salary
    retirement_funds = []
    retirement_funds.append(current_salary*save*.01)
    temp_fund = retirement_funds[0]
    for i in range(int(years)-1): 
        temp_fund=retirement_funds[-1]*(1+(getRandomReturnRate()*.01))+float(current_salary*save*.01)
        retirement_funds.append(temp_fund)
        current_salary=float(current_salary*(1+(growth/100)))
    return retirement_funds

def monteCarlo2(num,salary,save,years,growth,goal=0):
    temp_list=[]
    temp_high=0
    retire_list=[]
    list_success=[]
    for i in range(int(num)):
        temp_list=nestEggRandom2(salary,save,years,growth)
        temp_high=get_high(temp_list)
        retire_list.append(temp_high)
        if temp_high>goal:
            list_success.append(temp_high)
    success_num=len(list_success)
    success=(success_num/num)*100
    median=get_median(retire_list)
    Quart1=get_percentile_percent(retire_list, 25)
    Quart3=get_percentile_percent(retire_list, 75)
    low=get_low(retire_list)
    high=get_high(retire_list)
    retirement_funds={'minimum':low,'Q1':Quart1,'median':median,'Q3':Quart3,'maximum':high,'success_rate':success}
    return retirement_funds

def main():
    return_list=[]
    for i in range(30):
        return_list.append(getRandomReturnRate())
    testNestEggFixed()
    testNestEggVariable()
    funds =[0]
    i = 1
    while get_high(funds)<1000000:
        funds=nestEggFixed(50000,i,7,20)
        i+=1
    print("The answer to problem 1 is:",i-1)
    funds=[0]
    growths = [5,7,-3,2,5,-2,9,11,-7,3,5,-2,4,8,12,-3,-5,9,2,7]
    i = 1
    while get_high(funds)<1000000:
        funds=nestEggVariable(50000,i,growths)
        i+=1
    print('The answer to problem 2 is:',i-1)
    print()
    print(monteCarlo(1000,50000,10,30,1000000))
    print()
    print(monteCarlo(1000,50000,15,20,1000000))
    print()
    monte1=monteCarlo(1000,50000,10,30,1000000)
    monte2=monteCarlo2(1000,50000,10,30,2,1000000)
    print("Therefore you have a higher chance of accumulating over $1000000 if you save 10% per year for 30 years than if you save 15% per year for 20 years.")
    print()
    success_difference=(monte2['success_rate'])-(monte1['success_rate'])
    print("If your salary increases by 2% every year you are",success_difference,"% more likely to accumulate $1000000.")
    print()
    monte11=monteCarlo(1000,50000,5,30)
    monte12=monteCarlo(1000,50000,10,30)
    print('The median of 5% is:',monte11['median'],'\nThe median of 10% is:',monte12['median'],'\nThe difference between the two is:',(monte12['median']-monte11['median']),'\nTherefore when you double the saving amount the median value approximately doubles.')
    print()
    monte13=monteCarlo(1000,50000,5,15)
    monte14=monteCarlo(1000,50000,5,30)
    print('The median of 15 years is:',monte14['median'],'\nThe median of 30years is:',monte13['median'],'\nThe difference between the two is:',(monte14['median']-monte13['median']),'\nTherefore when you double the ampount of years the median amount is less than double of what it was for 15 years.')
    print()
    monte15=monteCarlo(1000,50000,5,30)
    monte16=monteCarlo(1000,50000,15,10)
    print('The median of 5% for 30 years is:',monte15['median'],'\nThe median of 15% for 10 years is:',monte16['median'],'\nThe difference between the two is',monte15['median']-monte16['median'])
    print()
    monte21=monteCarlo2(1000,50000,5,30,3)
    monte22=monteCarlo2(1000,50000,10,30,3)
    print('The median of 5% is:',monte21['median'],'\nThe median of 10% is:',monte22['median'],'\nThe difference between the two is:',(monte22['median']-monte21['median']),'\nTherefore when you double the saving amount, while getting a 3% raise every year, the median value approximately doubles.')
    print()
    monte23=monteCarlo2(1000,50000,5,15,3)
    monte24=monteCarlo(1000,50000,5,30,3)
    print('The median of 15 years is:',monte24['median'],'\nThe median of 30years is:',monte23['median'],'\nThe difference between the two is:',(monte24['median']-monte23['median']),'\nTherefore when you double the ampount, while getting a 3% raise, of years the median amount is less than double of what it was for 15 years.')
    print()
    monte25=monteCarlo2(1000,50000,5,30,3)
    monte26=monteCarlo2(1000,50000,15,10,3)
    print('The median of 5% for 30 years if you are getting a 3% raise is:',monte25['median'],'\nThe median of 15% for 10 years if you are getting a 3% raise is:',monte26['median'])
    
main()
