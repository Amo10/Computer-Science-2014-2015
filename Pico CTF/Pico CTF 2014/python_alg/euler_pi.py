# Euler's zeta function method for pi
# feed x = 2 into zeta function; 
# result converges to (pi^2)/6

def zeta(expt, err):
    """Zeta function. Takes the exponent and the error."""
    i = old = 1
    new = 0
    while abs(old - new) > err:
        old = new
        new += 1 / i ** expt
        i += 1
    return new

def main():
    print("Euler's method for calculating pi.")
    digits = int(input("How many digits? "))
    err = 10 ** - (2 * digits + 1)
    euler = zeta(2,err)
    string = "%." + str(digits) + 'f'
    print(string % (euler * 6) ** 0.5)

if __name__ == "__main__":
    main()

