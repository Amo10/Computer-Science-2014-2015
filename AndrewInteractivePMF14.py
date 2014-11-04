def mySqrt(n, times):
    old_guess = 0.5 * n
    for i in range(times):
        new_guess = 0.5 * (old_guess + n/old_guess)
        old_guess = new_guess
    return new_guess
