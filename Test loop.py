while True:
    # main program
    while True:
        answer = input("Run again? (y/n): ")
        if answer in ('y', 'n'):
            break
        print ('Invalid input.')
    if answer == 'y':
        continue
    else:
        print ('Goodbye')
        break
