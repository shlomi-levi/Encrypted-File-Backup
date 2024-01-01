
def main():
    PORT:int

    try:
        f = open('port.info', 'r')
        PORT = int(f.read())

        f.close()

    except OSError:
        print("port.info file could not be opened")
        PORT = 1256

    # add check db

    




    if






if __name__ == "__main__":
    main()