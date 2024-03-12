from server import Server
import constants

def main():
    PORT:int

    try:
        f = open(constants.PORT_INFO_FILE, 'r')
        PORT = int(f.read())
        f.close()

    except OSError:
        print(f"{constants.PORT_INFO_FILE} file could not be opened")
        PORT = constants.DEFAULT_PORT

    # todo: add check db
    s = Server(PORT)
    s.start()


if __name__ == "__main__":
    main()