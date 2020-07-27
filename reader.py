class Reader:
    def __init__(self, filename, mode="r"):
        self.__file = open(filename, mode)
        self.__line = 0
        self.__char = 0

    def close(self):
        self.__file.close()

    def readline(self, size=-1):
        curr_line = self.__file.readline(size)
        self.__line += 1
        self.__char += len(curr_line)
        return curr_line
    
    def line_num(self):
        return self.__line

    def char_num(self):
        return self.__char