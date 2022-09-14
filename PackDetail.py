class PackDetail:

    def __init__(self):
        self.p_size = None
        self.p_type = None
        self.src_addr = None
        self.dest_addr = None
        self.src_port = None
        self.dest_port = None

    def __str__(self):
        return "Len : " + str(self.p_size) + ", " + "PType : " + str(self.p_type) + ", " + "SRC : " + \
               str(self.src_addr) + ", " \
               + "DEST : " + str(self.dest_addr) + ", " + "SRC PORT : " + str(self.src_port) + ", " + "DEST PORT : " \
               + str(self.dest_port)


def p_size(self):
    return self.p_size


def p_type(self):
    return self.p_type


def src_addr(self):
    return self.src_addr


def dest_addr(self):
    return self.dest_addr


def src_port(self):
    return self.src_port


def dest_port(self):
    return self.dest_port
