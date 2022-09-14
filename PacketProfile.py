class PacketProfile:

    def __init__(self):
        self.t_size = None
        self.p_count = None
        self.i_time = None
        self.e_time = None
        self.p_rate = None
        self.p_type = None
        self.r_addr = None
        self.w_ports = None  # : separated

    def __str__(self):
        return "Len : " + str(self.t_size) + ", " + "Count : " + str(self.p_count) + ", " + "ITime : " + str(
            self.i_time) + ", " + "ETime : " + str(
            self.e_time) + ", " + "Rate: " + str(self.p_rate) + ", " + "Ptype : " + str(self.p_type) + \
               ", " + "addr : " + str(self.r_addr) + ", " + "SDPorts : " + str(self.w_ports)


def t_size(self):
    return self.t_size


def p_count(self):
    return self.t_count


def i_time(self):
    return self.i_time


def e_time(self):
    return self.e_time


def p_rate(self):
    return self.p_rate


def p_type(self):
    return self.p_type


def r_addr(self):
    return self.r_addr


def w_ports(self):
    return self.w_ports
