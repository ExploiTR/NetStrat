import re
import time
import pyshark
import netifaces
import subprocess
from tkinter import *
from tkinter import ttk
from threading import Thread
from PackDetail import PackDetail
from PacketProfile import PacketProfile

packet_details = []  # store raw packet data
display_packet_details = []  # store raw packet data (for display)
usable_interfaces = dict()  # lists all interfaces with dump_cap and uses name:hid as key:val
interface_options = dict()  # check button control, on:off value and interface name as key
profiled_packet_data = dict()  # use r_addr as key
cur_machine_ip = "127.0.0.1"  # updated later at @runSharkInternal

shark_tree = None
enable_raw_view = False


def setupUI(window):
    cmd = ["C:\\Program Files\\Wireshark\\dumpcap.exe", '-D']
    shark_interfaces = subprocess.run(cmd, stdout=subprocess.PIPE).stdout.decode("utf-8")
    shark_interfaces = shark_interfaces.split("\n")
    for any_interface in shark_interfaces:
        if "{" not in any_interface or "(" not in any_interface:
            continue
        us_index = any_interface.index("\\")
        br_index = any_interface.index("(")
        interface = any_interface[us_index: br_index - 1]
        interface_name = re.sub("[\r*()]", "", any_interface[br_index: len(any_interface)])
        usable_interfaces[interface_name] = interface
    createUI(window)


def validate_interface_control(variable):
    if interface_options[variable] == 1:
        for item in interface_options.keys():
            if variable is not item:
                interface_options[item] = 0


def createUI(stats_window):
    select_container = Frame(stats_window)
    select_container.pack(side=TOP, anchor="n", pady=5, padx=5)
    control_container = Frame(stats_window)
    control_container.pack(side=TOP, anchor="center", pady=5, padx=5)

    max_grid_x = int(len(usable_interfaces.keys()) / 2)
    max_grid_y = int(len(usable_interfaces.keys()) / max_grid_x)

    grid_x = 0
    grid_y = 0

    for any_iface in usable_interfaces.keys():
        temp_var = IntVar()
        interface_options[any_iface] = temp_var
        temp = ttk.Checkbutton(select_container, text=any_iface, variable=interface_options[any_iface],
                               onvalue=1,
                               offvalue=0, state="off",
                               command=validate_interface_control(any_iface))
        temp.grid(row=grid_x, column=grid_y)
        grid_y += 1
        if grid_y > max_grid_y:
            grid_y = 0
            grid_x += 1

    scrollbar = Scrollbar(stats_window)
    scrollbar.pack(side=RIGHT, fill=Y)

    global shark_tree
    shark_tree = ttk.Treeview(stats_window, height=50)
    scrollbar.config(command=shark_tree.yview)

    shark_tree['columns'] = ('type', 'src_ip', 'dest_ip', 'src_port', 'dest_port')
    shark_tree.column("#0", width=0, stretch=NO)
    shark_tree.column("type", anchor=CENTER, width=75)
    shark_tree.column("src_ip", anchor=CENTER, width=100)
    shark_tree.column("dest_ip", anchor=CENTER, width=100)
    shark_tree.column("src_port", anchor=CENTER, width=75)
    shark_tree.column("dest_port", anchor=CENTER, width=75)

    shark_tree.heading(0, text="Type", anchor=CENTER)
    shark_tree.heading(1, text="Source IP", anchor=CENTER)
    shark_tree.heading(2, text="Destination IP", anchor=CENTER)
    shark_tree.heading(3, text="Source Port", anchor=CENTER)
    shark_tree.heading(4, text="Destination Port", anchor=CENTER)

    run_button = ttk.Button(control_container, text="Load Config and Start", command=runSharkInternal)
    run_button.grid(row=0, column=0, padx=10, pady=5)

    raw_packet_show = ttk.Button(control_container, text="Show Raw", command=toggleRawView)
    raw_packet_show.grid(row=0, column=1, padx=10, pady=5)


def toggleRawView():
    global enable_raw_view
    enable_raw_view = not enable_raw_view


def runShark(window):
    setupUI(window)


def runSharkInternal():
    global cur_machine_ip
    interface_to_use = ""

    for name, state in interface_options.items():
        if state.get() == 1:
            interface_to_use = name

    if len(interface_to_use) < 1:
        for name in usable_interfaces.keys():
            if "Ethernet" == name:
                interface_options[name].set(1)
                interface_to_use = name
                break
            elif "Wi-Fi" == name:
                interface_options[name].set(1)
                interface_to_use = name

    for name in interface_options.keys():
        if name is not interface_to_use:
            interface_options[name].set(0)

    using_interface = usable_interfaces[interface_to_use]
    cur_machine_ip = netifaces.ifaddresses(using_interface.split("_")[1])[netifaces.AF_INET][0]['addr']
    capture = pyshark.LiveCapture(interface=usable_interfaces[interface_to_use],
                                  capture_filter="host " + cur_machine_ip)
    Thread(target=cap_contd, args=(capture,)).start()
    Thread(target=profile_packets).start()


def process_packet(pack):
    detail = PackDetail()
    append = False
    detail.p_size = pack.length
    for layer in pack.layers:
        if layer.layer_name == 'ip':
            detail.src_addr = layer.src_host
            detail.dest_addr = layer.dst_host
        elif layer.layer_name == 'tcp':
            append = True
            detail.p_type = 'tcp'
            detail.src_port = layer.srcport
            detail.dest_port = layer.dstport
        elif layer.layer_name == 'udp':
            append = True
            detail.p_type = 'udp'
            detail.src_port = layer.srcport
            detail.dest_port = layer.dstport
    if append:
        packet_details.append(detail)
        display_packet_details.append(detail)


def cap_contd(capture):
    for packet in capture.sniff_continuously():
        process_packet(packet)


def profile_packets_internal():
    global cur_machine_ip
    profile = PacketProfile()
    temp_packet_details = packet_details.copy()
    for packet in temp_packet_details:
        profile.r_addr = packet.dest_addr if packet.src_addr == cur_machine_ip else packet.src_addr

        if profile.r_addr in profiled_packet_data.keys():
            profile = profiled_packet_data[profile.r_addr]
            profile.t_size += packet.p_size
            profile.p_count += 1
        else:
            profile.t_size = packet.p_size
            profile.p_type = packet.p_type
            profile.i_time = time.time_ns()
            profile.w_ports = packet.src_port + ":" + packet.dest_port
            profile.p_count = 1

        profile.e_time = time.time_ns()

        profiled_packet_data[profile.r_addr] = profile
        packet_details.remove(packet)
    print(len(profiled_packet_data))


def profile_packets():
    while True:
        profile_packets_internal()


packets_displayed = 0
tree_hidden = True


# noinspection PyUnresolvedReferences
def updateUI(stats_window):
    global packets_displayed
    global tree_hidden
    if shark_tree is not None and enable_raw_view:
        if tree_hidden:
            shark_tree.pack(side=BOTTOM, anchor="s", pady=10, padx=10)
            tree_hidden = False
        if len(display_packet_details) > packets_displayed:
            for packet in display_packet_details[packets_displayed:len(display_packet_details)]:
                shark_tree.insert(parent='', index='end', iid=None,
                                  values=(packet.p_type, packet.src_addr, packet.dest_addr,
                                          packet.src_port, packet.dest_port))
        shark_tree.yview_moveto(1)
        if len(display_packet_details) > 1200:
            del display_packet_details[0:200]
    elif not enable_raw_view:
        if not tree_hidden:
            shark_tree.pack_forget()
        tree_hidden = True
    packets_displayed = len(display_packet_details)
    stats_window.update()
