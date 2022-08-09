import psutil
import subprocess
import time
from tkinter import *
from tkinter import ttk
from threading import Thread
import sys

# import socket

all_active_valid_conns = []
ip_address_data_base = dict()
ping_data_base = dict()
ping_data_base_old = dict()
index = 0


# todo socket.gethostbyaddr("69.59.196.211") - make a console window

def reset_app():
    global index
    all_active_valid_conns.clear()
    ip_address_data_base.clear()
    ping_data_base.clear()
    ping_data_base_old.clear()
    index = 0


# ####################################### UI #######################################

ws = Tk()
ws.title('NetSTRAT')
ws.geometry('800x800')
ws.iconbitmap('icon.ico')

style = ttk.Style()
style.tk.call("source", "azure.tcl")
style.tk.call("set_theme", "dark")  # light and dark

show_all_ip_address = IntVar()
show_ip_address_range = StringVar()
show_ip_address_range_tolerance = StringVar()

show_all = ttk.Checkbutton(ws, text="Show Unreachable Addresses", state="off", variable=show_all_ip_address, onvalue=1,
                           offvalue=0)
range_label = ttk.Label(ws, text='Ping Range Filter')
range_to_find = ttk.Entry(ws, textvariable=show_ip_address_range)
rang_tolerance_label = ttk.Label(ws, text='Range Tolerance ±')

range_tolerance = ttk.Entry(ws, textvariable=show_ip_address_range_tolerance)
range_tolerance.insert(END, '0')

reset_button = ttk.Button(ws, command=reset_app, text="Reset")
spacer = ttk.Separator(ws, orient="vertical")

show_all.pack(side=TOP, anchor="w", padx=16, pady=5)
range_label.pack(after=show_all, side=TOP, anchor="w", padx=16, pady=5)
range_to_find.pack(after=range_label, side=TOP, anchor="w", padx=16, pady=5)
rang_tolerance_label.pack(after=range_to_find, side=TOP, anchor="w", padx=16, pady=5)
range_tolerance.pack(after=rang_tolerance_label, side=TOP, anchor="w", padx=16, pady=5)
reset_button.pack(after=range_tolerance, side=TOP, anchor="w", padx=16, pady=5)
spacer.pack(after=reset_button, side=TOP, anchor="w", padx=16, pady=5)

scrollbar = Scrollbar(ws)
scrollbar.pack(side=RIGHT, fill=Y)

tree = ttk.Treeview(ws, height=100, yscrollcommand=scrollbar.set)
tree.pack(pady=5)

tree['columns'] = ('index', 'ip', 'lat')
tree.column("#0", width=0, stretch=NO)
tree.column("index", anchor=CENTER, width=250)
tree.column("ip", anchor=CENTER, width=250)
tree.column("lat", anchor=CENTER, width=250)

tree.heading(0, text="Index (in internal list)", anchor=CENTER)
tree.heading(1, text="IP Address", anchor=CENTER)
tree.heading(2, text="Latency", anchor=CENTER)

scrollbar.config(command=tree.yview)

ws.protocol("WM_DELETE_WINDOW", sys.exit)


# ####################################### Netstat Parsing #######################################


def update_ip_database():
    active_conns = psutil.net_connections()
    for any_activ_conn in active_conns:
        temp_s = getattr(any_activ_conn, "status")
        if temp_s == 'ESTABLISHED':
            temp_c = getattr(any_activ_conn, "raddr")
        else:
            continue
        if len(temp_c) < 1:
            continue
        temp_vc = getattr(temp_c, "ip")
        if temp_vc == "127.0.0.1" or temp_vc == "0.0.0.0" or (temp_vc in ip_address_data_base.values()):
            continue
        ip_address_data_base[len(ip_address_data_base)] = temp_vc


def update_ip_database_delay():
    update_ip_database()
    time.sleep(3)
    print("ipdb >> " + str(len(ip_address_data_base)))
    update_ip_database_delay()


Thread(target=update_ip_database_delay).start()

# ####################################### DATA -> UI #######################################

show_all_data = 0
ping_range_int = 50
ping_range_tolerance_int = 50
enable_range_filter = False


def get_ping(ip):
    process = subprocess.run(['ping', '-n', '1', '-w', '250', ip], stdout=subprocess.PIPE, shell=True)
    temp_res = process.stdout.decode('utf-8')
    result = ""
    if "Average" in temp_res:
        result = temp_res.split("Average = ")[1].split("ms")[0]
    if len(result) < 1:
        result = "-1"
    return result


def update_ping_data_async(ip_address):
    ping = int(get_ping(ip_address))
    if enable_range_filter:  # initial skimming through old pings and discarding quickly everything not falling in range
        for old_pings in list(ping_data_base.keys()):
            if not ping_range_int - ping_range_tolerance_int <= ping_data_base.get(
                    old_pings) <= ping_range_int + ping_range_tolerance_int:
                ping_data_base_old[old_pings] = ping_data_base.get(old_pings)  # keep record of old pings
                del ping_data_base[old_pings]
    elif len(ping_data_base_old) > 0:
        ping_data_base.update(ping_data_base_old)
        ping_data_base_old.clear()

    if ping > 0:
        if enable_range_filter:
            if ping_range_int - ping_range_tolerance_int <= ping <= ping_range_int + ping_range_tolerance_int:
                ping_data_base[ip_address] = ping
        else:
            ping_data_base[ip_address] = ping
    elif show_all_data == 1:
        ping_data_base[ip_address] = ping
    elif ip_address in ping_data_base:
        del ping_data_base[ip_address]


def update_ping_data():
    ip_address_data_base_copy = ip_address_data_base.copy()
    for any_valid_ip in ip_address_data_base_copy.values():
        Thread(target=update_ping_data_async, args=(any_valid_ip,)).start()
    time.sleep(5)
    update_ping_data()


Thread(target=update_ping_data).start()  # call recursively

# ####################################### Pulling the Strings #######################################


while True:
    ping_data_base_copy = ping_data_base.copy()

    if len(tree.get_children()) > 0:
        for line in tree.get_children():
            tempItem = tree.item(line)['values']
            if tempItem[1] in ping_data_base_copy.keys():
                tree.item(line, values=(tempItem[0], tempItem[1], ping_data_base_copy.get(tempItem[1])))
                del ping_data_base_copy[tempItem[1]]
            else:
                tree.delete(line)

    for ping_item in ping_data_base_copy.keys():
        # print(str(index) + " >> " + ping_item + " >> " + str(ping_data_base_copy.get(ping_item)))
        tree.insert(parent='', index='end', iid=index,
                    values=(index, ping_item, str(ping_data_base_copy.get(ping_item))))
        index = index + 1

    ws.update()

    show_all_data = show_all_ip_address.get()

    temp_r = show_ip_address_range.get()
    if temp_r.isalnum():
        ping_range_int = int(temp_r)
    else:
        ping_range_int = -1

    temp_t = show_ip_address_range_tolerance.get()
    if temp_t.isalnum():
        ping_range_tolerance_int = int(temp_t)
    else:
        ping_range_tolerance_int = 0

    if ping_range_int - ping_range_tolerance_int > 0:
        enable_range_filter = True
    else:
        enable_range_filter = False
