import sys
import time
import json
import psutil
import icmplib
import clipboard
import urllib.error
from tkinter import *
from tkinter import ttk
from threading import Thread
from urllib.request import urlopen

# import socket

all_active_valid_conns = []
ip_address_data_base = dict()
port_data_base_for_ip = dict()
pid_data_base_for_ip = dict()

ping_data_base = dict()
ping_data_base_old = dict()

index = 0
ip_data_details_erasable = ""
cur_ip_address = ""

DEBUG_LOG = True

# todo socket.gethostbyaddr("69.59.196.211") - make a console window
ws = Tk()  # create window first then work everything else

# ####################################### Utility Functions #######################################

show_all_ip_address = IntVar()
show_ip_address_range = StringVar()
show_ip_address_range_tolerance = StringVar()
total_address_count = StringVar()
cpu_percent_var = DoubleVar()
mem_percent_var = DoubleVar()
show_process_name_filter = StringVar()
show_ip_details_str = StringVar()


def reset_app():
    global index
    all_active_valid_conns.clear()
    ip_address_data_base.clear()
    ping_data_base.clear()
    ping_data_base_old.clear()
    show_all_ip_address.set(0)
    show_ip_address_range.set("")
    show_ip_address_range_tolerance.set("")
    show_process_name_filter.set("")
    index = 0


def log(data):
    if DEBUG_LOG:
        print(data)


def copy_ip_to_clipboard():
    clipboard.copy(cur_ip_address)


# ####################################### UI #######################################

ws.title('NetSTRAT')
ws.geometry('950x800')
ws.iconbitmap('icon.ico')
ws.anchor("center")

style = ttk.Style()
style.tk.call("source", "azure.tcl")
style.tk.call("set_theme", "dark")  # light and dark

main_container = ttk.Frame(ws, width=200)
control_container = ttk.Frame(main_container)
info_container = ttk.Frame(main_container)

show_all = ttk.Checkbutton(control_container, text="Show Unreachable Addresses", state="off",
                           variable=show_all_ip_address, onvalue=1,
                           offvalue=0)
total_address = ttk.Label(control_container, text="Total IP Count (in list) = 0", textvariable=total_address_count)

range_label = ttk.Label(control_container, text='Ping Range Filter')
range_to_find = ttk.Entry(control_container, textvariable=show_ip_address_range)

rang_tolerance_label = ttk.Label(control_container, text='Range Tolerance ±')
range_tolerance = ttk.Entry(control_container, textvariable=show_ip_address_range_tolerance)
range_tolerance.insert(END, '0')

process_filter_label = ttk.Label(control_container, text="Process Name Filter")
process_filter = ttk.Entry(control_container, textvariable=show_process_name_filter)

reset_button = ttk.Button(control_container, command=reset_app, text="Reset")

cpu_percent_label = ttk.Label(info_container, text="CPU Usage :", justify="center", anchor="n")
cpu_percent = ttk.Progressbar(info_container, mode="determinate", orient="horizontal", value=50, maximum=100,
                              variable=cpu_percent_var)

mem_percent_label = ttk.Label(info_container, text="Memory Usage :")
mem_percent = ttk.Progressbar(info_container, mode="determinate", orient="horizontal", value=50, maximum=100,
                              length=100, variable=mem_percent_var)

ip_address_details_view = ttk.Label(info_container,
                                    textvariable=show_ip_details_str, borderwidth=1, relief="raised",
                                    background="#ffffff", foreground="#000000")
show_ip_details_str.set("Select entry in list to reveal details!")

ip_copy_button = ttk.Button(info_container, text="Copy IP", command=copy_ip_to_clipboard)
ip_trace_button = ttk.Button(info_container, text="Traceroute IP")

pad_x_con = 4
pad_y_con = 4

main_container.pack(side=LEFT, anchor="n", expand=True)
control_container.grid(row=0, column=0, padx=pad_x_con, pady=pad_y_con)
info_container.grid(row=1, column=0, padx=pad_x_con, pady=pad_y_con)

pad_x = 4
pad_y = 4

show_all.grid(row=0, column=0, padx=pad_x, pady=pad_y)
total_address.grid(row=1, column=0, padx=pad_x, pady=pad_y)
range_label.grid(row=2, column=0, pady=pad_y)
range_to_find.grid(row=3, column=0, padx=pad_x, pady=pad_y)
rang_tolerance_label.grid(row=4, column=0, pady=pad_y)
range_tolerance.grid(row=5, column=0, padx=pad_x, pady=pad_y)
process_filter_label.grid(row=6, column=0, padx=pad_x, pady=pad_y)
process_filter.grid(row=7, column=0, padx=pad_x, pady=pad_y)
reset_button.grid(row=8, column=0, padx=pad_x, pady=pad_y)

cpu_percent_label.grid(row=0, column=0, padx=pad_x, pady=pad_y)
cpu_percent.grid(row=0, column=1, padx=pad_x, pady=pad_y)
mem_percent_label.grid(row=1, column=0, padx=pad_x, pady=pad_y)
mem_percent.grid(row=1, column=1, padx=pad_x, pady=pad_y)
ip_address_details_view.grid(row=2, column=0, padx=pad_x, pady=16, columnspan=2)
ip_copy_button.grid(row=3, column=0, padx=pad_x, pady=pad_y)
ip_trace_button.grid(row=3, column=1, padx=pad_x, pady=pad_y)

scrollbar = Scrollbar(ws)
scrollbar.pack(side=RIGHT, fill=Y)

tree = ttk.Treeview(ws, height=100, yscrollcommand=scrollbar.set)
tree.pack(pady=10, padx=10, anchor="w")

tree['columns'] = ('index', 'ip', 'lat', 'port', 'proc')
tree.column("#0", width=0, stretch=NO)
tree.column("index", anchor=CENTER, width=50)
tree.column("ip", anchor=CENTER, width=150)
tree.column("lat", anchor=CENTER, width=100)
tree.column("port", anchor=CENTER, width=100)
tree.column("proc", anchor=CENTER, width=200)

tree.heading(0, text="Index", anchor=CENTER)
tree.heading(1, text="IP Address", anchor=CENTER)
tree.heading(2, text="Latency", anchor=CENTER)
tree.heading(3, text="PORT", anchor=CENTER)
tree.heading(4, text="Process", anchor=CENTER)

scrollbar.config(command=tree.yview)

ws.protocol("WM_DELETE_WINDOW", sys.exit)


# ####################################### Netstat Parsing and Data Modification #######################################
# as much as the filter works instantly (async) we also need to limit adding new entries as per filter
def update_ip_database():
    active_conns = psutil.net_connections()
    for any_activ_conn in active_conns:
        temp_s = getattr(any_activ_conn, "status")
        temp_pid = getattr(any_activ_conn, "pid")  # todo
        if temp_s == 'ESTABLISHED':
            temp_c = getattr(any_activ_conn, "raddr")
        else:
            continue
        if len(temp_c) < 1:
            continue
        temp_vc = getattr(temp_c, "ip")
        temp_port = getattr(temp_c, "port")  # todo
        if temp_vc == "127.0.0.1" or temp_vc == "0.0.0.0" or (temp_vc in ip_address_data_base.values()):
            continue
        if temp_port is not None and temp_port > 0:
            port_data_base_for_ip[temp_vc] = temp_port
        else:
            port_data_base_for_ip[temp_vc] = "Unknown?"
        if temp_pid is not None and temp_pid > 0:
            pid_data_base_for_ip[temp_vc] = psutil.Process(temp_pid).name() + " (pid = " + str(temp_pid) + ")"
        else:
            pid_data_base_for_ip[temp_vc] = "Unknown?"

        ip_address_data_base[len(ip_address_data_base)] = temp_vc


def update_ip_database_delay():
    update_ip_database()
    time.sleep(3)
    # log("ipdb >> " + str(len(ip_address_data_base)))
    update_ip_database_delay()


Thread(target=update_ip_database_delay).start()

# ####################################### DATA -> UI #######################################

show_all_data = 0
ping_range_int = 50
ping_range_tolerance_int = 50
show_process_name_filter_str = ""
enable_range_filter = False
enable_proc_name_filter = False


# updating ip details
def update_ip_details(ip):
    global ip_data_details_erasable
    try:
        conn = urlopen("http://ip-api.com/json/" + ip)
        str_data = str(conn.read().decode("utf-8")).replace("\'", "\"")
        data = json.loads(str_data)
        stat = data["status"]
        if stat != "success":
            return
        else:
            country = data["country"]
            city = data["city"]
            zip_code = data["zip"]
            isp = data["isp"]
            org = data["org"]
            alias = data["as"]

            data = "IP Address details for " + ip + "\n" + "Country : " + country + "\n" + \
                   "City : " + city + "\n" + "Zip : " + zip_code + "\n" + "ISP : " + isp + "\n" + \
                   "Organization : " + org + "\n" + "Alias : " + alias
            ip_data_details_erasable = data
    except urllib.error.HTTPError:
        ip_data_details_erasable = "Error connecting to API (HTTPError)"
    except urllib.error.ContentTooShortError:
        ip_data_details_erasable = "Error connecting to API (ContentTooShortError)"
    except urllib.error.URLError:
        ip_data_details_erasable = "Error connecting to API (URLError)"


# handling tree selection
def handle_selection(ignored):
    global cur_ip_address
    cur_item = tree.item(tree.focus())
    temp_item = cur_item['values']
    cur_ip_address = str(temp_item[1])
    Thread(target=update_ip_details, args=(cur_ip_address,)).start()


# have to declare this here LOL
tree.bind('<ButtonRelease-1>', handle_selection)


# Faster?
def get_ping(ip):
    host = icmplib.ping(ip, count=1, interval=0, timeout=0.5, privileged=False)
    return host.avg_rtt if host.is_alive else -1


def update_ping_data_async(ip_address):
    ping = int(get_ping(ip_address))

    if ip_address not in ip_address_data_base:  # check rn?
        if ip_address in ping_data_base:
            del ping_data_base[ip_address]
        if ip_address in ping_data_base_old:
            del ping_data_base_old[ip_address]
        # if ip_address in pid_data_base_for_ip.keys(): weird?
        # del pid_data_base_for_ip[ip_address]
        # if ip_address in port_data_base_for_ip.keys():
        # del port_data_base_for_ip[ip_address]

    # initial skimming through old pings and discarding quickly everything not falling in range (if there is)
    if enable_range_filter:
        if ping_range_int - ping_range_tolerance_int <= ping <= ping_range_int + ping_range_tolerance_int:
            ping_data_base[ip_address] = ping
        elif ip_address in list(ping_data_base.keys()):
            del ping_data_base[ip_address]
            ping_data_base_old[ip_address] = ping  # store now for restoration
    elif ip_address in ping_data_base_old:
        ping_data_base[ip_address] = ping_data_base_old[ip_address]
        del ping_data_base_old[ip_address]
    elif ping > 0:
        ping_data_base[ip_address] = ping
    elif show_all_data == 1:
        ping_data_base[ip_address] = ping
    else:
        if ip_address in ping_data_base.keys():
            del ping_data_base[ip_address]
        if ip_address in pid_data_base_for_ip.keys():
            del pid_data_base_for_ip[ip_address]
        if ip_address in port_data_base_for_ip.keys():
            del port_data_base_for_ip[ip_address]

    if ip_address in ping_data_base.keys():
        if enable_proc_name_filter:
            if ip_address in list(pid_data_base_for_ip.keys()):
                if show_process_name_filter_str in pid_data_base_for_ip[ip_address]:
                    ping_data_base[ip_address] = ping
                else:
                    del ping_data_base[ip_address]
                    ping_data_base_old[ip_address] = ping  # store now for restoration
        elif ip_address in ping_data_base_old:
            ping_data_base[ip_address] = ping_data_base_old[ip_address]
            del ping_data_base_old[ip_address]
        elif ping > 0:
            ping_data_base[ip_address] = ping
        elif show_all_data == 1:
            ping_data_base[ip_address] = ping
        else:
            if ip_address in ping_data_base.keys():
                del ping_data_base[ip_address]
            if ip_address in pid_data_base_for_ip.keys():
                del pid_data_base_for_ip[ip_address]
            if ip_address in port_data_base_for_ip.keys():
                del port_data_base_for_ip[ip_address]


def update_ping_data():
    ip_address_data_base_copy = ip_address_data_base.copy()
    for any_valid_ip in ip_address_data_base_copy.values():
        Thread(target=update_ping_data_async, args=(any_valid_ip,)).start()
    time.sleep(0.5)
    update_ping_data()


Thread(target=update_ping_data).start()  # call recursively

# ####################################### Pulling the Strings #######################################

while True:
    show_all_data = show_all_ip_address.get()
    ping_data_base_copy = ping_data_base.copy()  # take a copy of the original list
    port_data_base_for_ip_copy = port_data_base_for_ip.copy()
    pid_data_base_for_ip_copy = pid_data_base_for_ip.copy()

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

    if len(show_process_name_filter.get()) > 0:
        enable_proc_name_filter = True
        show_process_name_filter_str = show_process_name_filter.get()
    else:
        enable_proc_name_filter = False

    total_address_count.set("Total IP Count (in list) = " + str(len(ping_data_base_copy)))
    cpu_percent_var.set(psutil.cpu_percent(interval=None))
    mem_percent_var.set(getattr(psutil.virtual_memory(), "percent"))

    children = tree.get_children()
    if len(children) > 0:
        for line in children:
            tempItem = tree.item(line)['values']
            temp_ip = tempItem[1]
            if temp_ip in ping_data_base_copy.keys():
                tree.item(line, values=(children.index(line), temp_ip, ping_data_base_copy.get(temp_ip),
                                        port_data_base_for_ip_copy.get(temp_ip),
                                        pid_data_base_for_ip_copy.get(temp_ip)))
                del ping_data_base_copy[temp_ip]  # we're working on copy real list so elimination
                if temp_ip in port_data_base_for_ip_copy.keys():
                    del port_data_base_for_ip_copy[temp_ip]
                if temp_ip in pid_data_base_for_ip_copy.keys():
                    del pid_data_base_for_ip_copy[temp_ip]
            else:
                tree.delete(line)

    if len(ping_data_base_copy) > 0:
        for ping_item in ping_data_base_copy.keys():
            # log( ping_item + " >> " + str(ping_data_base_copy.get(ping_item)))
            tree.insert(parent='', index='end', iid=None,
                        values=(index, ping_item,
                                str(ping_data_base_copy.get(ping_item)),
                                str(port_data_base_for_ip_copy.get(ping_item)),
                                str(pid_data_base_for_ip_copy.get(ping_item))))
            index += 1

    if len(ip_data_details_erasable) > 0:
        show_ip_details_str.set(ip_data_details_erasable)
        ip_data_details_erasable = ""

    ws.update()
