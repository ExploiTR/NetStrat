import os
import sys
import time
import json
import psutil
import ctypes
import icmplib
import SharkUI
import clipboard
import subprocess
import urllib.error
from tkinter import *
from tkinter import ttk
from threading import Thread
from tkinter import messagebox
from urllib.request import urlopen

# import socket

all_active_valid_conns = []
ip_address_data_base = dict()
port_data_base_for_ip = dict()
pid_data_base_for_ip = dict()

ping_data_base = dict()
ping_data_base_old = dict()

index = 0
show_text_in_console_str = ""
cur_ip_address = ""
cur_pid_select = ""
use_performance_mode_bool = False

DEBUG_LOG = True

# todo socket.gethostbyaddr("69.59.196.211") - make a console window
main_window = Tk()  # window for displaying netstat data
stats_window = Toplevel(main_window)  # window for displaying pyshark data

# ####################################### Utility Functions #######################################

use_performance_mode = IntVar()
show_all_ip_address = IntVar()
show_ip_address_range = StringVar()
show_ip_address_range_tolerance = StringVar()
total_address_count = StringVar()
cpu_percent_var = DoubleVar()
mem_percent_var = DoubleVar()
show_process_name_filter = StringVar()
show_text_in_console = StringVar()


def reset_app():
    os.execl(sys.executable, os.path.abspath(__file__), *sys.argv)


def log(data):
    if DEBUG_LOG:
        print(str(data) + "\n")


def copy_ip_to_clipboard():
    clipboard.copy(cur_ip_address)


def activate_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    main_window.quit()
    stats_window.quit()
    sys.exit(0)


# ####################################### UI #######################################

style = ttk.Style()
style.tk.call("source", "azure.tcl")
style.tk.call("set_theme", "dark")  # light and dark


def setupWindow(window, window_name, res, anchor, icon):
    window.title(window_name)
    window.geometry(res)
    window.iconbitmap(icon)
    window.anchor(anchor)


setupWindow(main_window, 'NetStrat', '800x800', CENTER, 'icon.ico')

x = main_window.winfo_x()
y = main_window.winfo_y()
setupWindow(stats_window, 'NetShark', "%dx%d+%d+%d" % (700, 800, x + 820, y), CENTER, 'icon.ico')

main_container = ttk.Frame(main_window, width=250, height=100)
control_container = ttk.Frame(main_container)
info_container = ttk.Frame(main_container)

show_all = ttk.Checkbutton(control_container, text="Show Unreachable Addresses", state="off",
                           variable=show_all_ip_address, onvalue=1,
                           offvalue=0)
performance_mode = ttk.Checkbutton(control_container, text="High Performance Mode (Beta)", state="on",
                                   variable=use_performance_mode, onvalue=1,
                                   offvalue=0)
total_address = ttk.Label(control_container, text="Total IP Count (in list) = 0", textvariable=total_address_count)

range_label = ttk.Label(control_container, text='Ping Range Filter')
range_to_find = ttk.Entry(control_container, textvariable=show_ip_address_range, width=5)

rang_tolerance_label = ttk.Label(control_container, text='Range Tolerance ±')
range_tolerance = ttk.Entry(control_container, textvariable=show_ip_address_range_tolerance, width=5)
range_tolerance.insert(END, '0')

process_filter_label = ttk.Label(control_container, text="Proc Filter (Name/PID - CS) ")
process_filter = ttk.Entry(control_container, textvariable=show_process_name_filter)

reset_button = ttk.Button(control_container, command=reset_app, text="Reset")

cpu_percent_label = ttk.Label(info_container, text="CPU Usage :", justify="center", anchor="n")
cpu_percent = ttk.Progressbar(info_container, mode="determinate", orient="horizontal", value=50, maximum=100,
                              variable=cpu_percent_var)

mem_percent_label = ttk.Label(info_container, text="Memory Usage :")
mem_percent = ttk.Progressbar(info_container, mode="determinate", orient="horizontal", value=50, maximum=100,
                              length=100, variable=mem_percent_var)

ip_address_details_view_container = ttk.Labelframe(info_container, text="Console", borderwidth=1,
                                                   relief="raised")
ip_address_details_view = ttk.Label(ip_address_details_view_container,
                                    textvariable=show_text_in_console, padding=5)

ip_copy_button = ttk.Button(info_container, text="Copy IP", command=copy_ip_to_clipboard)
ip_trace_button = ttk.Button(info_container, text="Traceroute IP")
ip_clear_button = ttk.Button(info_container, text="Clear IP", command=copy_ip_to_clipboard)
process_kill_button = ttk.Button(info_container, text="Kill Process", command=copy_ip_to_clipboard)
launch_as_admin = ttk.Button(info_container, text="Request Elevation (admin proc)", command=activate_admin)

pad_x_con = 4
pad_y_con = 4

main_container.pack(side=LEFT, anchor="n", expand=True)
control_container.grid(row=0, column=0, padx=pad_x_con, pady=pad_y_con)
info_container.grid(row=1, column=0, padx=pad_x_con, pady=pad_y_con)

pad_x = 4
pad_y = 4

show_all.grid(row=0, column=0, padx=pad_x, pady=pad_y, columnspan=2)
performance_mode.grid(row=1, column=0, padx=pad_x, pady=pad_y, columnspan=2)
total_address.grid(row=2, column=0, padx=pad_x, pady=pad_y, columnspan=2)
range_label.grid(row=3, column=0, pady=pad_y)
range_to_find.grid(row=3, column=1, padx=pad_x, pady=pad_y)
rang_tolerance_label.grid(row=4, column=0, pady=pad_y)
range_tolerance.grid(row=4, column=1, padx=pad_x, pady=pad_y)
process_filter_label.grid(row=5, column=0, padx=pad_x, pady=pad_y, columnspan=2)
process_filter.grid(row=6, column=0, padx=pad_x, pady=pad_y, columnspan=2)
reset_button.grid(row=7, column=0, padx=pad_x, pady=pad_y, columnspan=2)

cpu_percent_label.grid(row=0, column=0, padx=pad_x, pady=pad_y)
cpu_percent.grid(row=0, column=1, padx=pad_x, pady=pad_y)
mem_percent_label.grid(row=1, column=0, padx=pad_x, pady=pad_y)
mem_percent.grid(row=1, column=1, padx=pad_x, pady=pad_y)
ip_address_details_view_container.grid(row=2, column=0, padx=pad_x, pady=16, columnspan=2)
ip_address_details_view.grid(row=0, column=0, padx=pad_x, pady=pad_y, columnspan=2)
ip_copy_button.grid(row=3, column=0, padx=pad_x, pady=pad_y)
ip_trace_button.grid(row=3, column=1, padx=pad_x, pady=pad_y)
ip_clear_button.grid(row=4, column=0, padx=pad_x, pady=pad_y)
process_kill_button.grid(row=4, column=1, padx=pad_x, pady=pad_y)
launch_as_admin.grid(row=5, column=0, padx=pad_x, pady=pad_y, columnspan=2)

scrollbar = Scrollbar(main_window)
scrollbar.pack(side=RIGHT, fill=Y)

stat_tree = ttk.Treeview(main_window, height=50, yscrollcommand=scrollbar.set)
stat_tree.pack(pady=10, padx=10, anchor="w")
scrollbar.config(command=stat_tree.yview)

stat_tree['columns'] = ('index', 'ip', 'lat', 'port', 'proc')
stat_tree.column("#0", width=0, stretch=NO)
stat_tree.column("index", anchor=CENTER, width=50)
stat_tree.column("ip", anchor=CENTER, width=100)
stat_tree.column("lat", anchor=CENTER, width=50)
stat_tree.column("port", anchor=CENTER, width=50)
stat_tree.column("proc", anchor=CENTER, width=150)

stat_tree.heading(0, text="Index", anchor=CENTER)
stat_tree.heading(1, text="IP Address", anchor=CENTER)
stat_tree.heading(2, text="Latency", anchor=CENTER)
stat_tree.heading(3, text="PORT", anchor=CENTER)
stat_tree.heading(4, text="Process", anchor=CENTER)


def kill_self():
    main_window.quit()
    stats_window.quit()
    sys.exit(0)


main_window.protocol("WM_DELETE_WINDOW", kill_self)
stats_window.protocol("WM_DELETE_WINDOW", kill_self)

SharkUI.runShark(stats_window)

# ####################################### Netstat Parsing and Data Modification #######################################
# as much as the filter works instantly (async) we also need to limit adding new entries as per filter

thread_running_for_ipdb = False  # restrict number of threads running in simultaneously to 1


# Mean execution time : 24.68ms for 76 consecutive runs
def update_ip_database():
    global thread_running_for_ipdb
    thread_running_for_ipdb = True
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
        if temp_vc in ip_address_data_base.values():
            continue
        temp_port = getattr(temp_c, "port")  # todo
        if temp_vc == "127.0.0.1" or temp_vc == "0.0.0.0":
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
    thread_running_for_ipdb = False


def update_ip_database_delay():
    global thread_running_for_ipdb
    global use_performance_mode
    while True:
        if use_performance_mode_bool:
            time.sleep(0.05)  # 24ms avg, add 25tol + round up = 50,  delay = 50/1000
        else:
            time.sleep(3)
        if not thread_running_for_ipdb:
            Thread(target=update_ip_database).start()
        else:
            continue
    # log("ipdb >> " + str(len(ip_address_data_base)))


Thread(target=update_ip_database_delay).start()

# ####################################### DATA -> UI #######################################

show_all_data = 0
ping_range_int = 50
ping_range_tolerance_int = 50
show_process_name_filter_str = ""
enable_range_filter = False
enable_proc_name_filter = False


def truncate(text, length):
    return text[0: length] + "\n" + truncate(text[length:len(text)], length) if len(text) > length else text


# updating ip details
def update_ip_details(ip):
    global show_text_in_console_str
    try:
        url = "http://ip-api.com/json/" + ip
        conn = urlopen(url)
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

            data = "IP Address : " + ip + "\n" + "Country : " + country + "\n" + \
                   "City : " + city + "\n" + "Zip : " + zip_code + "\n" + "ISP : " + truncate(isp, 20) + "\n" + \
                   "Organization : " + truncate(org, 20) + "\n" + "Alias : " + truncate(alias, 20)
            show_text_in_console_str = data
    except urllib.error.HTTPError:
        show_text_in_console_str = "Error connecting to API (HTTPError)"
    except urllib.error.ContentTooShortError:
        show_text_in_console_str = "Error connecting to API (ContentTooShortError)"
    except urllib.error.URLError:
        show_text_in_console_str = "Error connecting to API (URLError)"


# handling tree selection
def handle_selection(ignored):
    global cur_ip_address
    global cur_pid_select
    cur_item = stat_tree.item(stat_tree.focus())
    temp_item = cur_item['values']
    cur_ip_address = str(temp_item[1])
    log(temp_item)
    cur_pid_select = str(temp_item[4]).split("=")[1].split(")")[0].strip()
    Thread(target=update_ip_details, args=(cur_ip_address,)).start()


# have to declare this here LOL
stat_tree.bind('<ButtonRelease-1>', handle_selection)


def clear_ip(ignored):
    show_text_in_console.set("")
    stat_tree.selection_remove(*stat_tree.selection())


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def kill_proc(ignored):
    pid = int(cur_pid_select)
    if psutil.pid_exists(pid):
        """""
        # not working
        try:
            process = psutil.Process(pid)
            child_proc = process.children(recursive=True)
            child_proc.append(process)
            for any_proc in child_proc:
                any_proc.send_signal(signal.SIGTERM)
        except psutil.NoSuchProcess:
            log("Proc not found")
        except psutil.AccessDenied:
            log("Not enough privileges!")
        """""
        command_to_execute = ["taskkill", "/f", "/im", psutil.Process(pid).name()]
        code = subprocess.run(command_to_execute).returncode

        if code == 0:
            log("killed")
        elif is_admin():
            messagebox.showerror("Error", "This process is likely un-killable ? (are you sure it's running?)")
        else:
            # todo notify relaunch as admin
            activate_admin()


def trace_ip_and_update_internal():
    global cur_ip_address
    global show_text_in_console_str

    result = "TTL        Addr        RTT"

    trace = icmplib.traceroute(address=cur_ip_address, max_hops=30, timeout=0.2, fast=False)
    for any_hop in trace:
        result += "\n" + f'{any_hop.distance}    {any_hop.address}    {int(any_hop.avg_rtt)} ms'

    show_text_in_console_str = result


def trace_ip_and_update(ignored):
    show_text_in_console.set("Traceroute " + cur_ip_address + "\nover 30 hops...")
    Thread(target=trace_ip_and_update_internal).start()


ip_clear_button.bind('<ButtonRelease-1>', clear_ip)
process_kill_button.bind('<ButtonRelease-1>', kill_proc)
ip_trace_button.bind('<ButtonRelease-1>', trace_ip_and_update)


# Faster?
def get_ping(ip):
    host = icmplib.ping(ip, count=1, interval=0, timeout=0.25 if use_performance_mode_bool else 1, privileged=False)
    return host.avg_rtt if host.is_alive else -1


# overhead : 70ms (threaded, with ping delay)
def update_ping_data_async(ip_address):
    ping = int(get_ping(ip_address))

    if ip_address in ping_data_base and ip_address not in ip_address_data_base:  # check rn?
        del ping_data_base[ip_address]

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


# overhead = 1.66 ms
def sort_ping_db_by_value():
    global ping_data_base
    ping_data_base_local_copy = ping_data_base.copy()
    dictionary_keys = list(ping_data_base_local_copy.keys())
    sorted_dict = {dictionary_keys[i]: sorted(
        ping_data_base_local_copy.values())[i] for i in range(len(dictionary_keys))}
    ping_data_base = sorted_dict.copy()


def update_ping_data_internal():
    ip_address_data_base_copy = ip_address_data_base.copy()
    for any_valid_ip in ip_address_data_base_copy.values():
        Thread(target=update_ping_data_async, args=(any_valid_ip,)).start()
    # Thread(target=sort_ping_db_by_value).start()
    if use_performance_mode_bool:
        time.sleep(0.3)
    else:
        time.sleep(1)


def update_ping_data():
    while True:
        update_ping_data_internal()


Thread(target=update_ping_data).start()  # call recursively

# ####################################### Updating UI #######################################

frames = 0
existing_ping_entries = dict()  # reduces overhead created for reading tree again and again

# todo use flags before exit
while True:
    # excess updates : 1.08 ms mean overhead
    if frames > 14:
        total_address_count.set("Total IP Count (in list) = " + str(len(ping_data_base)))
        cpu_percent_var.set(psutil.cpu_percent(interval=None))
        mem_percent_var.set(getattr(psutil.virtual_memory(), "percent"))
        frames = 0

    # normal updates : 70 ms mean overhead (w/ ws.update) | 1.05ms mean overhead (wo/ ws.update)
    try:
        ping_range_int = int(show_ip_address_range.get())
    except ValueError:
        ping_range_int = -1

    try:
        ping_range_tolerance_int = int(show_ip_address_range_tolerance.get())
    except ValueError:
        ping_range_tolerance_int = -1

    use_performance_mode_bool = True if use_performance_mode.get() == 1 else False
    enable_range_filter = True if ping_range_int > ping_range_tolerance_int else False
    enable_proc_name_filter = True if len(show_process_name_filter_str := show_process_name_filter.get()) > 0 else False

    show_all_data = show_all_ip_address.get()
    ping_data_base_copy = ping_data_base.copy()  # take a copy of the original list
    port_data_base_for_ip_copy = port_data_base_for_ip.copy()
    pid_data_base_for_ip_copy = pid_data_base_for_ip.copy()
    existing_ping_entries_copy = existing_ping_entries.copy()

    """
    # Mean execution time = 1.7ms (+more hitching)
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
                
    """
    # Mean execution time = 1.5ms (less hitching)
    children = stat_tree.get_children()
    loc_index = 0
    if len(existing_ping_entries_copy) > 0 and len(children) > 0:
        for entry in existing_ping_entries_copy.values():
            line = children[loc_index]
            loc_item = stat_tree.item(line)['values']
            temp_ip = loc_item[1]  # we're working on a copy , del so new duplicate entries are prevented
            if entry in ping_data_base_copy.keys() and entry in loc_item:
                stat_tree.item(line, values=(children.index(line), temp_ip, ping_data_base_copy.get(temp_ip),
                                             port_data_base_for_ip_copy.get(temp_ip),
                                             pid_data_base_for_ip_copy.get(temp_ip)))
                del ping_data_base_copy[temp_ip]
            else:
                stat_tree.delete(line)
                del existing_ping_entries[list(existing_ping_entries_copy.keys())[loc_index]]
            loc_index += 1

    if len(ping_data_base_copy) > 0:
        for ping_item in ping_data_base_copy.keys():
            stat_tree.insert(parent='', index='end', iid=None,
                             values=(index, ping_item,
                                     str(ping_data_base_copy.get(ping_item)),
                                     str(port_data_base_for_ip_copy.get(ping_item)),
                                     str(pid_data_base_for_ip_copy.get(ping_item))))
            existing_ping_entries[index] = ping_item
            index += 1

    if len(show_text_in_console_str) > 0:
        show_text_in_console.set(show_text_in_console_str)
        show_text_in_console_str = ""

    frames += 1
    main_window.update()
    SharkUI.updateUI(stats_window)
