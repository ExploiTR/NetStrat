# noinspection PyUnresolvedReferences
import sys
from tkinter import *
from tkinter import ttk
from threading import Thread
from tkinter import messagebox

raw_packet_window = None
raw_tree = None
packets_displayed = 0
tree_hidden = True


def setupUI(main_window):
    global raw_packet_window
    global raw_tree
    raw_packet_window = Toplevel(main_window)
    raw_packet_window.protocol("WM_DELETE_WINDOW", kill_self)

    scrollbar = Scrollbar(main_window)
    scrollbar.pack(side=RIGHT, fill=Y)

    raw_tree = ttk.Treeview(main_window, height=50, yscrollcommand=scrollbar.set)
    raw_tree.pack(pady=10, padx=10, anchor="w")
    scrollbar.config(command=raw_tree.yview)

    raw_tree['columns'] = ('index', 'ip', 'lat', 'port', 'proc')
    raw_tree.column("#0", width=0, stretch=NO)
    raw_tree.column("index", anchor=CENTER, width=50)
    raw_tree.column("ip", anchor=CENTER, width=100)
    raw_tree.column("lat", anchor=CENTER, width=50)
    raw_tree.column("port", anchor=CENTER, width=50)
    raw_tree.column("proc", anchor=CENTER, width=150)

    raw_tree.heading(0, text="Index", anchor=CENTER)
    raw_tree.heading(1, text="IP Address", anchor=CENTER)
    raw_tree.heading(2, text="Latency", anchor=CENTER)
    raw_tree.heading(3, text="PORT", anchor=CENTER)
    raw_tree.heading(4, text="Process", anchor=CENTER)


def kill_self():
    raw_packet_window.quit()


def updateUI(enable_raw_view, display_packet_details):
    global raw_tree
    global packets_displayed
    global tree_hidden

    if raw_tree is not None and enable_raw_view:
        if tree_hidden:
            raw_packet_window.deiconify()
            raw_tree.pack(side=BOTTOM, anchor="s", pady=10, padx=10)
            tree_hidden = False
        if len(display_packet_details) > packets_displayed:
            for packet in display_packet_details[packets_displayed:len(display_packet_details)]:
                raw_tree.insert(parent='', index='end', iid=None,
                                values=(packet.p_type, packet.src_addr, packet.dest_addr,
                                        packet.src_port, packet.dest_port))
        raw_tree.yview_moveto(1)
        if len(display_packet_details) > 1200:
            del display_packet_details[0:200]
    elif not enable_raw_view:
        if not tree_hidden:
            raw_packet_window.withdraw()
            raw_tree.pack_forget()
        tree_hidden = True
    packets_displayed = len(display_packet_details)
    raw_packet_window.update()
