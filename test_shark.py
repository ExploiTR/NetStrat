import re
import pyshark
import subprocess
import netifaces
from PackDetail import PackDetail

cmd = ["C:\\Program Files\\Wireshark\\dumpcap.exe", '-D']
shark_interfaces = subprocess.run(cmd, stdout=subprocess.PIPE).stdout.decode("utf-8")
shark_interfaces = shark_interfaces.split("\n")

usable_interfaces = dict()

for any_interface in shark_interfaces:
    if "{" not in any_interface or "(" not in any_interface:
        continue
    us_index = any_interface.index("\\")
    br_index = any_interface.index("(")
    interface = any_interface[us_index: br_index - 1]
    interface_name = re.sub("[\r*()]", "", any_interface[br_index: len(any_interface)])
    usable_interfaces[interface_name] = interface

detail = PackDetail()


def process_packet(pack):
    for layer in pack.layers:
        if layer.layer_name == 'ip':
            detail.src_addr = layer.src_host
            detail.dest_addr = layer.dst_host
        elif layer.layer_name == 'tcp':
            detail.p_type = 'tcp'
            detail.src_port = layer.srcport
            detail.dest_port = layer.dstport
        elif layer.layer_name == 'udp':
            detail.p_type = 'udp'
            detail.src_port = layer.srcport
            detail.dest_port = layer.dstport

    '''''
    Better performance wise but can raise : AttributeError: No attribute named ip

    detail.src_addr = packet.ip.src
    detail.dest_addr = packet.ip.dst
    detail.p_type = packet.transport_layer
    detail.src_port = packet[packet.transport_layer].srcport
    detail.dest_port = packet[packet.transport_layer].dstport
    '''''

    print(detail)


using_interface = usable_interfaces["Ethernet"]
ip = netifaces.ifaddresses(using_interface.split("_")[1])[netifaces.AF_INET][0]['addr']
capture = pyshark.LiveCapture(interface=using_interface)
for packet in capture.sniff_continuously():
    process_packet(packet)
