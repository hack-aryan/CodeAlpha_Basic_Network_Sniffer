
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import threading
import sys


def get_windows_interface_names():
    try:
        import winreg
    except ImportError:
        return {}
    iface_map = {}
    reg_path = r'SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as adapters:
            for i in range(0, 1000):
                try:
                    guid = winreg.EnumKey(adapters, i)
                    try:
                        with winreg.OpenKey(adapters, guid + r'\\Connection') as conn:
                            name, _ = winreg.QueryValueEx(conn, 'Name')
                            iface_map[guid] = name
                    except Exception:
                        continue
                except OSError:
                    break
    except Exception:
        pass
    return iface_map

# Analyze and display useful information from packets
def packet_callback(packet):
    
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
        payload = bytes(ip_layer.payload)
        payload_str = payload[:32].hex() if payload else 'None'
        print(f"[IP] {src_ip} -> {dst_ip} | Protocol: {proto_name} | Payload (hex): {payload_str}")
    else:
        print(f"[Other] {packet.summary()}")
    # Save full packet for later analysis
    with open("sniffed_packets.txt", "a") as f:
        f.write(packet.summary() + "\n" + str(packet.show(dump=True)) + "\n\n")

# Start sniffing
def sniff_packets(interface):
    print(f"[*] Starting packet sniffing on interface: {interface}")
    print("Press Ctrl+C to stop.")
    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopped sniffing.")

if __name__ == "__main__":
    print("Basic Network Sniffer - Learn how packets flow through the network!")
    interfaces = get_if_list()
    iface_map = {}
    if sys.platform.startswith('win'):
        iface_map = get_windows_interface_names()
    print("Available interfaces:")
    for idx, iface in enumerate(interfaces):
        # Try to extract GUID
        friendly = ''
        if sys.platform.startswith('win') and iface.startswith('\\Device\\NPF_'):
            guid = iface.split('_', 1)[-1].strip('{}')
            friendly = iface_map.get(guid, iface_map.get('{' + guid + '}', ''))
        if friendly:
            print(f"  [{idx}] {iface}  -->  {friendly}")
        else:
            print(f"  [{idx}] {iface}")
    while True:
        try:
            choice = int(input(f"Select interface number [0-{len(interfaces)-1}]: "))
            if 0 <= choice < len(interfaces):
                interface = interfaces[choice]
                break
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")
    sniff_packets(interface)