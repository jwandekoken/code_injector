import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    packet[scapy.Raw].load = str(load)
    # remove the len and chksum from the ip layer and the chksum from the TCP layer (scapy will calculate it automatically for us)
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # if destination port == 80 (http port), it is a request
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            # remove Accept-Encoding field
            modified_load = re.sub(
                "Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load.decode()
            )
            new_packet = set_load(scapy_packet, modified_load)
            print(new_packet.show())
            packet.set_payload(new_packet.build())
            # packet.set_payload(bytes(new_packet))

        # if source port == 80 (http port), it is a response
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            print(scapy_packet.show())
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
