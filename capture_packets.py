import pyshark
import pandas as pd

packet_data = []

def sniff_traffic(net_iface):
    try:
        live_stream = pyshark.LiveCapture(interface=net_iface, display_filter='ip and tcp')

        print(f"Listening for TCP packets on {net_iface}...")

        for pkt in live_stream.sniff_continuously():
            try:
                pkt_details = {}

                if 'IP' in pkt:
                    pkt_details['Source IP'] = pkt.ip.src
                    pkt_details['Destination IP'] = pkt.ip.dst
                    pkt_details['TTL'] = pkt.ip.ttl
                    pkt_details['IP Flags'] = pkt.ip.flags

                    print(f"IP Packet: {pkt_details['Source IP']} -> {pkt_details['Destination IP']} (TTL: {pkt_details['TTL']}, Flags: {pkt_details['IP Flags']})")

                if 'TCP' in pkt:
                    pkt_details['Source Port'] = pkt.tcp.srcport
                    pkt_details['Destination Port'] = pkt.tcp.dstport
                    pkt_details['TCP Flags'] = pkt.tcp.flags
                    pkt_details['Acknowledgment Number'] = pkt.tcp.ack
                    pkt_details['Sequence Number'] = pkt.tcp.seq
                    pkt_details['Window Size'] = pkt.tcp.window_size
                    pkt_details['Data Offset'] = pkt.tcp.hdr_len
                    pkt_details['Packet Length'] = pkt.length

                    print(f"TCP Packet: {pkt_details['Source Port']} -> {pkt_details['Destination Port']} (Flags: {pkt_details['TCP Flags']})")

                packet_data.append(pkt_details)

            except AttributeError:
                continue

    except KeyboardInterrupt:
        print("\nCapture terminated by user.")
    except Exception as err:
        print(f"Error occurred: {err}")

def export_to_excel():
    df_packets = pd.DataFrame(packet_data)

    df_packets.to_excel('captured_packets.xlsx', index=False, columns=[
        'Source IP', 'Destination IP', 'TTL', 'IP Flags',
        'Source Port', 'Destination Port', 'TCP Flags',
        'Acknowledgment Number', 'Sequence Number', 'Window Size',
        'Data Offset', 'Packet Length'
    ])

    print("Captured data saved to 'captured_packets.xlsx'.")

if __name__ == "__main__":
    iface = "Wi-Fi"
    sniff_traffic(iface)
    export_to_excel()
