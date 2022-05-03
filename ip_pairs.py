"""ip_pairs.py
   script to count the packets send to/from each source and destination IP pair
   pairs and number of packets stored in dictionary which can be printed
   as a table ordered by number of packets send from largest to smallest
   output generated with tabulate
"""
import socket
import dpkt
from tabulate import tabulate


def find_ip_pairs(packet_list: list[tuple]) -> dict[str, int]:
    """
    Find all IPv4 source and destination pairs and count packets send To/From the pairs
    store number of packets send between pairs in a dictionary
    :param packet_list: list of (packet_timestamp, packet_bytes) tuples
    :return:
    """
    ip_pairs = {}

    for unused_timestamp, eth in packet_list:
        # skips non IPv4 packets which causes an errors
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data

        # convert source and destination IP to human-readable strings
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)

        # create key from src and dst
        ip_pair_key = src + " -> " + dst

        ip_pairs.setdefault(ip_pair_key, 0)
        # increment packets from that key
        ip_pairs[ip_pair_key] += 1

    return ip_pairs


def print_ip_pairs_ordered(ip_pairs: dict[str, int]) -> None:
    """
    Prints the source and destination IP pair and the number of packets sent
    to/from that pair, ordered by number of packets sent largest to smallest
    :param ip_pairs:
    """
    headers = ['Source -> Destination IP',
               'Packets']
    rows = []

    # creates a list of tuples containing a key and number of packets from ip_pairs
    key_num = [(key, ip_pairs[key]) for key in ip_pairs]
    # sort the list by number of packets then key from largest to smallest
    key_num = sorted(key_num, key=lambda kn: [kn[1], kn[0]], reverse=True)

    for key, num_of_packets in key_num:
        rows.append([key, num_of_packets])

    print(tabulate(rows, headers, tablefmt='pretty'))
