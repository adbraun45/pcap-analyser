"""parse_pcap.py
   script to parse a pcap file with dpkt
   returns a list of (packet_timestamp, ethernet_layer) tuples
"""
import sys
import dpkt


def packet_list(pcap_file: str) -> list[tuple]:
    """
    read in a pcap file and return a list of tuples
    containing a packets timestamp and ethernet layer
    :param pcap_file: relative path to pcap file
    :return: list of (packet_timestamp, packet_bytes) tuples
    """
    try:
        with open(pcap_file, 'rb') as open_file:
            pcap = dpkt.pcap.Reader(open_file)
            packets = []
            # add timestamp and ethernet layer tuple from each packet to list
            for (timestamp, buf) in pcap:
                packet = timestamp, dpkt.ethernet.Ethernet(buf)
                packets.append(packet)
            return packets
    # specified file does not exist
    except FileNotFoundError as err:
        print(f'Exceptions ({err.__class__.__name__}): {err}', file=sys.stderr)
        sys.exit()
    # script cannot read file due to lack of permissions
    except PermissionError as err:
        print(f'Exceptions ({err.__class__.__name__}): {err}', file=sys.stderr)
        sys.exit()
    # file is not in the correct format
    except ValueError as err:
        print(f'Exceptions ({err.__class__.__name__}): {err}', file=sys.stderr)
        sys.exit()
