"""pcap_summary.py
   script to create create a summary table from a pcap file
   one row represents one type of protocol
   output generated with tabulate
"""
import datetime
from tabulate import tabulate


def protocol_info(packet_list: list[tuple]) -> dict[str, dict]:
    """
    Using a list of tuples with timestamp and packet data
    return a formatted output with information about each
    protocol type in the list of packets
    :param packet_list: list of (packet_timestamp, packet_bytes) tuples
    :return: a dictionary with summary information for each protocol
    """
    # dictionary to store attributes of each protocol
    protocols = {}

    for (timestamp, eth) in packet_list:
        ip_layer = eth.data
        # get protocol name from packet
        try:
            # protocol from ip layer
            proto = ip_layer.get_proto(ip_layer.p).__name__
        except AttributeError:
            try:
                # get protocol from ethernet layer if packet has no ip layer
                proto = eth.get_type(eth.type).__name__
            # if get_type fails to find protocol name use protocol number (e.g. LLDP = 35020)
            except KeyError:
                proto = eth.type

        update_protocols(protocols, len(eth), proto, timestamp)

    return protocols


def update_protocols(protocols: dict[str, dict], packet_size: int, protocol: str, timestamp: float) -> None:
    """
    add new protocol to protocols dictionary
    updates info for a protocol in protocols dict
    :param protocols: dictionary key: protocol value: protocol summary info
    :param packet_size: size of packet
    :param protocol: name of protocol for packet
    :param timestamp: timestamp of packet
    """
    # convert timestamp to UTC format
    timestamp = datetime.datetime.utcfromtimestamp(timestamp)

    # set initial values in dictionary for new protocol
    protocols.setdefault(protocol, {'number': 0,
                                    'first': timestamp,
                                    'last': timestamp,
                                    'mean_size': 0,
                                    'sum_size': 0
                                    })

    # calculates attributes new values for a protocol
    protocols[protocol]['number'] += 1
    protocols[protocol]['last'] = timestamp
    protocols[protocol]['sum_size'] += packet_size
    new_mean = protocols[protocol]['sum_size'] / protocols[protocol]['number']
    protocols[protocol]['mean_size'] = new_mean


def protocol_table(protocols: dict[str, dict]) -> str:
    """
    create table from protocols dictionary
    :param protocols: dictionary of with summary info for each protocol
    :return: table information for each type of protocol
    """
    # list of headers for table
    headers = ['Type',
               'Number',
               'First Timestamp',
               'Last Timestamp',
               'Mean Packet size'
               ]
    # list to store each row of table
    rows = []

    # create a row for each type of protocol
    for (name, attributes) in protocols.items():
        # protocol type added to row
        row = [name]
        # add all attributes for each protocol to row
        for attribute in attributes:
            row.append((protocols[name][attribute]))
        # removes total_size since it is not used in output
        row.pop()
        # round mean_size as late as possible to reduces floating-point errors
        row[-1] = round(row[-1], 2)
        rows.append(row)

    return tabulate(rows, headers, tablefmt='pretty')
