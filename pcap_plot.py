"""pcap_plot.py
   script to plot a graph of packets over time from a list of packets
   calculate and add a threshold line to graph
   when graph is above this line indicates periods of heavy traffic
"""
from datetime import datetime
from math import floor
import matplotlib.pyplot as plt
from numpy import std, arange


def plot_packet_activity(packet_list: list[tuple], pcap_name: str) -> None:
    """
    plot graph of packets in list over a variable time interval
    and indicate when traffic was higher than calculated threshold
    :param packet_list: list of (packet_timestamp, packet_bytes) tuples
    :param pcap_name: name of pcap file packets came from
    """
    graph_name = pcap_name.split(".")[0]
    time_interval = 1.5

    # list to store number of packets in each time interval group
    time_group: list[int] = []
    # get the timestamp of the first packet
    first_ts = datetime.utcfromtimestamp(packet_list[0][0])

    for timestamp, unused_data in packet_list:
        current_ts = datetime.utcfromtimestamp(timestamp)
        ts_diff = current_ts - first_ts
        # convert difference between timestamps to seconds
        seconds = ts_diff.total_seconds()
        # calculate which group packet belongs to
        group_num = floor(seconds / time_interval)

        # group_num is used as an index to increment number of packets for that time interval group
        # since a time interval could have no packets that index could be out of range of the list
        # the while loop appends 0 to the list until the index is no longer out of range
        while True:
            try:
                time_group[group_num] += 1
                break
            except IndexError:
                time_group.append(0)

    # threshold calculated as mean packets per interval + 2 standard deviations
    threshold = sum(time_group) / len(time_group) + std(time_group) * 2

    y_axis = time_group
    # using arange allows for a non-integer time_interval
    x_axis = arange(0, len(y_axis) * time_interval, time_interval)

    plt.plot(x_axis, y_axis, "g", label=f"packets per {time_interval} sec")
    # add threshold line to graph
    plt.axhline(y=threshold, color='r', linestyle='-', label=f"Threshhold={round(threshold, 2)}")
    plt.xlabel(f"Seconds since: {first_ts}")
    plt.ylabel("Number of Packets")
    plt.legend()

    plt.savefig(graph_name)
    print(f'Graph Saved as {graph_name}.png')
    plt.show()
