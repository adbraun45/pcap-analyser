"""pcap_analyser.py
   Script to retrieve and generate info about packets from a pcap file

   Output:
   Summary of packets,
   find emails in TO: and FROM: fields,
   find image files in http requests,
   count packets send to/from IP pairs
   KML file with geolocation of valid destination IPs,
   graph of packets over time
"""

import os
import argparse
from parse_pcap import packet_list
from pcap_summary import protocol_info, protocol_table
from pcap_emails import find_emails
from pcap_images import find_images
from ip_pairs import find_ip_pairs, print_ip_pairs_ordered
from packet_geolocation import packet_geolocation
from pcap_plot import plot_packet_activity


def main() -> None:
    """
    process command line arguments for input and output file names
    and call functions to output pcap file information
    """
    parser = argparse.ArgumentParser(description='Process arguments '
                                                 'for input file')
    parser.add_argument('-i', '--input',
                        metavar='',
                        help='name of file to be read in')

    parser.add_argument('-o', '--output',
                        metavar='',
                        help='name kml file created')

    args = parser.parse_args()

    pcap_file_path = args.input
    kml_file = args.output

    # ask for user to give a file name if one wasn't given
    if pcap_file_path is None:
        pcap_file_path = input('Enter a pcap file to read: ')
    pcap_name = os.path.basename(pcap_file_path)
    if kml_file is None:
        # use pcap file name for kml file if one is not given
        kml_file = f'{pcap_name.split(".")[0]}'

    # append .kml to KML file name specified if not already present
    if any(extension not in kml_file for extension in ['.kml', '.KML']):
        kml_file += ".kml"

    packets: list[tuple] = packet_list(pcap_file_path)
    print(f'\nFile: {pcap_name} read successfully')

    print(f'\nBuilding table for {pcap_name} ...')
    protocols_dict = protocol_info(packets)
    print(protocol_table(protocols_dict))

    print(f'\nSearching for Emails in {pcap_name} ...')
    print(find_emails(packets))

    print(f'\nSearching for Image files in {pcap_name} ...')
    print(find_images(packets))

    print('\nCounting packets between Source and Destination IP pairs')
    ip_pairs = find_ip_pairs(packets)
    print_ip_pairs_ordered(ip_pairs)

    print(f'\nFinding Geolocation for all destination IPs in {pcap_name} ...')
    print(packet_geolocation(packets, kml_file))

    print(f'\nPlotting packet activity for {pcap_name} ...')
    plot_packet_activity(packets, pcap_name)


if __name__ == '__main__':
    main()
