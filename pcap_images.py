"""pcap_images.py
   script to find image files present in http requests
   uses regular expression to identify image files
   stores the images and their URIs in lists and create a table
   output generated with tabulate
"""
import regex as re
import os
import dpkt
from tabulate import tabulate


def find_images(packet_list: list[tuple]) -> str:
    """
    search https request data for image files (.png|.gif|.jpg)
    keep lists of image file names and their associated URIs

    create a table do display all image files found along with their full URIs
    :param packet_list: list of (packet_timestamp, packet_bytes) tuples
    :return: table with all image files found along with their full URIs
    """
    images = []
    uris = []
    for (unused_timestamp, eth) in packet_list:
        try:
            ip = eth.data
            tcp = ip.data
            dport = tcp.dport
        # skips packets with no ports specified (e.g. IGMP) or no transport layer (e.g. ARP)
        except AttributeError:
            continue

        if dport == 80 and len(ip.data) > 0:
            try:
                http = dpkt.http.Request(tcp.data)
                image = re.search(r'([a-zA-Z0-9-_]+\.(gif|png|jpg))', http.uri, re.IGNORECASE)

                # true when image is found
                if image:
                    # remove the query portion of the uri
                    uri = http.uri.split('?')[0]
                    # isolate file name from uri
                    image = os.path.basename(uri)

                    # build full URI
                    full_uri = "http://" + http.headers["host"] + uri
                    uris.append(full_uri)
                    images.append(image)
            except dpkt.UnpackError:
                continue

    return build_image_table(images, uris)


def build_image_table(images: list, uris: list) -> str:
    """
    from a list of image files and URIs create a table
    one row for each image and the associated uri
    :param images: list of all images found in http requests
    :param uris: list of uris associated with images
    :return: table for images and URIs
    """
    headers = ['Image File',
               'Full Image URI'
               ]

    # create list of rows for the table
    rows = create_rows(images, uris)

    # if no images are found rows will be empty
    if not rows:
        return '[!] No Images Found!'

    # return table of images found and their full URIs
    return tabulate(rows, headers=headers, tablefmt='pretty', stralign='left')


def create_rows(images, uris):
    """
    turn two lists of images files and URIs into one list of rows
    :param images: list of image files
    :param uris: list of URIs associated with image files
    :return: list of rows with image name and associated URI
    """
    number_of_images = len(images)
    rows = []
    # add each image and URI to list of rows which will be used in table
    for i in range(number_of_images):
        rows.append((images[i], uris[i]))

    return rows
