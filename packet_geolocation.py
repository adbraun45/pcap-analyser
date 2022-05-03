"""packet_geolocation.py
   script to find geolocation of all valid destination IPv4 addresses
   and number of packets send to that IP in list of packets

   using geoip2.database to get geolocation from IP
   create a KML file with a point for each IP
   point description contains city, country and packet send to that IP
"""
import socket
import dpkt
import simplekml
import geoip2.database
from geoip2.errors import AddressNotFoundError


def packet_geolocation(packet_list: list[tuple], file_name: str) -> str:
    """
    find geolocation information of valid IPv4 addresses
    create a KML file with information found about each address
    :param packet_list: list of (packet_timestamp, packet_bytes) tuples
    :param file_name: name of KML file
    :return: string indicating success or failure finding any IP geolocations
    """
    ips = {}
    try:
        with geoip2.database.Reader(r"GeoLite2-City_20190129.mmdb") as reader:
            kml = simplekml.Kml()
            for unused_timestamp, eth in packet_list:
                # skip non-IPv4 packets
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                # get packets destination IP
                dst_ip = eth.data.dst
                # covert to human readable IP
                dst_ip = socket.inet_ntoa(dst_ip)

                # skip packets with invalid destination IPs (e.g. private IPs)
                try:
                    reader.city(dst_ip)
                except AddressNotFoundError:
                    continue

                # count number of packets for each destination ip
                ips.setdefault(dst_ip, 0)
                ips[dst_ip] += 1

                # if no geolocations are found
                if len(ips) == 0:
                    return "No valid IPs in pcap file"

            for (ip_address, packet_count) in ips.items():
                geo_info = reader.city(ip_address)

                # get longitude and latitude of IP
                long = geo_info.location.longitude
                lat = geo_info.location.latitude

                # if city name couldn't be found use Unknown
                if geo_info.city.name is None:
                    city = 'Unknown'
                else:
                    city = geo_info.city.name

                country = geo_info.country.name

                # add new point to kml file
                kml.newpoint(name=ip_address,
                             coords=[(long, lat)],
                             description=f"{ip_address}\n"
                                         f"City: {city}\n"
                                         f"Country: {country}\n"
                                         f"Packets: {packet_count}")
            kml.save(file_name)
            return f'Output Geolocation info to {file_name}'
    # when IP location database file not present
    except FileNotFoundError as err:
        return f'{err.__class__.__name__} IP location database "GeoLite2-City_20190129.mmdb"'
