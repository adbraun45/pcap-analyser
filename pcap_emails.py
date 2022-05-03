"""pcap_emails.py
   script uses regular expressions to find any emails
   in To: and From: fields of the TCP data of a packet

   store lists of emails found in To: field and emails found in From: field
   uses both list to create a table for all emails found and in what field
   output generated with tabulate
"""
import regex as re
from tabulate import tabulate


def find_emails(packet_list: list[tuple]) -> str:
    """
    search TCP data for email addresses in To: and From: fields
    keep lists of emails found in each field

    create a table do display all emails found
    and which fields they were present in
    :param packet_list: list of (packet_timestamp, packet_bytes) tuples
    :return: table for all emails found and in what field
    """

    # lists to store emails found in each field
    emails_from = []
    emails_to = []

    # regular expression strings to find emails in To: and From: field
    # To/From: <{email}>
    from_regex = r'From:.+<((?:[a-zA-Z0-9](?:[\.-])?)+@(?:[a-zA-Z0-9](?:[\.-])?)+[a-zA-Z0-9]+)>'
    to_regex = r'To:.+<((?:[a-zA-Z0-9](?:[\.-])?)+@(?:[a-zA-Z0-9](?:[\.-])?)+[a-zA-Z0-9]+)>'

    for (unused_timestamp, eth) in packet_list:
        ip = eth.data
        try:
            protocol = ip.p
            # check if protocol is TCP
            if protocol == 6:
                tcp = ip.data
                decoded_tcp_data = tcp.data.decode('utf-8', errors='replace')

                # search tcp data for emails in From: field
                match = re.search(from_regex, decoded_tcp_data)
                # if emails has not been found before add to list
                if match and match.group(1) not in emails_from:
                    emails_from.append(match.group(1))

                # search tcp data for emails in To: field
                match = re.search(to_regex, decoded_tcp_data)
                # if emails has not been found before add to list
                if match and match.group(1) not in emails_to:
                    emails_to.append(match.group(1))
        # packets without ip layer are skipped (e.g. ARP)
        except AttributeError:
            continue

    return build_email_table(emails_from, emails_to)


def build_email_table(emails_from: list[str], emails_to: list[str]) -> str:
    """
    from a list of recipient emails and sender emails create a table
    one row for each unique email and what fields it was found in
    :param emails_from: list of emails in From: field
    :param emails_to: list of emails in To: field
    :return: table for unique emails found and fields it was found in
    """
    # list of headers for table
    headers = ['Email Address',
               'In From:',
               'In To:'
               ]

    # create list of rows for the table
    rows = create_rows(emails_from, emails_to)

    # if no emails are found rows will be empty
    if not rows:
        return '[!] No Email Addresses Found!'

    # return table of emails found
    return tabulate(rows, headers, tablefmt='pretty')


def create_rows(emails_from: list, emails_to: list) -> list[tuple]:
    """
    turn two lists of emails into one list with no duplicate emails
    :param emails_from: list of emails found in From: field
    :param emails_to: list of emails found in To: field
    :return: list of rows with email and fields it was found in
    """
    rows = []
    yes = 'Y'
    no = 'N'
    # possible row configurations
    # (email, 'Y', 'N') only in From:
    # (email, 'N', 'Y') only in To:
    # (email, 'Y', 'Y') in To: and From:

    # loop through emails found in From: field
    for email in emails_from:
        rows.append((email, yes, no))

    # loop through emails found in To: field
    for email in emails_to:
        for row_num, row in enumerate(rows):
            # if email already has a row both values are ✔
            if email == row[0]:
                rows[row_num] = (email, yes, yes)
                index = emails_to.index(email)
                # set email to None, so it isn't duplicated in next step
                emails_to[index] = None

    # loop through emails found in To: field
    for email in emails_to:
        # if email has not been set to None it was only present in emails_to
        if email:
            rows.append((email, no, yes))

    return rows
