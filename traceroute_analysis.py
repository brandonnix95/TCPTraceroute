#!/usr/bin/env python
import sys


def getList(fileName):
    # loop and get the list
    dump_list = []
    with open(fileName) as tcp_dump:
        dump_list = tcp_dump.readlines()
    return dump_list


def find_occurence(string, occurence, n):
    start = string.find(occurence)
    while start >= 0 and n > 1:
        start = string.find(occurence, start + len(occurence))
        n -= 1
    return start


def analysis(dump_list):
    currentPos = 0
    validCheck = 0
    rtt = None
    comparison = None
    ip_address = None
    ip_addresses = []
    match = None
    for i in dump_list:
        # ip_addresses.append(ip_address)
        # print(ip_addresses)
        # print(line)
        ttl = None
        send_time = None
        receive_time = None
        packet_id = None
        line_analyzing = dump_list[currentPos]
        # see if there is an id in the line currently being looked at
        id_index = line_analyzing.index('id') if 'id' in line_analyzing else -1
        # print(id_index)
        if (id_index != -1):
            string_one_end = line_analyzing.index(', o') if ', o' in line_analyzing else -1
            ttl_index = line_analyzing.index('ttl') if 'ttl' in line_analyzing else -1
            string_two_end = line_analyzing.index(', i') if ', i' in line_analyzing else -1
            ip_index = line_analyzing.index('IP') if 'IP' in line_analyzing else -1
            packet_id = line_analyzing[id_index:string_one_end].rstrip()
            # print(packet_id)
            ttl = line_analyzing[ttl_index:string_two_end].rstrip()
            send_time = line_analyzing[:ip_index].rstrip()
            # print(send_time)
        for j in range(currentPos + 1, len(dump_list)):
            # print ("J", j)
            # print(len(dump_list))
            # print(currentPos)
            # print("J",j)
            comparison = dump_list[j]
            second_id_index = comparison.index('id') if 'id' in comparison else -1
            new_one_end = comparison.index(', o') if ', o' in comparison else -1
            # print(comparison_id)
            if (second_id_index != -1):
                comparison_id = comparison[second_id_index:new_one_end].rstrip()
                if (comparison_id == packet_id and packet_id != "id 0"):
                    match = True
                    icmp_line = dump_list[j - 1]
                    front_splice_point = find_occurence(icmp_line, ')', 2) + 1
                    back_splice_point = icmp_line.index(' >') if ' >' in icmp_line else -1
                    new_ip_index = icmp_line.index('IP') if 'IP' in icmp_line else -1
                    # print(splice_point)
                    ip_address = icmp_line[front_splice_point:back_splice_point].strip()
                    ip_addresses.append(ip_address)
                    receive_time = icmp_line[:new_ip_index].strip()
                    # print(validCheck)

                    try:
                        rtt = float(receive_time) - float(send_time)
                    except ValueError:
                        print("UH-OH, IT BROKE")
                    rtt = rtt * 1000
                    rtt = round(rtt, 3)
                    if (validCheck == 0):
                        print(ttl)
                        print(ip_address)
                        print(rtt, "ms")
                        validCheck = validCheck + 1
                    elif (validCheck != 0 and validCheck % 3 == 0):
                        print("==================")
                        print(ttl)
                        print(ip_address)
                        print(rtt, "ms")
                        validCheck = validCheck + 1
                    else:
                        print(rtt, "ms")
                        validCheck = validCheck + 1
                else:
                    match == False

            if (match == False and comparison_id != 0 and 'cksum' in line_analyzing):
                if (validCheck == 0):
                    print(ttl)
                    print("*")
                    validCheck = validCheck + 1
                elif (validCheck != 0 and validCheck % 3 == 0):
                    print("---------")
                    print(ttl)
                    print("*")
                    validCheck = validCheck + 1
                else:
                    print("*")
                    validCheck = validCheck + 1

        currentPos = currentPos + 1
    print(
        "If a TTL that was sent does not appear, no response was indicated by the files. All RTTs(as stated in the directions, traceroute measures to an intermediate node) that were present are calculated.")


def main():
    file = sys.argv[1]
    list = getList(file)
    analysis(list)


if __name__ == '__main__':
    main()
