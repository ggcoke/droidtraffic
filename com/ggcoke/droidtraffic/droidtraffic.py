#!/usr/bin/env python
#-*-coding:utf-8 -*-

import subprocess
import re
import sys
import curses
import traceback
from subprocess import Popen, PIPE, STDOUT

PACKAGE_NAME_WITHOUT_INODE = "package_without_inode"

TRAFFIC_DEBUG = False

stdscr = curses.initscr()

## Display output as table
def set_win():
    global stdscr

    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.noecho()
    curses.cbreak()

    stdscr.nodelay(1)
    stdscr.border(0)

def unset_win():
    global stdscr

    curses.nocbreak()
    curses.echo()
    curses.endwin()

def show_result(tcp_package_infos, color_pair=1):
    global stdscr
    stdscr.erase()

    stdscr.addstr(1, 2, "UID", curses.color_pair(color_pair))
    stdscr.addstr(1, 16, "Package Name", curses.color_pair(color_pair))
    stdscr.addstr(1, 38, "Data Send", curses.color_pair(color_pair))
    stdscr.addstr(1, 55, "Data Recv", curses.color_pair(color_pair))
    stdscr.addstr(1, 70, "Data Total", curses.color_pair(color_pair))
    # stdscr.addstr(1, 80, "Remote Server", curses.color_pair(color_pair))

    if (tcp_package_infos == None or len(tcp_package_infos) == 0):
        stdscr.refresh()
        return

    line = 2
    remote_server_without_inode = ''
    for (package_name, traffic_info) in tcp_package_infos.iteritems():
        if (package_name == PACKAGE_NAME_WITHOUT_INODE):
            remote_server_without_inode = str(traffic_info.remote_server)

        stdscr.addstr(line, 1, str(traffic_info.package_uid).center(6), curses.color_pair(color_pair))
        stdscr.addstr(line, 7, package_name[0:31].center(32), curses.color_pair(color_pair))
        stdscr.addstr(line, 38, str(traffic_info.traffic_send).center(10), curses.color_pair(color_pair))
        stdscr.addstr(line, 55, str(traffic_info.traffic_recv).center(10), curses.color_pair(color_pair))
        stdscr.addstr(line, 70, str(traffic_info.traffic_send + traffic_info.traffic_recv).center(10), curses.color_pair(color_pair))
        # stdscr.addstr(line, 80, str(traffic_info.remote_server), curses.color_pair(color_pair))
        line += 1

    if (len(remote_server_without_inode) > 0):
        stdscr.addstr((line + 1), 1, "Traffic for packages without inode:", curses.color_pair(color_pair))
        stdscr.addstr((line + 2), 1, remote_server_without_inode, curses.color_pair(color_pair))
    stdscr.refresh()

def exec_adb_shell(cmd):
    proc = subprocess.Popen(["adb", "shell", cmd], stdout=subprocess.PIPE, shell=False)
    return proc.communicate()

def get_interface():
    IGNORE_INTERFACES = ('lo', 'p2p0')
    out, err = exec_adb_shell("cat /proc/net/if_inet6")
    outputlines = out.split("\n")
    for line in outputlines:
        line = line.strip()
        if (not len(line)):
            continue
        line_split = re.split("\ +", line)
        interface = line_split[-1]

        ignore = False
        for ignore_interface in IGNORE_INTERFACES:
            if ignore_interface == interface:
                ignore = True
                break
        if ignore:
            continue
        return interface
    return None

def get_current_interface_ip():
    interface = get_interface()
    if interface ==None:
        return None
    out, err = exec_adb_shell("ifconfig " + interface)
    out_fields = re.split("\ +", out.strip().split("\n")[0])
    if out_fields[1] != "ip":
        return None
    return interface, out_fields[2]

#class NetworkDevicesException(BaseException):
#    def __init__(self, msg):
#        self.message = msg
#    def  __str__(self):
#        return repr(self.value)

class Singleton(object):
    _instance = None
    def __new__(class_, *args, **kwargs):
        if not isinstance(class_._instance, class_):
            class_._instance = object.__new__(class_, *args, **kwargs)
        return class_._instance

class TcpPacket(object):
    def __init__(self):
        self.time = ""
        self.local_port = 0
        self.remote_ip = ""
        self.remote_port = 0
        self.length = 0
        self.send = False

    def __str__(self):
        if self.send:
            direction = 'send'
        else:
            direction = 'recv'

        return "time:%s\nlocal_port:%d\tremote_ip:%s\tremote_port:%d\ndirection:%s\nlength:%d" % (
                self.time,
                self.local_port,
                self.remote_ip,
                self.remote_port,
                direction,
                self.length)

class TcpDumpWraper(Singleton):
    def parse_tcp_dumpLine(self, line):
        fields = re.split("\ +", line.strip())
        if fields[1] != "IP":
            return None

        length = fields[-1]
        if length == '0':
            return None

        tcp_packet = TcpPacket()

        tcp_packet.time = fields[0]
        tcp_packet.length = int(length)

        source_ip_port = fields[2].rsplit(".", 1)
        target_ip_port = fields[4].rsplit(".", 1)
        target_ip_port[1] = target_ip_port[1][:-1]

        if source_ip_port[0] == self.local_ip:
            tcp_packet.send = True
            tcp_packet.local_port = int(source_ip_port[1])
            tcp_packet.remote_ip = target_ip_port[0]
            tcp_packet.remote_port = int(target_ip_port[1])
        else:
            tcp_packet.send = False
            tcp_packet.local_port = int(target_ip_port[1])
            tcp_packet.remote_ip = source_ip_port[0]
            tcp_packet.remote_port = int(source_ip_port[1])
        return tcp_packet

    def __init__(self):
        self.listeners = []

    def register(self, listener):
        self.listeners.append(listener)

    def unregister(self, listener):
        self.listeners.remove(listener)

    def start(self):
        #raise NetworkDevicesException("Network device is not ready!")
        if len(self.listeners) < 1:
            print "Not any listener!"
            return

        interface_ip = get_current_interface_ip()
        if interface_ip == None:
            print "Network device is not ready!"
            sys.exit(1)
        self.local_ip = interface_ip[1]
        cmd = "tcpdump -i %s -nn tcp" % interface_ip[0]
        p = subprocess.Popen(["adb", "shell", cmd], stdout=subprocess.PIPE, shell=False)
        while True:
            line = p.stdout.readline()
            if line == '':
                break
            #packet =
            #print "testing!!!  ", line
            tcp_packet = self.parse_tcp_dumpLine(line)
            if tcp_packet != None:
                self.post(tcp_packet)

        print "Exit!"


    def post(self, tcp_packet):
        for listener in self.listeners:
            listener.onEvent(tcp_packet)

class TrafficStatListener(object):
    def __init_(self):
        pass

    def onEvent(self, tcp_packet):
        print "*************** TrafficStatListener begin ****************"
        print tcp_packet
        print "############### TrafficStatListener end ##################"

class TrafficStatListener2(object):
    def __init_(self):
        pass

    def onEvent(self, tcp_packet):
        print "------------ TrafficStatListener2 begin -----------------"
        print tcp_packet
        print "------------ TrafficStatListener2 end -------------------"


class PackageTrafficInfo:
    package_name = ''
    package_uid = 0
    traffic_send = 0
    traffic_recv = 0
    remote_server = {}

    def __str__(self):
        return "package: %s\ntraffic_tx:%d\ntraffic_rx:%d\nremote_server:%s" % (
            self.package_name,
            self.package_uid,
            self.traffic_send,
            self.traffic_recv,
            self.remote_server
        )

    def __cmp__(self, other):
        return cmp(self.package_name, other.package_name)

class TcpStatRecord:
    src_ip = ''
    src_port = ''
    dest_ip = ''
    dest_port = ''
    traffic_uid = ''
    traffic_inode = ''

    def __init__(self, content):
        content_list = content.split()
        tmp_src_ip = content_list[1].split(':')[0]
        tmp_src_port = content_list[1].split(':')[1]
        tmp_dest_ip = content_list[2].split(':')[0]
        tmp_dest_port = content_list[2].split(':')[1]
        tmp_uid = content_list[7]
        tmp_inode = content_list[9]
        self.__format(tmp_src_ip, tmp_src_port, tmp_dest_ip, tmp_dest_port, tmp_uid, tmp_inode)

    def __format(self, src_ip, src_port, dest_ip, dest_port, traffic_uid, traffic_inode):
        self.src_ip = self.__convert_ip(src_ip)
        self.src_port = str(int(src_port, 16))
        self.dest_ip = self.__convert_ip(dest_ip)
        self.dest_port = str(int(dest_port, 16))
        self.traffic_uid = traffic_uid
        self.traffic_inode = traffic_inode

    def __convert_ip(self, src):
        result = []
        normal_order_ip = src.replace('0000000000000000FFFF0000', '')
        for i in range(0, 4):
            ip_tmp = int(normal_order_ip[(2 * i):(2 * (i + 1))], 16)
            result.insert(0, str(ip_tmp))
        return '.'.join(result)

    def __str__(self):
        return "Tcp stat record:[src ip: %s, src port: %s, dest ip: %s, dest port:%s, uid: %s, inode: %s" % (
            self.src_ip, self.src_port, self.dest_ip, self.dest_port, self.traffic_uid, self.traffic_inode
        )

class PackageTrafficListener(TrafficStatListener):
    _dict_inode_pid = {}
    _dict_pid_package = {}
    _dict_package_traffic_info = {}
    _dict_tcp_package = {}
    _dict_tcp_package_without_inode = {}
    _dict_package_uid = {}

    _first = True

    def __init__(self):
        TrafficStatListener.__init__(self)
        self.__init_dicts_()

    def onEvent(self, tcp_packet):
        if (tcp_packet == None):
            # print "Tcp package is None."
            return

        # print "============================================= Tcp package received ===================================================".center(130)
        if (TRAFFIC_DEBUG):
            print tcp_packet

        if (self._first == True):
            self._first = False
            self.__update_tcp_package_dict()
        # 1. Build key used to find application package from tcp package
        tcp_key = self.__build_tcp_key(tcp_packet)
        if (tcp_key == None):
            # print("Build tcp key failed for " + tcp_packet)
            return

        # 2. Find package which has send or received the tcp package
        package_name = self.__find_package_from_tcp_package(tcp_key)
        if (package_name == None):
            package_name = PACKAGE_NAME_WITHOUT_INODE

        # 3. Update traffic info of the package
        if (self._dict_package_traffic_info.has_key(package_name) == False):
            info = PackageTrafficInfo()
            info.package_name = package_name
            info.traffic_recv = 0
            info.traffic_send = 0
            self._dict_package_traffic_info[package_name] = info

        traffic_info = self._dict_package_traffic_info.get(package_name)
        if (package_name == PACKAGE_NAME_WITHOUT_INODE):
            key = tcp_packet.remote_ip + ":" + str(tcp_packet.remote_port)
            if (traffic_info.remote_server.has_key(key)):
                traffic_info.remote_server[key] += tcp_packet.length
            else:
                traffic_info.remote_server[key] = tcp_packet.length
        else:
            traffic_info.remote_server = tcp_packet.remote_ip + ":" + str(tcp_packet.remote_port)

        if (tcp_packet.send == True):
            traffic_info.traffic_send += tcp_packet.length
        else:
            traffic_info.traffic_recv += tcp_packet.length

        if (self._dict_package_uid.has_key(package_name) == False):
            traffic_info.package_uid = 0
        else:
            traffic_info.package_uid = self._dict_package_uid[package_name]

        self.show_current_traffic()

    def show_current_traffic(self):
        show_result(self._dict_package_traffic_info)
        # if (self._dict_package_traffic_info == None or len(self._dict_package_traffic_info) == 0):
        #     print("No traffic available yet.")
        #     return
        # print("\r\n" + "Package".center(50) + "Data Send".center(20) + "Data Recv".center(20) + "Data Total".center(20) + "Remoute Server")
        # for (package_name, traffic_info) in self._dict_package_traffic_info.iteritems():
        #     print "%s%s%s%s%s" % (
        #         package_name.center(50),
        #         str(traffic_info.traffic_send).center(20),
        #         str(traffic_info.traffic_recv).center(20),
        #         str(traffic_info.traffic_send + traffic_info.traffic_recv).center(20),
        #         str(traffic_info.remote_server)
        #     )

    def __init_dicts_(self):
        self.__reset_tcp_package_dicts()
        self._dict_package_traffic_info.clear()

    def __reset_tcp_package_dicts(self):
        self._dict_inode_pid.clear()
        self._dict_pid_package.clear()
        self._dict_tcp_package.clear()
        self._dict_package_uid.clear()

    def __find_package_from_tcp_package(self, tcp_key):
        if (tcp_key == None):
            # print('Find package from tcp package failed because key is None')
            return None

        if (self._dict_tcp_package.has_key(tcp_key) == False):
            self.__update_tcp_package_dict()
        return self.__find_package_from_tcp_package_inner(tcp_key)

    def __find_package_from_tcp_package_inner(self, tcp_key):
        if (self._dict_tcp_package.has_key(tcp_key)):
            return self._dict_tcp_package.get(tcp_key)
        elif (self._dict_tcp_package_without_inode.has_key(tcp_key)):
            return self._dict_tcp_package_without_inode.get(tcp_key)
        return None

    def __update_tcp_package_dict(self):
        # self.__reset_tcp_package_dicts()

        # 1. Find current socket via cat /proc/net/tcp && cat /proc/net/tcp6
        traffic_list = []
        p = Popen('adb shell cat /proc/net/tcp', stdout=PIPE, stderr=STDOUT, shell=True)

        header_line = True
        for line in p.stdout:
            if (TRAFFIC_DEBUG):
                print line
            if (header_line == True):
                header_line = False
                continue
            t = TcpStatRecord(line)
            traffic_list.append(t)

        p = Popen('adb shell cat /proc/net/tcp6', stdout=PIPE, stderr=STDOUT, shell=True)
        header_line = True
        for line in p.stdout:
            if (TRAFFIC_DEBUG):
                print line
            if (header_line == True):
                header_line = False
                continue
            t = TcpStatRecord(line)
            traffic_list.append(t)

        # 2. Build open socket map
        self.__fetch_inode_list()

        # 3. Build process map
        self.__fetch_pid_list()

        for t in traffic_list:
            tcp_key = "%s_%s:%s" % (t.src_port, t.dest_ip, t.dest_port)

            if (int(t.traffic_inode) == 0):
                if (TRAFFIC_DEBUG):
                    print "traffic inode is 0 for key " + tcp_key + ", traffic is " + str(t)
                if (self._dict_tcp_package.has_key(tcp_key) == False):
                    self._dict_tcp_package_without_inode[tcp_key] = PACKAGE_NAME_WITHOUT_INODE
                    self._dict_package_uid[PACKAGE_NAME_WITHOUT_INODE] = t.traffic_uid
                continue

            if (self._dict_inode_pid.has_key(t.traffic_inode) == False):
                # print 'No such inode for tcp record: ' + str(t)
                continue
            pid = self._dict_inode_pid.get(t.traffic_inode)
            if (self._dict_pid_package.has_key(pid) == False):
                # print "No such process has pid " + pid + " for tpc record: " + str(t)
                continue
            package_name = self._dict_pid_package.get(pid)

            # print 'Find tcp key: ' + tcp_key + ", package is " + package_name
            self._dict_tcp_package[tcp_key] = package_name
            self._dict_package_uid[package_name] = t.traffic_uid

            if (self._dict_tcp_package_without_inode.has_key(tcp_key) == True):
                del self._dict_tcp_package_without_inode[tcp_key]

    def __build_tcp_key(self, tcp_package):
        return "%s_%s:%s" % (tcp_package.local_port, tcp_package.remote_ip, tcp_package.remote_port)

    def __fetch_inode_list(self):
        pattern = re.compile(r"socket:\[(\d+)\]")

        p = Popen('adb shell lsof', stdout=PIPE, stderr=STDOUT, shell=True)

        for line in p.stdout:
            result_list = line.split()
            match = pattern.match(result_list[-1])
            if (match == None):
                continue
            self._dict_inode_pid[match.group(1)] = result_list[1]
            if (TRAFFIC_DEBUG):
                print "Inode: %s, pid: %s" % (str(match.group(1)), str(result_list[1]))

    def __fetch_pid_list(self):
        p = Popen('adb shell ps', stdout=PIPE,
                  stderr=STDOUT, shell=True)

        for line in p.stdout:
            result_list = line.split()
            self._dict_pid_package[result_list[1]] = result_list[-1]
            if (TRAFFIC_DEBUG):
                print "Pid: %s, package: %s" % (str(result_list[1]), str(result_list[-1]))

if __name__ == "__main__":
    try:
        set_win()
        show_result(None)
        tdw = TcpDumpWraper()
        # tdw.register(TrafficStatListener())
        tdw.register(PackageTrafficListener())
        tdw.start()
    except Exception, e:
        # raise e
        traceback.print_exc()
    finally:
        unset_win()
