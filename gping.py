#!/usr/bin/env python

__author__ = 'lomoalbert@gmail.com'


#todo l18n

from gi.repository import Gtk
from gi.repository import GObject
import os
import platform
import threading
import struct
import array
import time
import select
import binascii
import socket
# total size of data (payload)
ICMP_DATA_STR = 56
# initial values of header variables
ICMP_TYPE = 8
ICMP_TYPE_IP6 = 128
ICMP_CODE = 0
ICMP_CHECKSUM = 0
ICMP_ID = 0
ICMP_SEQ_NR = 0

global builder
GObject.threads_init()


class MyThread(threading.Thread):
    def __init__(self,ips,iplist):
        super(MyThread, self).__init__()
        self.ips=ips
        self.iplist=iplist

    def run(self):
        timeout=1
        size=64
        ipv6=False
        iplist=self.iplist
        pingSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        self.pinging = True
        while self.pinging:
            uplabel(self.ips)
            for start in range(len(iplist)):
                packet = _construct(start, size, ipv6) # make a ping packet
                pingSocket.sendto(packet,(iplist[start],1))
                self.ips[iplist[start]][0][4]+=1
            stime=time.time()
            while time.time()< (stime+timeout):
                iwtd, owtd, ewtd = select.select([pingSocket], [], [], timeout)
                if iwtd:
                    endtime=time.time()
                    pong, address = pingSocket.recvfrom(size+48)
                    rawPongHop = struct.unpack("s", pong[8])[0]
                    # convert TTL from 8 bit to 16 bit integer
                    pongHop = int(binascii.hexlify(str(rawPongHop)), 16)
                    # fetch pong header
                    pongHeader = pong[20:28]
                    pongType, pongCode, pongChksum, pongID, pongSeqnr = struct.unpack("bbHHh", pongHeader)
                    # fetch starttime from pong
                    starttime = struct.unpack("d", pong[28:36])[0]
                    print address,endtime-starttime,pongType, pongCode, pongChksum, pongID, pongSeqnr,pongHop
                    ip=address[0]
                    if self.ips.has_key(ip):
                        self.ips[ip][0][2]=round(1000*(endtime-starttime))
                        self.ips[ip][0][3]+=1
            for ip in self.iplist:
                self.ips[ip][0][1]=round(100-100.0*self.ips[ip][0][3]/max(self.ips[ip][0][4],1),2)

    def stop(self):
        self.pinging = False


def uplabel(ips,ip=None):
    if ip:
        for no in range(len(ips[ip][0])):
            ips[ip][no+1].set_text(str(ips[ip][0][no]))
    else:
        for ip in ips:
            for no in range(len(ips[ip][0])):
                ips[ip][no+1].set_text(str(ips[ip][0][no]))



def _construct(id, size, ipv6):
    """Constructs a ICMP echo packet of variable size
    """
    # size must be big enough to contain time sent
    if size < int(struct.calcsize("d")):
        _error("packetsize to small, must be at least %d" % int(struct.calcsize("d")))

    # construct header
    if ipv6:
        header = struct.pack('BbHHh', ICMP_TYPE_IP6, ICMP_CODE, ICMP_CHECKSUM, \
                             ICMP_ID, ICMP_SEQ_NR+id)
    else:
        header = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, ICMP_CHECKSUM, \
                             ICMP_ID, ICMP_SEQ_NR+id)
    # if size big enough, embed this payload
    load = "-- IF YOU ARE READING THIS YOU ARE A NERD! --"

    # space for time
    size -= struct.calcsize("d")
    # construct payload based on size, may be omitted :)
    rest = ""
    if size > len(load):
        rest = load
        size -= len(load)
    # pad the rest of payload
    rest += size * "X"
    # pack
    data = struct.pack("d", time.time()) + rest
    packet = header + data          # ping packet without checksum
    checksum = _in_cksum(packet)    # make checksum
    # construct header with correct checksum
    if ipv6:
        header = struct.pack('BbHHh', ICMP_TYPE_IP6, ICMP_CODE, checksum, \
                             ICMP_ID, ICMP_SEQ_NR+id)
    else:
        header = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, checksum, ICMP_ID, \
                             ICMP_SEQ_NR+id)
    # ping packet *with* checksum
    packet = header + data
    # a perfectly formatted ICMP echo packet
    return packet


def _in_cksum(packet):
    """THE RFC792 states: 'The 16 bit one's complement of
    the one's complement sum of all 16 bit words in the header.'
    Generates a checksum of a (ICMP) packet. Based on in_chksum found
    in ping.c on FreeBSD.
    """
    # add byte if not dividable by 2
    if len(packet) & 1:
        packet = packet + '\0'
    # split into 16-bit word and insert into a binary array
    words = array.array('h', packet)
    sum = 0
    # perform ones complement arithmetic on 16-bit words
    for word in words:
        sum += (word & 0xffff)
    hi = sum >> 16
    lo = sum & 0xffff
    sum = hi + lo
    sum = sum + (sum >> 16)

    return (~sum) & 0xffff # return ones complement


class Handler:
    def __init__(self):
        global builder
        self.builder=builder
        self.pinging=False
        self.ips={}
        self.iplist=[]
        self.iptuple=[]
        self.domain=[]
        self.pingcount=1
        self.t=None

    def onDeleteWindow(self, *args):
        if self.t:self.t.stop()
        Gtk.main_quit(*args)


    def clean(self):
        for domain in self.domain:
            domain.destroy()
        for ip in self.ips:
            for lable in self.ips[ip][1:]:
                lable.destroy()
        self.ips={}
        self.iplist=[]
        self.iptuple=[]

    def on_button1_clicked(self,button):
        self.clean()
        textview1=self.builder.get_object('textview1')
        buffer=textview1.get_buffer()
        iptext=buffer.get_text(buffer.get_start_iter(),buffer.get_end_iter(),1)
        for ip in iptext.split('\n'):
            try:
                if not ip:continue
                adress=socket.gethostbyname(ip)
                if self.ips.has_key(adress):continue
                self.ips[adress]=[]
                self.iptuple.append((ip,adress))
                self.iplist.append(adress)
            except:
                pass
        self.init_grid()
        uplabel(self.ips)


    def init_grid(self):
        self.grid=self.builder.get_object('grid1')
        row=0
        for ip,adress in self.iptuple:
            row+=1
            self.ips[adress].append([adress,0,0,0,0])
            label=Gtk.Label()
            label.set_text(ip)
            label.show()
            self.domain.append(label)
            self.grid.attach(label, 0, row, 1, 1)
            for com in range(1,6):
                label=Gtk.Label()
                self.grid.attach(label, com, row, 1, 1)
                label.show()
                self.ips[adress].append(label)


    def on_button2_clicked(self,button):
        pass


    def on_button3_clicked(self,button):
        if not self.t:
            self.t=MyThread(self.ips,self.iplist)
            button.set_label('Stop')
            self.t.start()
        else:
            button.set_label('ping continued')
            self.t.stop()
            self.t=None




builder = Gtk.Builder()
builder.add_from_file("mainwindow.glade")
builder.connect_signals(Handler())

if platform.system()=='Linux' and os.getuid() != 0:
    button3 = builder.get_object("button3")
    button3.set_sensitive(False)
    msg='You must be root.'
    statusbar = builder.get_object('statusbar1')
    statusbar.push(1,msg)

window = builder.get_object("window1")
window.show_all()

Gtk.main()
