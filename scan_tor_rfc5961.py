#!/usr/bin/env python

from scapy.all import *
from multiprocessing import Process, Queue
import sys
import time
import copy
import argparse


# Handles the initial TCP handshake
class TcpHandshake(object):
    def __init__(self, target):
        self.handshake_timeout = 4
        self.seq = 0
        self.seq_next = 0
        self.target = target
        self.dst = target[0]
        self.dport = target[1]
        self.sport = random.randrange(2**15, 2**16)
        self.l4 = IP(dst=target[0]) / TCP(sport=self.sport, dport=self.dport, flags=0, seq=random.randrange(0, 2 ** 32))
        self.src = self.l4.src
        self.swin = self.l4[TCP].window
        self.dwin = 1
        self.alive = False
        self.next_srv_ack = 0

    def handle_recv(self, pkt):
        if pkt and pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[TCP].flags & 0x3f == 0x18:  # PSH+ACK
                self.next_srv_ack = pkt.seq + len(pkt[Raw])
                return
            elif pkt[TCP].flags & 4 != 0:  # RST
                return
            elif pkt[TCP].flags & 0x1 == 1:  # FIN
                return self.send_finack(pkt)
            elif pkt[TCP].flags & 0x3f == 0x10:  # FIN+ACK
                return self.send_ack(pkt)
        return None

    def do_handshake(self):
        self.l4[TCP].flags = "S"
        self.seq_next = self.l4[TCP].seq + 1
        response = sr1(self.l4, verbose=False, timeout=self.handshake_timeout)
        self.l4[TCP].seq += 1
        if response and response.haslayer(IP) and response.haslayer(TCP):
            if response[TCP].flags & 0x3f == 0x12:  # SYN+ACK
                self.l4[TCP].ack = response[TCP].seq + 1
                self.l4[TCP].flags = "A"
                self.seq_next = self.l4[TCP].seq
                self.synack_ack_seq_next = self.seq_next
                send(self.l4, verbose=False)
                self.next_srv_ack = response.seq + 1
                return True
            elif response[TCP].flags & 4 != 0:  # RST
                print "Connection refused: %s %s" % (self.dst, self.dport)
                return False
            else:
                print "Connection handshake failure: invalid TCP state"
        else:
            print "Connect timeout: %s %s" % (self.dst, self.dport)
        return False

    def send_fin(self):
        self.l4[TCP].flags = "FA"
        self.l4[TCP].seq = self.synack_ack_seq_next
        self.l4[TCP].ack = self.next_srv_ack
        response = sr1(self.l4, verbose=False, timeout=self.handshake_timeout)
        return self.handle_recv(response)

    def send_finack(self, pkt):
        self.l4[TCP].flags = "FA"
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.seq_next = self.l4[TCP].seq + 1
        response = send(self.l4, verbose=False)
        self.l4[TCP].seq += 1

    def send_ack(self, pkt):
        self.l4[TCP].flags = "A"
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.seq_next = self.l4[TCP].seq + 1
        send(self.l4, verbose=False)
        self.l4[TCP].seq += 1

    def send_bulk(self, pcount):
        self.l4[TCP].sport = self.sport
        self.l4[TCP].flags = "R"
        self.l4[TCP].seq = self.seq_next + 666
        send(self.l4 / '.', count=pcount, verbose=False)

# Sniffs for packets, threaded.
class sniffer():
    def __init__(self, server_ip, server_seq, q, timeout=5):
        """Capture packets with specified source IPv4 address and TCP Sequence number,
        put packets into multiprocessing queue.
        """
        self.server_ip = server_ip
        self.q = q
        self.seq = server_seq
        self.ca = 0
        self.timeout = timeout

    def sniffs(self):
        build_filter = lambda (r): TCP in r and IP in r and r[IP].src == self.server_ip and r[TCP].seq == self.seq
        ca = sniff(lfilter=build_filter, timeout=self.timeout)
        self.q.put(len(ca))

    def run(self):
        self.run = Process(target=self.sniffs)
        self.run.start()


BUCKETS = {
    "r == 0" : "zero challenge ACKs",
    "0 < r <= 10" : "probably new kernel",
    "10 < r <= 20" : "maybe new kernel?",
    "20 < r <= 90" : "inconclusive?",
    "90 < r < 100" : "probably vulnerable",
    "(r%100)==0 and 0<r<500" : "almost definitely vulnerable",
    "(r%100)!=0 and 100<r<450" : "probably vulnerable",
    "(r%100)!=0 and 450<=r<=490" : "inconclusive?",
    "490 < r < 500" : "most likely applied sysctl workaround",
    "r == 500" : "probably applied sysctl workaround",
    "500 < r" : "extra duplicate packets?",
}

def bucket(r, buckets=BUCKETS):
    res = None
    for constraints in buckets.keys():
        if eval(constraints):
            assert res == None, "%s landed in multiple buckets, first %s then %s, fix your bucket definitions!" % (r, res, bucket)
            res = buckets[constraints]
    assert res != None, "%s didn't land in any bucket" % (r,)
    return res

def probe_for_global_counter(tcp_hs, server_ip, server_port, server_seq):
    q = Queue()
    x = sniffer(server_ip, server_seq, q)
    x.run()

    probe_count = 500 # number of probe packets (in-window TCP RST packets)
    start = time.time()
    tcp_hs.send_bulk(probe_count)
    stop = time.time()

    # wait for results
    received = q.get()
    time_diff = stop - start
    verdict = bucket(received)

    print "%s,%s,%s,%s,%s,%s" % (server_ip, server_port, verdict, time_diff, probe_count, received)
    return time_diff

def tcp_handshake_probe_close(server_ip, server_port):
    # perform a tcp handshake, retry max 3 times
    # send probes
    # close connection
    max_handshake_retry = 3
    for i in range(max_handshake_retry):
        tcp_hs = TcpHandshake((server_ip, server_port))
        handshake_success = tcp_hs.do_handshake()
        if not handshake_success:
            pass
        else:
            break
    if not handshake_success:
        return
    probe_duration = probe_for_global_counter(tcp_hs, server_ip, server_port, tcp_hs.next_srv_ack)
    tcp_hs.send_fin()
    return probe_duration

def main():
# receive one relay ip address and tcp port per line of stdin
    for line in sys.stdin:
        host, port = line.split()
        probe_duration = tcp_handshake_probe_close(host, int(port))
        # XXX todo: retry probe if probe_duration deviates past a certain threshold.
        # question: what does this protect against? the local write buffer being full
        # and the write syscall to the socket blocking longer than it should?

if __name__ == "__main__":
    if sys.version_info > (3, 0):
        sys.exit('Script built for Python2.7. You are using 3.0 or greater.')

    main()
