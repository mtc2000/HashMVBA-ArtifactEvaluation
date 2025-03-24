from collections import defaultdict
from typing import List

from gevent import monkey
from gevent.event import Event

monkey.patch_all()

import time

import gevent
from gevent import Greenlet
from gevent.server import StreamServer
from gevent.queue import Queue

try:
    import cPickle as pickle
except ImportError:
    import pickle


# Sockets that route through Tor
import socket
import socks

_orig_print = print

def print(*args, **kwargs):
    _orig_print(*args, flush=True, **kwargs)

class QueueCollection:
    TIMEOUT = 0

    def __init__(self, queues):
        self.queues: List[Queue] = queues.copy()
        self.N = len(self.queues)
        self._get_queue = Queue()
        def _get_watcher(watched_queue: Queue, target_queue: Queue):
            # Watcher function to check if the queue is non-empty
            e = watched_queue.peek()  # blocking; avoid busy-waiting
            target_queue.put_nowait(e)

        self._get_threads = []
        for i in range(len(self.queues)):
            self._get_threads.append(gevent.spawn(_get_watcher, self.queues[i], self._get_queue))


    def get(self):
        return self._get_queue.get()


    def wait(self, k):
        if not (0 < k <= len(self.queues)):
            raise ValueError("Invalid value of k")

        non_empty_set = set()

        while True:
            for i in range(self.N):
                if i in non_empty_set: continue
                if self.queues[i].qsize() > 0:
                    non_empty_set.add(i)
                if len(non_empty_set) >= k:
                    return list(non_empty_set)
            gevent.sleep(QueueCollection.TIMEOUT)


    def wait_value(self, value, k):
        if not (0 < k <= len(self.queues)):
            raise ValueError("Invalid value of k")

        non_empty_set = set()
        matched_value_set = set()

        while True:
            for i in range(self.N):
                if i in non_empty_set: continue
                if self.queues[i].qsize() > 0:
                    non_empty_set.add(i)
                sender, received_value = self.queues[i].peek()
                if received_value == value:
                    matched_value_set.add(i)
                if len(matched_value_set) >= k:
                    return list(matched_value_set)
            gevent.sleep(QueueCollection.TIMEOUT)


    def get_value_at_least_k1_count_within_k2_count(self, k1, k2):
        queues = self.queues.copy()
        if not (0 < k1 <= k2 <= len(queues)):
            raise ValueError("Invalid value of k1 or k2")

        counter = defaultdict(set)
        non_empty_set = set()

        while True:
            for i in range(self.N):
                if i in non_empty_set: continue
                if self.queues[i].qsize() > 0:
                    non_empty_set.add(i)
                sender, received_value = self.queues[i].peek()
                counter[received_value].add(i)
                if len(counter[received_value]) >= k1:
                    return received_value, sorted(counter[received_value])
                if len(non_empty_set) >= k2:
                    return None, list()
            gevent.sleep(QueueCollection.TIMEOUT)


class QueueCollectionThreads:
    def __init__(self, queues):
        self.queues = queues.copy()
        self._get_queue = Queue()
        def _get_watcher(watched_queue: Queue, target_queue: Queue):
            # Watcher function to check if the queue is non-empty
            e = watched_queue.peek()  # blocking; avoid busy-waiting
            target_queue.put_nowait(e)

        self._get_threads = []
        for i in range(len(self.queues)):
            self._get_threads.append(gevent.spawn(_get_watcher, self.queues[i], self._get_queue))


    def get(self):
        return self._get_queue.get()


    def wait(self, k):
        # if not (0 < k <= len(self.queues)):
        #     raise ValueError("Invalid value of k")
        #
        # events = [Event() for _ in range(len(self.queues))]
        #
        # def watcher(queue: Queue, event):
        #     # Watcher function to check if the queue is non-empty
        #     queue.peek()  # blocking; avoid busy-waiting
        #     event.set()  # Set the event when the queue is non-empty
        #
        # threads = []
        # for i in range(len(self.queues)):
        #     threads.append(gevent.spawn(watcher, self.queues[i], events[i]))
        #
        # # Wait for at least k of the events to be set
        # gevent.joinall(events, count=k)
        # gevent.killall(threads)
        #
        # return [i for i, event in enumerate(events) if event.is_set()]
        return self.wait_value(None, k)

    def wait_value(self, value, k):
        if not (0 < k <= len(self.queues)):
            raise ValueError("Invalid value of k")

        events = [Event() for _ in range(len(self.queues))]

        def watcher(queue: Queue, event):
            # Watcher function to check if the queue is non-empty
            e = queue.peek()  # blocking; avoid busy-waiting

            if value is None:
                event.set()
                return

            try:
                sender, received_value = e
                if value == received_value:
                    event.set()  # Set the event when the queue is non-empty
            except Exception as e:
                print('watcher!?')
                print(e)

        threads = []
        for i in range(len(self.queues)):
            threads.append(gevent.spawn(watcher, self.queues[i], events[i]))

        # Wait for at least k of the events to be set
        gevent.joinall(events, count=k)
        gevent.killall(threads)

        return [i for i, event in enumerate(events) if event.is_set()]


    def get_value_at_least_k1_count_within_k2_count(self, k1, k2):
        queues = self.queues.copy()
        if not (0 < k1 <= k2 <= len(queues)):
            raise ValueError("Invalid value of k1 or k2")

        events = [Event() for _ in range(len(queues))]

        def watcher(queue: Queue, event):
            # Watcher function to check if the queue is non-empty
            e = queue.peek()  # blocking; avoid busy-waiting
            event.set()

        threads = []
        for i in range(len(queues)):
            threads.append(gevent.spawn(watcher, queues[i], events[i]))

        # at least k1 events is set!
        gevent.joinall(events, count=k1)

        counter = dict()
        finished_threads = list()
        finished_events = list()

        while len(finished_events) < k2:
            gevent.joinall(events, count=1)
            for i in range(len(threads) - 1, -1, -1):
                if events[i].is_set():
                    try:
                        sender, received_value = queues[i].peek()
                        counter.setdefault(received_value, set())
                        counter[received_value].add(sender)
                        finished_events.append(events.pop(i))
                        finished_threads.append(threads.pop(i))
                        queues.pop(i)
                        if len(counter[received_value]) >= k1:
                            gevent.killall(finished_threads)
                            gevent.killall(threads)
                            return received_value, sorted(counter[received_value])
                    except Exception as e:
                        print('watcher!?')
                        print(e)
            gevent.killall(finished_threads)
            finished_threads.clear()

        gevent.killall(threads)
        return None, list()

def listen_to_channel(thisnode):
    q = Queue(1)
    thisIP, port = thisnode

    def _handle(socket, address):
        f = socket.makefile(mode ='rb')
        while True:
            try:
                message_head = f.read(30).decode().strip()
                message_length = int(message_head)
                '''
                read_cir = int(message_length/1024)
                ii=0
                data = b''
                while ii<read_cir:
                    data=data+f.read(1024)
                    ii=ii+1
                rest = message_length-(1024*ii)
                data = data +f.read(rest)
                '''
                data = f.read(message_length)
                msg = pickle.loads(data)
                q.put(msg)
                del data
                #print(str(thisnode), "接收到的消息：", str(msg)[0: 200])
            except Exception as e:
                print(socket, "when server is receiving some thing fails, we close it:")
                print(e)
                socket.close()
                break

    try:
        server = StreamServer((thisIP, port), _handle)
        server.start()
    except Exception as e:
        print('When i start listen, at ', str(thisnode), 'server = StreamServer((thisIP, port), _handle) erros!!!!!')
        print(e)
    return q


def connect_to_channel(hostnode, node_queue):
    hostname, port = hostnode

    retry = True
    s = socks.socksocket()  ## Yi~ I always think it's not good.
    while retry:
        try:
            s = socks.socksocket()
            s.connect((hostname, port))
            retry = False
        except Exception as e:  # socks.SOCKS5Error:
            retry = True
            gevent.sleep(1)
            #s.close()
            #print(s.getsockname(), "when re-connects to ", hostname, ',', port, "some erro occurs, the erro:")
            #print(e)

    def _handle():
        sin = s

        while True:
            obj = node_queue.get()   ##人家已经放进来了一旦出了问题，你得保证重建信道、然后把这个发出去才可以吧
            #print(obj)
            try:
                content = pickle.dumps(obj)
                del obj
                content_lenth = len(content)
                try_head = str(content_lenth).encode()
                while True:
                    if len(try_head) < 30:
                        try_head = try_head + b' '
                    else:
                        break

                sin.sendall(try_head + content)
                del content
                #print("发送出的消息：", str(obj)[0: 200])
                #print(1)
            except Exception as e:
                print('在从发送队列中读取消息时出错了，假装什么都没发生过，以后也不尝试重新建立连接，直接把队列中的东西拿出来扔掉', e)
                pass

    Greenlet(_handle).start()
