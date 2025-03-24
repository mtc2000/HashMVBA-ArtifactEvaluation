from gevent import monkey;

monkey.patch_all(thread=False)
import socket
# from gevent.server import StreamServer
import pickle
import gevent
from gevent.queue import Queue
from typing import Callable
import os
import logging
import traceback
from multiprocessing import Value as mpValue, Process

import linecache
import tracemalloc

# Network node class: deal with socket communications
class NetworkServer(Process):
    SEP = '\r\nSEP\r\nSEP\r\nSEP\r\n'.encode('utf-8')

    def __init__(
            self,
            port: int,
            my_ip: str,
            party_id: int,
            addresses_list: list,
            server_to_bft: Callable,
            server_ready: mpValue,
            stop: mpValue,
            test_termination: mpValue,
            win=1
        ):
        # tracemalloc.start()

        self.server_to_bft: Callable = server_to_bft
        self.ready: mpValue = server_ready
        self.stop: mpValue = stop
        self.test_termination: mpValue = test_termination

        self.ip = my_ip
        self.port = port
        self.party_id = party_id
        self.addresses_list = addresses_list
        self.N = len(self.addresses_list)
        self.is_in_sock_connected = [False] * self.N
        self.local_test = self.N > len(set([address[0] for address in self.addresses_list]))
        self.socks = [None for _ in self.addresses_list]
        # self.test_termination_queue = Queue()
        self.win = win
        super().__init__()

    def _listen_and_recv_forever(self):
        pid = os.getpid()
        self.logger.info(
            'node %d\'s socket server %s starts to listen ingoing connections on process id %d' % (self.party_id, str((self.ip, self.port)), pid))
        

        def _handler(sock, address):
            self.logger.info(address)
            jid = self._address_to_id(address)
            if jid is None:
                # random server on the internet?!
                return
            self.is_in_sock_connected[jid] = True
            self.logger.info('node id %d server is connected by node %d' % (self.party_id, jid))
            if all(self.is_in_sock_connected):
                with self.ready.get_lock():
                    self.ready.value = True
            buf = b''
            try:
                while not self.stop.value or not self.test_termination.value:
                    if self.win == 1:
                        buf += sock.recv(212992 * 4)
                    else:
                        buf += sock.recv(212992 * 4)
                        # buf += sock.recv(106496)
                    tmp = buf.split(self.SEP, 1)
                    while len(tmp) == 2:
                        buf = tmp[1]
                        data = tmp[0]
                        if data != '' and data:
                            loaded_data = pickle.loads(data)
                            data_len = len(data)
                            del data # reduce memory usage?
                            # (j, o) = (jid, loaded_data)
                            # assert j in range(self.N)

                            # if loaded_data == 'TESTEND':
                            #     self.test_termination_queue.put(jid)
                            #     self.logger.info(f'recv TESTEND from {jid}, counting {self.test_termination_queue.qsize()}')
                            #     if self.test_termination_queue.qsize() == self.N:
                            #         self.logger.info('test_termination1')
                            #         with self.test_termination.get_lock():
                            #             self.logger.info('test_termination2')
                            #             self.test_termination.value = True
                            #         self.logger.info('test_termination3')
                            #     break

                            self.server_to_bft((jid, loaded_data))
                            self.logger.info(f'recv {data_len} {str((jid, loaded_data))[:150]}')
                        else:
                            self.logger.error('syntax error messages')
                            raise ValueError
                        tmp = buf.split(self.SEP, 1)
                    # gevent.sleep(0)
            except Exception as e:
                self.logger.error(
                    traceback.format_exc()
                )

        # self.streamServer = StreamServer((self.ip, self.port), _handler)
        # self.streamServer.serve_forever()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.logger.info(f"binding {self.ip} at {self.port}")
        if self.ip in ('localhost', '127.0.0.1'):
            server.bind((self.ip, self.port))
        else:
            server.bind(('', self.port))
        server.listen(1024)
        handler_threads = list()
        def _joinall_handlers(_handler_threads):
            try:
                expireds = gevent.joinall(_handler_threads, timeout=1)
                for expired in expireds:
                    pass
            except Exception:
                pass
        while True:
            sock, address = server.accept()
            self.logger.info(f'accept incoming connection from {address}')
            handler_thread = gevent.spawn(_handler, sock, address)
            handler_threads.append(handler_thread)
            

    def run(self):
        pid = os.getpid()
        self.logger = self._set_server_logger(self.party_id)
        self.logger.info('node id %d is running on pid %d, N = %d' % (self.party_id, pid, self.N))
        with self.ready.get_lock():
            self.ready.value = False
        # gevent.spawn(self.display_top)
        self._listen_and_recv_forever()

    def _address_to_id(self, address: tuple):
        if not self.local_test:
            for i in range(self.N):
                if address[0] == self.addresses_list[i][0]:
                    return i
        for i in range(self.N):
            if address[0] == self.addresses_list[i][0] and self.addresses_list[i][1] < address[1] <= self.addresses_list[i][1] + self.N:
                return i
        self.logger.error(f'unknown address {address}')
        return None
        # raise ValueError(f'unknown address {address}')
        # return int((address[1] - 10000) / 200)

    def _set_server_logger(self, id: int):
        logger = logging.getLogger("node-" + str(id))
        logger.setLevel(logging.DEBUG)
        # logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
        if 'log' not in os.listdir(os.getcwd()):
            os.makedirs(os.getcwd() + '/log', exist_ok=True)
        full_path = os.path.realpath(os.getcwd()) + '/log/' + "node-net-server-" + str(id) + ".log"
        file_handler = logging.FileHandler(full_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger

    def display_top(self, key_type='lineno', limit=3):
        while not self.stop.value or not self.test_termination.value:
            snapshot = tracemalloc.take_snapshot()
            snapshot = snapshot.filter_traces((
                tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
                tracemalloc.Filter(False, "<unknown>"),
            ))
            top_stats = snapshot.statistics(key_type, cumulative=True)

            if self.logger: self.logger.info("Top %s lines" % limit)
            for index, stat in enumerate(top_stats[:limit], 1):
                frame = stat.traceback[0]
                if self.logger: self.logger.info("#%s: %s:%s: %.1f KiB"
                    % (index, frame.filename, frame.lineno, stat.size / 1024))
                line = linecache.getline(frame.filename, frame.lineno).strip()
                if line:
                    if self.logger: self.logger.info('    %s' % line)

            other = top_stats[limit:]
            if other:
                size = sum(stat.size for stat in other)
                if self.logger: self.logger.info("%s other: %.1f KiB" % (len(other), size / 1024))
            total = sum(stat.size for stat in top_stats)
            if self.logger: self.logger.info("Total allocated size: %.1f KiB" % (total / 1024))
            gevent.sleep(5)