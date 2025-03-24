from gevent import monkey;

monkey.patch_all(thread=False)

import time
import pickle
from typing import List, Callable
import gevent
import os
from multiprocessing import Value as mpValue, Process, Event as mpEvent
from queue import Empty
from gevent import socket, lock
from gevent.pool import Pool
from gevent.queue import Queue, PriorityQueue
import logging
import traceback

import linecache
import tracemalloc

SLEEP_INTERVAL_LONG = 0.1
SLEEP_INTERVAL = 0.0001

# Network node class: deal with socket communications
class NetworkClient(Process):
    SEP = '\r\nSEP\r\nSEP\r\nSEP\r\n'.encode('utf-8')

    def __init__(
            self,
            port: int,
            my_ip: str,
            party_id: int,
            addresses_list: list,
            client_from_bft: Callable,
            client_ready: mpValue,
            stop: mpValue,
            test_termination: mpValue,
            s=0
        ):
        # tracemalloc.start()

        self.client_from_bft = client_from_bft
        self.ready: mpValue = client_ready
        self.stop: mpValue = stop
        self.test_termination: mpValue = test_termination

        self.ip = my_ip
        self.port = port
        self.party_id = party_id
        self.addresses_list = addresses_list
        self.N = len(self.addresses_list)

        self.is_out_sock_connected = [False] * self.N

        self.socks: List[socket.socket] = [None for _ in self.addresses_list]
        self.sock_queues = [PriorityQueue() for _ in self.addresses_list]

        self.sock_locks = [lock.Semaphore() for _ in self.addresses_list]
        self.s = s
        self.BYTES = 5000

        # self.logger = self._set_client_logger(self.party_id)

        super().__init__()


    def _connect_and_send_forever(self):
        os_pid = os.getpid()
        self.logger.info(
            'node %d\'s socket client starts to make outgoing connections on process id %d' % (self.party_id, os_pid))
        while not self.stop.value or not self.test_termination.value:
            try:
                for j in range(self.N):
                    if not self.is_out_sock_connected[j]:
                        self.is_out_sock_connected[j] = self._connect(j)
                if all(self.is_out_sock_connected):
                    with self.ready.get_lock():
                        self.ready.value = True
                    break
            except Exception as e:
                self.logger.error(traceback.format_exc())
        
        send_threads = [gevent.spawn(self._send, j) for j in range(self.N)]      

        self._handle_send_loop()
        # gevent.joinall(send_threads)

    def _connect(self, j: int):
        self.logger.info(
            'node %d\'s socket client starts to make outgoing connections to node %d server' % (self.party_id, j))
        try:
            socket_ready = False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if self.ip in ('localhost', '127.0.0.1'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((self.ip, self.port + 1 + j))
                else:
                    sock.bind((''     , self.port + 1 + j))
            except OSError as e:
                # address already in use?
                self.logger.error(
                        traceback.format_exc()
                    )
                if self.ip in ('localhost', '127.0.0.1'):
                    raise e
                else:
                    pass
            # try:
            #     self.logger.info(f"binding {self.ip} at {self.port + 1 + j}")
            #     sock.bind((self.ip, self.port + 1 + j))
            #     socket_ready = True
            # except Exception as e1:
            #     self.logger.warning(f"failed binding {self.ip} at {self.port + 1 + j}")
            #     self.logger.warning(f"{e1}")
            # if not socket_ready:
            #     self.logger.info(f"re-binding 0.0.0.0 at {self.port + 1 + j}")
            #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #     sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            #     sock.bind(('0.0.0.0', self.port + 1 + j))
            #     self.logger.info(f"re-binding 0.0.0.0 at {self.port + 1 + j}")
            while True:
                try:
                    sock.connect(self.addresses_list[j])
                    break
                except ConnectionRefusedError:
                    self.logger.warning(f"{self.addresses_list[j]} ConnectionRefusedError")
                except Exception:
                    self.logger.warning(traceback.format_exc())
                gevent.sleep(SLEEP_INTERVAL_LONG)
            self.socks[j] = sock
            self.logger.info('node %d\'s socket client made an outgoing connection to node %d server' % (self.party_id, j))
            return True
        except Exception:
            self.logger.warning(traceback.format_exc())
            self.logger.warning('node %d\'s socket client fails to make connection to node %d server' % (self.party_id, j))
            return False

    def _send(self, j: int):
        while not self.stop.value or not self.test_termination.value:
            gevent.sleep(SLEEP_INTERVAL)
            # self.sock_locks[j].acquire()
            # _msg = self.sock_queues[j].get()
            # msg = pickle.dumps(_msg)
            msg = self.sock_queues[j].get()
            # del _msg # reduce memory usage?
            while True:
                try:
                    # time.sleep(int(self.party_id) * 0.01) # random delay before sending
                    self.socks[j].sendall(msg + self.SEP)
                    break
                except Exception as e:
                    self.logger.error(f"fail to send msg to {j}")
                    try:
                        self.socks[j].shutdown(socket.SHUT_RDWR)
                        self.socks[j].close()
                    except Exception as ee:
                        self.logger.warning(f'fail to close socket to {j}')
                        self.logger.error(traceback.format_exc())
                    while True:
                        succ = self._connect(j)
                        if succ:
                            break
                        else:
                            gevent.sleep(SLEEP_INTERVAL)

    def _handle_send_loop(self, multithread_bcast=False):

        def _worker(_thread_queue: Queue):
            while not self.stop.value or not self.test_termination.value:
                thread: gevent.Greenlet = _thread_queue.get()
                thread.start()
                thread.join()
        
        num_threads = 4
        send_queue = Queue(num_threads)
        pool: Pool = None
        if multithread_bcast:
            pool = Pool(num_threads)
            for _ in range(num_threads):
                pool.spawn(_worker, send_queue)

        while not self.stop.value or not self.test_termination.value:
            try:
                j, o_raw = self.client_from_bft()
                # o = self.send_queue[j].get_nowait()
                send_summary = str((j, o_raw))[:60]
                o = pickle.dumps(o_raw)
                del o_raw
                self.logger.info(f'send {len(o)} {send_summary}')
                if not multithread_bcast:
                    try:
                        if j == -1: # -1 means broadcast
                            for i in range(self.N):
                                self.sock_queues[i].put_nowait(o)
                        elif j == -2: # -2 means broadcast except myself
                            for i in range(self.N):
                                if i != self.party_id:
                                    self.sock_queues[i].put_nowait(o)
                        else:
                            self.sock_queues[j].put_nowait(o)
                    except Exception as e:
                        self.logger.error(
                            traceback.format_exc()
                        )
                else:
                    try:
                        if j == -1: # -1 means broadcast
                            for i in range(self.N):
                                g = gevent.Greenlet(self.sock_queues[i].put_nowait, o)
                                send_queue.put(g)
                        elif j == -2: # -2 means broadcast except myself
                            for i in range(self.N):
                                if i != self.party_id:
                                    g = gevent.Greenlet(self.sock_queues[i].put_nowait, o)
                                    send_queue.put(g)
                        else:
                            g = gevent.Greenlet(self.sock_queues[j].put_nowait, o)
                            send_queue.put(g)
                    except Exception as e:
                        self.logger.error(
                            traceback.format_exc()
                        )
            except Empty:
                pass
            except Exception as e:
                self.logger.error(
                        traceback.format_exc()
                    )

        # print("sending loop quits ...")
                            
    # def _handle_send_loop(self, multithread_bcast=False):
    #     while not self.stop.value:
    #         try:
    #             j, o_raw = self.client_from_bft()
    #             # o = self.send_queue[j].get_nowait()
    #             send_summary = str((j, o_raw))[:60]
    #             o = pickle.dumps(o_raw)
    #             del o_raw
    #             self.logger.info(f'send {len(o)} {send_summary}')
    #             try:
    #                 if j == -1: # -1 means broadcast
    #                     for i in range(self.N):
    #                         self.sock_queues[i].put_nowait(o)
    #                 elif j == -2: # -2 means broadcast except myself
    #                     for i in range(self.N):
    #                         if i != self.party_id:
    #                             self.sock_queues[i].put_nowait(o)
    #                 else:
    #                     self.sock_queues[j].put_nowait(o)
    #             except Exception as e:
    #                 self.logger.error(
    #                     traceback.format_exc()
    #                 )
    #         except Empty:
    #             pass
    #         except Exception as e:
    #             self.logger.error(
    #                     traceback.format_exc()
    #                 )

    #     # print("sending loop quits ...")

    def run(self):
        self.logger = self._set_client_logger(self.party_id)
        os_pid = os.getpid()
        self.logger.info('node id %d is running on pid %d' % (self.party_id, os_pid))
        with self.ready.get_lock():
            self.ready.value = False
        # gevent.spawn(self.display_top)
        
        conn_thread = gevent.spawn(self._connect_and_send_forever)
        conn_thread.join()

    def stop_service(self):
        with self.stop.get_lock():
            self.stop.value = True

    def _set_client_logger(self, id: int):
        logger = logging.getLogger("node-" + str(id))
        logger.setLevel(logging.DEBUG)
        # logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
        if 'log' not in os.listdir(os.getcwd()):
            os.mkdir(os.getcwd() + '/log')
        full_path = os.path.realpath(os.getcwd()) + '/log/' + "node-net-client-" + str(id) + ".log"
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