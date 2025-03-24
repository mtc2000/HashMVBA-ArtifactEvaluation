import traceback

from speedmvba.core.smvba_e import speedmvba

_orig_print = print

def print(*args, **kwargs):
    _orig_print(*args, flush=True, **kwargs)


from collections import defaultdict, namedtuple
from ctypes import c_bool
import logging
import os
from typing import Callable, Dict
from enum import Enum
import random

from coincurve import PrivateKey, PublicKey
from crypto.threshsig.boldyreva import serialize, deserialize1
from multiprocessing import Value as mpValue, Queue as mpQueue
from queue import Empty

import hashlib
def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()

import socket
import time
import gevent
from gevent.queue import Queue
from gevent.event import Event
from gevent import monkey
monkey.patch_all(thread=False)

try:
    import cPickle as pickle
except ImportError:
    import pickle

from honeybadgerbft.exceptions import UnknownTagError
from mvba_node.make_random_tx import random_tx_generator, pseudo_random_tx_generator


def load_key(pid, N: int, f: int):

    folder_name = f'keys/keys-N{N}-f{f}'
    full_path = f'{os.getcwd()}/{folder_name}'

    with open(f'{full_path}/sPK.key', 'rb') as fp:
        sPK = pickle.load(fp)

    with open(f'{full_path}/sPK1.key', 'rb') as fp:
        sPK1 = pickle.load(fp)

    sPK2s = []
    for i in range(N):
        with open(f'{full_path}/sPK2-{i}.key', 'rb') as fp:
            sPK2s.append(PublicKey(pickle.load(fp)))

    with open(f'{full_path}/ePK.key', 'rb') as fp:
        ePK = pickle.load(fp)

    with open(f'{full_path}/sSK-{pid}.key', 'rb') as fp:
        sSK = pickle.load(fp)

    with open(f'{full_path}/sSK1-{pid}.key', 'rb') as fp:
        sSK1 = pickle.load(fp)

    with open(f'{full_path}/sSK2-{pid}.key', 'rb') as fp:
        sSK2 = PrivateKey(pickle.load(fp))

    with open(f'{full_path}/eSK-{pid}.key', 'rb') as fp:
        eSK = pickle.load(fp)

    return sPK, sPK1, sPK2s, ePK, sSK, sSK1, sSK2, eSK


def set_consensus_log(id: int):
    logger = logging.getLogger("consensus-node-" + str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.makedirs(os.getcwd() + '/log', exist_ok=True)
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "consensus-node-" + str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


class SMVBA_E():
    def __init__(self, sid, pid, B, N, f,
                 bft_from_server, bft_to_client,
                 ready: mpValue, stop: mpValue, K=3, countpoint=0, mode='debug', mute=False, debug=False, tx_buffer=None):
        sPK, sPK1, sPK2s, ePK, sSK, sSK1, sSK2, eSK = load_key(pid, N, f)
        self.bft_from_server = bft_from_server
        self.bft_to_client = bft_to_client
        self.send: Callable = lambda j, o: self.bft_to_client((j, o))
        self.recv: Callable = lambda: self.bft_from_server()
        self.ready = ready
        self.stop = stop
        self.mode = mode
        self.mute = mute
        self.debug = debug
        self.K = K
        self.countpoint = countpoint
        self.logger = set_consensus_log(pid)
        self.round_threads: Dict[int, Queue] = defaultdict(Queue)
        self.round_stops: Dict[int, Event] = defaultdict(Event)

        self.sid = sid
        self.pid = pid
        self.B = B
        self.N = N
        self.f = f
        self.sPK = sPK
        self.sSK = sSK

        # self.sPKNf2 = sPK1  # sPKNf2
        # self.sSKNf2 = sSK1  # sSKNf2
        self.sPK2s = sPK2s  # sPK2s
        self.sSK2 = sSK2  # sSK2
        # self.ePK = ePK
        # self.eSK = eSK

        self.round = 0  # Current block number
        self.transaction_buffer = Queue()
        # self.transaction_buffer = TransactionBuffer(batch_size=self.B)
        self._per_round_recv = {}  # Buffer of incoming messages

        self.latency_list = list()
        self.tp_list = list()

        self.total_latency = 0
        self.total_tx = 0

        self.log_file_name = "../log_" + "dumbo" + ".txt"

    def submit_tx(self, tx):
        """Appends the given transaction to the transaction buffer.
        :param tx: Transaction to append to the buffer.
        """
        self.transaction_buffer.put_nowait(tx)

    def buffer_size(self):
        return self.transaction_buffer.qsize()
    
    def round_bootstrap(self):
        self.logger.info('node id %d is inserting dummy payload TXs' % (self.pid))
        if self.mode == 'test' or 'debug': #K * max(Bfast * S, Bacs)
            # Set each dummy TX to be 250 Byte
            tx = pseudo_random_tx_generator(250, seed=self.sid)
            # tx = random_tx_generator(250) # corrupt input
            for r in range(self.B):
                self.submit_tx(tx)
                if (r+1) % 50000 == 0:
                    self.logger.info('node id %d just inserts 50000 TXs' % (self.pid))
        else:
            pass
            # TODO: submit transactions through tx_buffer
        
        self.logger.info('node id %d completed the loading of dummy TXs' % (self.pid))
    
    def round_thread_cleanup(self):
        for r in range(self.K + self.countpoint):
            self.round_stops[r].wait()
            gevent.sleep(0)
            while True:
                try:
                    t = self.round_threads[r].get_nowait()
                    t.kill()
                except Empty:
                    break


    def _run(self):
        """Run the HoneyBadgerBFT protocol."""

        def _recv():
            """Receive messages."""
            while True:
                try:
                    # blocking read with timeout
                    msg = self.recv()
                except Empty:
                    gevent.sleep(0)
                    continue

                (sender, (r, msg)) = msg

                for _old_r in range(self.round):
                    _old_recv = self._per_round_recv[_old_r]
                    if _old_recv:
                        del _old_recv
                        self._per_round_recv[_old_r] = None

                # Maintain an *unbounded* recv queue for each epoch
                if r not in self._per_round_recv:
                    # Buffer this message
                    assert r >= self.round  # pragma: no cover
                    self._per_round_recv[r] = Queue()

                _recv = self._per_round_recv[r]
                if _recv is not None:
                    # Queue it
                    _recv.put((sender, msg))

        _recv_thread = gevent.spawn(_recv)
        round_cleanup_thread = gevent.spawn(self.round_thread_cleanup)

        while True:
            r = self.round

            # self.logger.info('node id %d is running round %d' % (self.pid, r))

            self.round_bootstrap()

            if r not in self._per_round_recv:
                self._per_round_recv[r] = Queue()

            assert self.B > 0
            tx_to_send = []
            for _ in range(self.B):
                tx_to_send.append(self.transaction_buffer.get_nowait())
                tx_to_send.append('/')

            str_to_send = ''.join(tx_to_send)
            del tx_to_send

            # TODO: Wait a bit if transaction buffer is not full

            def _make_send(r):
                def _send(j, o):
                    self.logger.info('send this' + str((j, self.pid, (r, o)))[:40])
                    self.send(j, (r, o))
                return _send

            send_r = _make_send(r)
            recv_r = self._per_round_recv[r].get

            latency, recv_tx_len = self._run_round(r, str_to_send, send_r, recv_r)
            if r >= self.countpoint:
                self.total_latency += latency
                self.latency_list.append(latency)
                self.total_tx += recv_tx_len
                self.tp_list.append(recv_tx_len / latency)

            # gevent.sleep(2)
            # while True:
            #     try:
            #         t = self.round_threads[r].get_nowait()
            #         t.kill()
            #     except Empty:
            #         break

            self.round += 1  # Increment the round

            if self.round >= self.K + self.countpoint:
                break            
        
        gevent.sleep(3 + self.B / 500)
        _recv_thread.kill()
        if not round_cleanup_thread.dead:
            self.logger.info(f'cleanup taking more then expected time')
            round_cleanup_thread.kill()
        
        # Calculate the average latency (latency per round)
        self.a_latency = self.total_latency / self.K
        # Calculate the average throughput
        self.a_throughput = self.total_tx / self.total_latency

        import numpy
        
        self.logger.info(  # Print average delay/throughput to the execution log
            "node: %d epoch: %d run: %f, "
            "total delivered Txs after warm-up: %d, "
            "latency after warm-up: %f, "
            "tps after warm-up: %f, "
            "average latency by rounds + stddev: %f %f, " 
            "average tps by rounds + stddev: %f %f, " 
            %
            (self.pid, self.round, self.total_latency,
             self.total_tx,
             self.a_latency, 
             self.a_throughput,
             numpy.average(self.latency_list), numpy.std(self.latency_list),
             numpy.average(self.tp_list), numpy.std(self.tp_list),
             ))
        print(
            "node: %d epoch: %d run: %f, "
            "total delivered Txs after warm-up: %d, "
            "latency after warm-up: %f, "
            "tps after warm-up: %f, "
            "average latency by rounds + stddev: %f %f, " 
            "average tps by rounds + stddev: %f %f, " 
            %
            (self.pid, self.round, self.total_latency,
             self.total_tx,
             self.a_latency, 
             self.a_throughput,
             numpy.average(self.latency_list), numpy.std(self.latency_list),
             numpy.average(self.tp_list), numpy.std(self.tp_list),
             ))

        return

    def _run_round(self, r, tx_to_send, send, recv):
        """Run one protocol round."""

        sid = self.sid
        pid = self.pid
        N = self.N
        f = self.f

        round_input_queue = Queue(1)
        round_output_queue = Queue(1)

        _t = gevent.spawn(speedmvba,
                     sid, pid, N, f,
                     self.sPK, self.sSK, self.sPK2s, self.sSK2,
                     round_input_queue.get, round_output_queue.put_nowait,
                     recv, send,
                     self.round_threads[r].put_nowait,
                     lambda x: True,
                     self.logger)
        self.round_threads[r].put_nowait(_t)

        round_input_queue.put_nowait(tx_to_send)
        start_time = time.time()
        result = round_output_queue.get()
        end_time = time.time()
        latency = end_time - start_time

        _t.join()
        self.round_stops[r].set()

        if isinstance(result, str):
            return latency, result.count('/')
        if isinstance(result, bytes):
            return latency, result.count(b'/')

    def run(self):

        os_pid = os.getpid()
        self.logger.info('node %d\'s starts to run consensus on process id %d' % (self.pid, os_pid))

        # add_thread = gevent.spawn(self.add_tx)
        # self.prepare_bootstrap()
        time.sleep(1)
        while not self.ready.value:
            time.sleep(1)
            #gevent.sleep(1)

        self._run()
        # add_thread.join()
        self.stop.value = True
        self.logger.info('done!!!!!!!!!!!!!')