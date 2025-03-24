import sys
import traceback

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

from mvba_node.make_random_tx import random_tx_generator, pseudo_random_tx_generator

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


class MVBA():
    def __init__(
            self,
            sid, pid, B, N, f,
            bft_from_server: Callable,
            bft_to_client: Callable,
            ready: mpValue,
            stop: mpValue,
            K=3,
            countpoint=0,
            mode='debug',
            mute=False,
            debug=False,
            mvba_func=None
        ):
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
        
        self.round = 0  # Current block number
        self.transaction_buffer = Queue()
        # self.transaction_buffer = TransactionBuffer(batch_size=self.B)
        self._per_round_recv = {}  # Buffer of incoming messages
        self._per_round_recv['sys'] = Queue()

        self.latency_list = list()
        self.tp_list = list()

        self.total_latency = 0
        self.total_tx = 0

        self.mvba_func = mvba_func
        self.sync_events: Dict[int, Event] = defaultdict(Event)

    def submit_tx(self, tx):
        """Appends the given transaction to the transaction buffer.
        :param tx: Transaction to append to the buffer.
        """
        self.transaction_buffer.put_nowait(tx)

    def buffer_size(self):
        return self.transaction_buffer.qsize()

    def round_bootstrap(self, round):
        self.logger.info('node id %d is inserting dummy payload TXs' % (self.pid))
        if self.mode == 'test' or 'debug':  # K * max(Bfast * S, Bacs)
            # Set each dummy TX to be 250 Byte
            tx = pseudo_random_tx_generator(250, seed=f'{self.sid}/{round}')
            # tx = random_tx_generator(250) # corrupt input
            for r in range(self.B):
                self.submit_tx(tx)
                if (r + 1) % 50000 == 0:
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
                    raw_msg = self.recv()
                except Empty:
                    gevent.sleep(0)
                    continue

                try:
                    (sender, (r, msg)) = raw_msg
                except ValueError:
                    self.logger.warning('special message {raw_msg}')
                    continue
                
                for _old_r in range(self.round):
                    _old_recv = self._per_round_recv[_old_r]
                    if _old_recv:
                        del _old_recv
                        self._per_round_recv[_old_r] = None

                # Maintain an *unbounded* recv queue for each epoch
                if r != 'sys' and r not in self._per_round_recv:
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

            self.round_bootstrap(r)

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
                    self.logger.debug('send this' + str((j, self.pid, (r, o)))[:40])
                    self.send(j, (r, o))

                return _send

            send_r = _make_send(r)
            recv_r = self._per_round_recv[r].get

            sync_thread = gevent.spawn(self._sync)
            self.sync_events[self.round].wait()
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

        gevent.sleep(3)
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

        # mvba_func should only exist when
        # it can confirms all messages to be sent are enqueued

        _t = gevent.spawn(
            self.mvba_func,
            sid, pid, r, N, f,
            round_input_queue,
            recv, send,
            round_output_queue,
            self.round_threads[r].put_nowait,
            lambda x: True,
            self.logger
        )
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
    
    def set_mvba_func(self, func: Callable):
        self.mvba_func = func
    
    def _sync(self):
        def _make_send(r):
            def _send(j, o):
                self.send(j, ('sys', (r, o)))

            return _send

        send = _make_send(self.round)
        recv = self._per_round_recv['sys'].get
        
        try:
            self.sync_events[self.round].clear()
            # start together
            pid = self.pid
            N = self.N

            SLEEP_INTERVAL = 0.0001

            final_start_time = -1
            if pid == 0:
                final_start_time = time.time() + 15 + self.N / 20
                # send timestamp
                send(-2, final_start_time)
            else:
                # receive timestamp
                while True:
                    try:
                        (_, (_r, final_start_time)) = recv()
                        assert type(final_start_time) == float
                        break
                    except (Empty, AssertionError):
                        gevent.sleep(SLEEP_INTERVAL)
                        continue

            sleep_duration = final_start_time - time.time()
            self.logger.info(f'sleep {sleep_duration} until protocol starting at {final_start_time}')
            # wait until start_time
            gevent.sleep(sleep_duration)
            self.sync_events[self.round].set()
        except Exception as e:
            self.logger.error(str(e))
            self.logger.error(traceback.format_exc())
            self.stop.value = True
    
    def _sync_slow(self):
        def _make_send(r):
            def _send(j, o):
                self.send(j, ('sys', (r, o)))

            return _send

        send = _make_send(self.round)
        recv = self._per_round_recv['sys'].get
        
        try:
            self.sync_events[self.round].clear()
            # start together
            pid = self.pid
            N = self.N

            SLEEP_INTERVAL = 0.0001

            final_start_time = -1
            if pid == 0:
                leader_latency = 0
                for _ in range(N - 1):
                    while True:
                        try:
                            # ready
                            leader_now = time.time()
                            (sender, (_r, sender_now)) = recv()
                            assert type(sender_now) == float
                            network_latency = leader_now - sender_now
                            if network_latency > leader_latency:
                                leader_latency = network_latency
                            break
                        except (Empty, AssertionError):
                            gevent.sleep(SLEEP_INTERVAL)
                            continue
                leader_init_msg = (time.time(), leader_latency)
                send(-2, leader_init_msg)



                for _ in range(N - 1):
                    while True:
                        try:
                            (sender, (_r, updated_start_time)) = recv()
                            assert type(updated_start_time) == float
                            if updated_start_time > final_start_time:
                                final_start_time = updated_start_time
                            break
                        except (Empty, AssertionError):
                            gevent.sleep(SLEEP_INTERVAL)
                            continue
                # send a timestamp
                send(-2, final_start_time)
            else:
                now = time.time()
                send(0, now)
                # receive hi
                while True:
                    try:
                        (_, (_r, (leader_now, leader_latency))) = recv()
                        assert type(leader_now) == float
                        now = time.time()
                        my_latency = (now - leader_now)
                        network_latency = max(my_latency, leader_latency)
                        updated_start_time = now + 3 * network_latency
                        send(0, updated_start_time)
                        break
                    except (Empty, AssertionError):
                        gevent.sleep(SLEEP_INTERVAL)
                        continue

                # receive timestamp
                while True:
                    try:
                        (_, (_r, final_start_time)) = recv()
                        assert type(final_start_time) == float
                        break
                    except (Empty, AssertionError):
                        gevent.sleep(SLEEP_INTERVAL)
                        continue

            sleep_duration = final_start_time - time.time()
            self.logger.info(f'sleep {sleep_duration} until protocol starting at {final_start_time}')
            # wait until start_time
            gevent.sleep(sleep_duration)
            self.sync_events[self.round].set()
        except Exception as e:
            self.logger.error(str(e))
            self.logger.error(traceback.format_exc())
            self.stop.value = True
        

    def run(self):

        pid = os.getpid()
        self.logger.info('node %d\'s starts to run consensus on process id %d' % (self.pid, pid))

        # add_thread = gevent.spawn(self.add_tx)
        # self.prepare_bootstrap()
        while not self.ready.value:
            gevent.sleep(0.01)
        
        
        if self.mvba_func is None:
            self.stop.value = True
            self.logger.info('done!!!!!!!!!!!!!')
            return
        
        self.sync_events[self.round].clear()
        run_thread = gevent.spawn(self._run)
        run_thread.join()

        # add_thread.join()
        #with self.stop.get_lock():
        self.stop.value = True
        self.logger.info('done!!!!!!!!!!!!!')
