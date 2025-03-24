from __future__ import annotations

import logging
import queue
import sys
from collections import namedtuple, defaultdict
from enum import Enum
import random
import traceback
from typing import Tuple, List, Callable, Dict, Any

from fin_mvba.raba.pisa import reproposable_binaryagreement

import hashlib


def _hash(x):
    if x is None:
        x = 'None'
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

simple_qc = False

if simple_qc:
    from hash_mvba.core.QueueCollection import QueueCollection
else:
    from hash_mvba.core.QueueCollection import QueueCollectionThreads as QueueCollection

NULL = b'0'

TIMEOUT = 0.00001

from gevent.lock import BoundedSemaphore
from collections import defaultdict


class ThreadSafeWrapper:
    def __init__(self, obj):
        self.__dict__['_obj'] = obj
        self.__dict__['_lock'] = BoundedSemaphore(value=1)

    def __getattr__(self, name):
        with self.__dict__['_lock']:
            return getattr(self.__dict__['_obj'], name)

    def __setattr__(self, name, value):
        with self.__dict__['_lock']:
            setattr(self.__dict__['_obj'], name, value)

    def __delattr__(self, name):
        with self.__dict__['_lock']:
            delattr(self.__dict__['_obj'], name)

    def __getitem__(self, key):
        with self.__dict__['_lock']:
            return self.__dict__['_obj'][key]

    def __setitem__(self, key, value):
        with self.__dict__['_lock']:
            self.__dict__['_obj'][key] = value

    def __delitem__(self, key):
        with self.__dict__['_lock']:
            del self.__dict__['_obj'][key]

    def __contains__(self, *args, **kwargs):  # real signature unknown
        """ True if the dictionary has the specified key, else False. """
        with self.__dict__['_lock']:
            return self.__dict__['_obj'].__contains__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        with self.__dict__['_lock']:
            return self.__dict__['_obj'](*args, **kwargs)

    # Add other methods as needed


def run_fin_mvba(
        sid, pid, r, N, f,
        _input: Queue,
        recv: Callable, send: Callable,
        output_queue: Queue,
        put_thread: Callable = lambda x: None,
        predicate: Callable = lambda x: True,
        logger: logging.Logger = None,
        thread_safe: bool = True
):
    """
    Run FIN MVBA protocol

    """
    # logger = None

    if logger: logger.info(f'{pid} start mvba!')

    spawn_time = time.time()

    fin_mvba_prefix = f'{sid}:FINMVBA:{str(r)}'
    send_threads = Queue()

    class BroadcastTag(Enum):
        SEND = f'{fin_mvba_prefix}/SEND'
        ECHO = f'{fin_mvba_prefix}/ECHO'
        READY = f'{fin_mvba_prefix}/READY'
        VALUE = f'{fin_mvba_prefix}/VALUE'
        ELECTION = f'{fin_mvba_prefix}/ELECT'
        RABA = f'{fin_mvba_prefix}/RABA'

    broadcast_receiver_queues = namedtuple(
        'broadcast_receiver_queues',
        (
            'SEND',
            'ECHO',
            'READY',
            'VALUE',
            'ELECTION',
            'RABA',
        ))

    def broadcast_receiver(recv_func: Callable, recv_queues, unhandled_queue: Queue):
        recv_msg = recv_func()
        sender, (tag_value, j, msg) = recv_msg

        if tag_value not in BroadcastTag._value2member_map_:
            unhandled_queue.put_nowait(recv_msg)
            print('Unknown tag: {}! Must be one of {}.'.format(
                tag_value, BroadcastTag._value2member_map_.keys()))
            return
            # raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
            #     tag_value, BroadcastTag._value2member_map_.keys()))

        tag_name = BroadcastTag._value2member_map_[tag_value].name
        # print(sender, (tag_value, j, msg), tag_name)

        recv_queue: Queue | List[Queue] = recv_queues._asdict()[tag_name]

        if tag_value not in (BroadcastTag.ELECTION.value,):
            recv_queue: Queue = recv_queue[j]

        try:
            recv_queue.put_nowait((sender, msg))
        except queue.Full:
            if logger: logger.error(f'full?!/{recv_queue.qsize()}/{recv_queue.maxsize}/{recv_msg}')

    def broadcast_receiver_loop(recv_func: Callable, recv_queues, unhandled_queue: Queue):
        while True:
            broadcast_receiver(recv_func, recv_queues, unhandled_queue)

    def broadcast(o):
        send(-1, o)

    # send_recvs = Queue()
    # echo_recvs: List[Queue] = [Queue(1) for _ in range(N)]
    # ready_recvs: List[Queue] = [Queue(1) for _ in range(N)]
    # value_recvs: List[Queue] = [Queue() for _ in range(N)]

    send_recvs: List[Queue] = [Queue() for _ in range(N)]
    echo_recvs: List[Queue] = [Queue() for _ in range(N)]
    ready_recvs: List[Queue] = [Queue() for _ in range(N)]
    value_recvs: List[Queue] = [Queue() for _ in range(N)]
    election_recv: Queue = Queue()

    # raba_recvs[r] is the receiving channel for round r
    raba_recvs = defaultdict(Queue)

    # sub-protocol messages are unhandled
    unhandled_recvs = Queue()

    T_list = ThreadSafeWrapper([None for _ in range(N)]) if thread_safe else [None for _ in range(N)]
    ready_sent = [Event() for _ in range(N)]
    wr_deliver_dict = ThreadSafeWrapper(dict()) if thread_safe else dict()

    recv_queues = broadcast_receiver_queues(
        SEND=send_recvs,
        ECHO=echo_recvs,
        READY=ready_recvs,
        VALUE=value_recvs,
        ELECTION=election_recv,
        RABA=raba_recvs
    )

    _t = gevent.spawn(broadcast_receiver_loop, recv, recv_queues, unhandled_recvs)
    put_thread(_t)

    vi = _input.get()
    while not predicate(vi):
        vi = _input.get()

    def broadcast_send_vi(_vi):
        broadcast(
            (
                BroadcastTag.SEND.value,
                pid,
                _vi
            )
        )

    # broadcast_send_vi(vi)
    _t = gevent.spawn(broadcast_send_vi, vi)
    send_threads.put_nowait(_t)



    def upon_receiving_send(instance_id: int, _recv_func: Callable, _T_list: List):
        def broadcast_echo_hash(_instance_id: int, _hash):
            broadcast(
                (
                    BroadcastTag.ECHO.value,
                    _instance_id,
                    (_instance_id, _hash)
                )
            )

        _sender_j, _vj = _recv_func()
        assert _sender_j == instance_id
        if predicate(_vj):
            if _T_list[_sender_j] not in (None, NULL):
                if logger: logger.warning('')
                return
            _T_list[_sender_j] = _vj
            _vj_hash = _hash(_vj)
            _t = gevent.spawn(broadcast_echo_hash, instance_id, _vj_hash)
            send_threads.put_nowait(_t)
        else:
            # do noting when predicate is static
            if logger: logger.warning('')

    for i in range(N):
        # upon_receiving_send_from_j(send_recv, T_list)
        _t = gevent.spawn(upon_receiving_send, i, send_recvs[i].get, T_list)
        put_thread(_t)

    # TODO: fix below:

    def broadcast_ready(_instance_id: int, _hash):
        broadcast(
            (
                BroadcastTag.READY.value,
                _instance_id,
                (_instance_id, _hash)
            )
        )

    def upon_receiving_N_f_matching_echo(instance_id: int, _recv_func: Callable, _ready_sent: Event):
        counting = defaultdict(set)
        received_from = set()
        while True:
            _sender, (
                _instance_id,
                _h
            ) = _recv_func()
            assert instance_id == _instance_id
            if _sender in received_from:
                if logger: logger.warning('')
            if _sender in counting[_h]:
                if logger: logger.warning('')
            received_from.add(_sender)
            counting[_h].add(_sender)
            if len(counting[_h]) >= N - f:
                break

        if _h is None:
            logger.warning('')
        if not _ready_sent.ready():
            _ready_sent.set()
            _t = gevent.spawn(broadcast_ready, instance_id, _h)
            send_threads.put_nowait(_t)
        else:
            if logger: logger.warning(f'wrbc{instance_id} sends ready because of receiving f+1 matching ready first')

    for i in range(N):
        _t = gevent.spawn(upon_receiving_N_f_matching_echo, i, echo_recvs[i].get, ready_sent[i])
        put_thread(_t)

    def upon_receiving_matching_ready(instance_id: int, _recv_func: Callable, _deliver_list: Dict, _ready_sent: Event,
                                      _T_list: List):
        counting = defaultdict(set)
        received_from = set()
        f_1_matching = Event()
        while True:
            _sender, (
                _instance_id,
                _h
            ) = _recv_func()
            if logger: logger.debug(f'ready {_sender}, {_instance_id}, {_h}')
            assert instance_id == _instance_id
            if _sender in received_from:
                if logger: logger.warning('')
            if _sender in counting[_h]:
                if logger: logger.warning('')
            received_from.add(_sender)
            counting[_h].add(_sender)
            if logger: logger.debug(f'ready counting {counting}')
            if len(counting[_h]) >= f + 1 and not f_1_matching.ready():
                f_1_matching.set()
                if _h is None:
                    logger.warning('')
                if not _ready_sent.ready():
                    _ready_sent.set()
                    _t = gevent.spawn(broadcast_ready, instance_id, _h)
                    send_threads.put_nowait(_t)
                else:
                    if logger: logger.warning(
                        f'wrbc{_instance_id} sends ready because of receiving n-f matching echo first')
            if len(counting[_h]) >= N - f:
                if logger: logger.debug('receive more than (N-f) ready messages')
                if _T_list[_instance_id] in (None, NULL) or _hash(_T_list[_instance_id]) != _h:
                    _T_list[_instance_id] = NULL
                    if logger: logger.warning(f'wrbc{_instance_id} hash mismatch')
                if _instance_id in _deliver_list:
                    if logger: logger.warning('???')
                if logger: logger.warning(f'put hash {_h} inst {_instance_id} in deliver list')
                _deliver_list[_instance_id] = _h
                break

    deliver_threads = list()

    for i in range(N):
        _t = gevent.spawn(upon_receiving_matching_ready, i, ready_recvs[i].get, wr_deliver_dict, ready_sent[i], T_list)
        put_thread(_t)
        deliver_threads.append(_t)

    def election_phase(_deliver_threads: List[gevent.Greenlet], _wr_deliver_dict: Dict, _raba_recvs: defaultdict[Any, Queue],
                       _value_recvs: List[Queue], _T_list: List, _stop_event: Event):
        if logger: logger.debug(f'wrbc phase starts')
        gevent.joinall(_deliver_threads, count=N - f)
        if logger: logger.debug(f'wrbc phase ends')

        # if logger: logger.debug(f'{len(_wr_deliver_dict)}')
        # if logger: logger.debug(f'{_wr_deliver_dict}')
        # # wr_deliver_dict should have at least size (N-f) now!
        # while len(_wr_deliver_dict) < N - f:
        #     gevent.sleep(TIMEOUT)

        if logger: logger.debug(f'elect phase starts')

        # cheap election
        def elect(_election_round: int):
            seed = int.from_bytes(_hash(fin_mvba_prefix + str(_election_round)), byteorder='big') % (2 ** 10 - 1)
            return seed % N

        # cheap coin
        def raba_coin(_coin_round: int):
            seed = int.from_bytes(_hash(fin_mvba_prefix + str(_coin_round) + 'coin'), byteorder='big') % (2 ** 10 - 1)
            return int(seed % 2)

        election_round = 0
        while True:
            k = elect(election_round)

            def make_raba_broadcast(_election_round):
                def _raba_broadcast(o):
                    broadcast(
                        (
                            BroadcastTag.RABA.value,
                            _election_round,
                            o
                        )
                    )

                return _raba_broadcast

            repropose_event = Event()

            raba_input_queue = Queue(1)
            raba_output_queue = Queue(1)

            raba_thread = gevent.spawn(reproposable_binaryagreement,
                              fin_mvba_prefix, pid, N, f,
                              raba_coin,
                              raba_input_queue.get,
                              raba_output_queue.put_nowait,
                              make_raba_broadcast(election_round),
                              _raba_recvs[election_round].get,
                              repropose_event=repropose_event,
                              put_thread=put_thread,
                              put_send_thread=send_threads.put_nowait,
                              logger=logger
                              )
            put_thread(raba_thread)

            if k in _wr_deliver_dict:
                # raba-propose(1)
                raba_input_queue.put_nowait(1)
            else:
                # raba-propose(0)
                raba_input_queue.put_nowait(0)
                def repropose():
                    _deliver_threads[k].join()
                    if logger: logger.info(f'repropose in round {election_round}')
                    repropose_event.set()
                _t = gevent.spawn(repropose)
                put_thread(_t)

            raba_output = raba_output_queue.get()

            stop_raba_event = Event()

            def kill_raba(_stop_raba_event: Event):
                _stop_raba_event.wait()
                raba_thread.kill()
            gevent.spawn(kill_raba, stop_raba_event)

            if logger: logger.debug(f'raba output {raba_output}')

            if raba_output == 1:
                if k not in _wr_deliver_dict:
                    if logger: logger.debug(f'waiting wrbc {k}')
                    if not _deliver_threads[k].dead:
                        _deliver_threads[k].join()
                    else:
                        if logger: logger.debug(f'wrbc {k} was dead')
                    if logger: logger.debug(f'stop waiting wrbc {k}')
                if k not in _wr_deliver_dict:
                    if logger: logger.error(f'k {k} has not delivered, deliver list: {_wr_deliver_dict} T_list {_T_list}')
                _h_k = _wr_deliver_dict[k]
                if logger: logger.debug(f'elect {k} T[k] = {_T_list[k]}')
                if _T_list[k] not in (None, NULL):
                    if logger: logger.debug(f'send VALUE')
                    # broadcast VALUE(T_i[k])
                    def broadcast_value(_instance_id, _v_k):
                        broadcast(
                            (
                                BroadcastTag.VALUE.value,
                                _instance_id,
                                (_instance_id, _v_k)
                            )
                        )
                    # broadcast_value(k, _T_list[k])
                    _t = gevent.spawn(broadcast_value, k, _T_list[k])
                    send_threads.put_nowait(_t)

                else:
                    while True:
                        _sender, (
                            _k, _v_k
                        ) = _value_recvs[k].get()
                        if logger: logger.debug(f'receive VALUE')
                        assert _k == k
                        if _hash(_v_k) == _h_k:
                            _T_list[k] = _v_k
                            break
                _stop_event.set()
                stop_raba_event.set()
                if logger: logger.debug(f'decide')
                output_queue.put_nowait(_T_list[k])
                break

            election_round += 1

    stop_event = Event()

    # election_phase(deliver_threads, wr_deliver_dict, raba_recvs, value_recvs, T_list)
    _t = gevent.spawn(election_phase, deliver_threads, wr_deliver_dict, raba_recvs, value_recvs, T_list, stop_event)
    put_thread(_t)

    spawn_time = time.time() - spawn_time
    if logger: logger.info(f'spawn time:{spawn_time}')

    stop_event.wait()

    while not send_threads.empty():
        _t: gevent.Greenlet = send_threads.get()
        try:
            if not _t.dead:
                _t.join(timeout=0.001)
                _t.kill()
        except Exception:
            if logger: logger.warning(traceback.format_exc())

    if logger: logger.info(f'the end!')
    # result = mba(v)
    # output_queue.put_nowait(result)
