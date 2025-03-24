import logging
from collections import namedtuple, defaultdict
from enum import Enum
import random
from typing import Tuple, List, Callable

import hashlib

# _orig_print = print
#
# def print(*args, **kwargs):
#     _orig_print(*args, flush=True, **kwargs)

verbose_log = True


def _hash(x):
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
from gevent import monkey

monkey.patch_all(thread=False)

try:
    import cPickle as pickle
except ImportError:
    import pickle

from honeybadgerbft.exceptions import UnknownTagError
# from honeybadgerbft.core.binaryagreement import binaryagreement # TODO: use with caution!
from hash_mvba.adkg.binaryagreement import binaryagreement

simple_qc = True

if simple_qc:
    from hash_mvba.core.QueueCollection import QueueCollection
else:
    from hash_mvba.core.QueueCollection import QueueCollectionThreads as QueueCollection

NULL = b'0'

# alg 2

def run_mba(
        sid, pid, r, N, f,
        input_queue: Queue,
        recv: Callable, send: Callable,
        output_queue: Queue,
        put_thread: Callable = lambda x: None,
        put_send_thread: Callable = lambda x: None,
        logger: logging.Logger = None
    ):
    """
    Run MBA protocol
    Usage:

    round_input_queue = Queue(1)
    round_output_queue = Queue(1)

    #run_mba(sid, pid, r, N, f, round_input_queue.get, recv, send, self.sPK, self.sSK, round_output_queue,
    #        self.aba_time, self.aba_time_interval, self.basetime)

    gevent.spawn(run_mba, sid, pid, r, N, f, round_input_queue, recv, send, self.sPK, self.sSK, round_output_queue,
            self.aba_time, self.aba_time_interval, self.basetime)

    round_input_queue.put_nowait(tx_to_send)
    result = round_output_queue.get() # None or a result

    """
    # logger = logging.getLogger("consensus-node-" + str(pid))
    if logger: logger.info(f'{pid} start mba!')

    mba_prefix = f'{sid}:MBA:{r}'

    class BroadcastTag(Enum):
        VALUE = f'{mba_prefix}/VALUE'
        ECHO = f'{mba_prefix}/ECHO'
        RANDOM_NUMBER = f'{mba_prefix}/RANDOM_NUMBER'
        ABA = f'{mba_prefix}/ABA'
        ABA_COIN = f'{mba_prefix}/ABA_COIN'

    broadcast_receiver_queues = namedtuple(
        'broadcast_receiver_queues', (
            'VALUE',
            'ECHO',
            'RANDOM_NUMBER',
            'ABA',
            'ABA_COIN',
        ))

    def broadcast_receiver(recv_func, recv_queues):
        sender, (tag_value, j, msg) = recv_func()

        if tag_value not in BroadcastTag._value2member_map_:
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag_value, BroadcastTag._value2member_map_.keys()))

        tag_name = BroadcastTag._value2member_map_[tag_value].name
        # print(sender, (tag_value, j, msg), tag_name)

        recv_queue = recv_queues._asdict()[tag_name]

        if tag_value not in (BroadcastTag.ABA.value, BroadcastTag.RANDOM_NUMBER.value):
            recv_queue = recv_queue[j]
        recv_queue.put_nowait((sender, msg))

    def broadcast_receiver_loop(recv_func, recv_queues):
        while True:
            broadcast_receiver(recv_func, recv_queues)

    def broadcast(o):
        # for j in range(N):
        #     send(j, o)
        send(-1, o)

    # # Launch ACS, ABA, instances
    aba_coin_recvs = [Queue() for _ in range(N)]
    aba_recv = Queue()
    random_number_recvs = Queue()

    aba_input = Queue(1)  # noqa: E221

    # prepare recv queues for multicast actions
    value_recvs = [Queue() for _ in range(N)]
    echo_recvs = [Queue() for _ in range(N)]

    recv_queues = broadcast_receiver_queues(
        VALUE=value_recvs,
        ECHO=echo_recvs,
        RANDOM_NUMBER=random_number_recvs,
        ABA=aba_recv,
        ABA_COIN=aba_coin_recvs,
    )

    _t = gevent.spawn(broadcast_receiver_loop, recv, recv_queues)
    put_thread(_t)

    # generate m, (f+1, n)-erasure code
    input_msg = input_queue.get()
    # if logger: logger.info(f"tx_hash:{_hash(tx_to_send)}")

    def multicast_value_all(msg):
        multicast_value_all_time = time.time()
        broadcast((BroadcastTag.VALUE.value, pid, msg))
        multicast_value_all_time = time.time() - multicast_value_all_time
        if verbose_log and logger: logger.info(f'multicast_value_all time:{multicast_value_all_time}')

    _t = gevent.spawn(multicast_value_all, input_msg)
    put_send_thread(_t)
    # put_thread(_t) # do not kill sending thread

    def upon_receiving_value(value_queues):
        if verbose_log and logger: logger.debug(f'upon_receiving_value starts')
        value_waiting_time = time.time()
        value_qc = QueueCollection(value_queues)
        v_prime = value_qc.get_value_at_least_k1_count_within_k2_count(
            N - 2 * f,
            N - f
        )[0] # blocking
        # v_prime = value_qc.get_k_matching_value(N - 2*f)
        value_waiting_time = time.time() - value_waiting_time
        if verbose_log and logger: logger.info(f'echo_msg time:{value_waiting_time}')

        if v_prime is None:
            v_prime = NULL

        def multicast_echo_all(_msg):
            broadcast((BroadcastTag.ECHO.value, pid, _msg))

        multicast_echo_all_time = time.time()
        _t = gevent.spawn(multicast_echo_all, v_prime)
        put_send_thread(_t)
        # _t.join() # do not kill sending thread
        multicast_echo_all_time = time.time() - multicast_echo_all_time
        if verbose_log and logger: logger.info(f'multicast_echo_all time:{multicast_echo_all_time}')

    # upon_receiving_value(commit_recvs)
    _t = gevent.spawn(upon_receiving_value, value_recvs)
    put_thread(_t)

    def upon_receiving_N_minus_f_echo(echo_queues, flag: Queue):
        if verbose_log and logger: logger.debug(f'upon_receiving_N_minus_f_echo starts')
        upon_receiving_N_minus_f_echo_time = time.time()
        echo_qc = QueueCollection(echo_queues)
        result = echo_qc.get_non_zero_value_at_least_k1_count_within_k2_count(
            N - 2 * f,
            N - f
        )[0]

        upon_receiving_N_minus_f_echo_time = time.time() - upon_receiving_N_minus_f_echo_time
        if verbose_log and logger: logger.info(
            f'upon_receiving_N_minus_f_echo time:{upon_receiving_N_minus_f_echo_time}')

        if result == NULL:
            if logger: logger.error(f'this is impossible!')
            raise Exception
        elif result is None:
            flag.put_nowait(0)
        else:
            flag.put_nowait(1)

    flag_queue = Queue()

    # upon_receiving_N_minus_f_echo(echo_recvs, flag_queue)
    _t = gevent.spawn(upon_receiving_N_minus_f_echo, echo_recvs, flag_queue)
    put_thread(_t)

    def ABA(_flag_queue: Queue, _b_queue: Queue):
        aba_overall_time = time.time()

        _flag = _flag_queue.get()
        if logger: logger.info(f'_flag {_flag}')

        """
        Run a Coin instance
        """

        # cheap coin
        def aba_coin(aba_round: int):
            seed = int.from_bytes(_hash(mba_prefix + str(aba_round)), byteorder='big') % (2 ** 10 - 1)
            return int(seed % 2)

        def aba_bcast(o):
            broadcast((BroadcastTag.ABA.value, -1, o))

        aba_input.put_nowait(_flag)

        binaryagreement(
            BroadcastTag.ABA.value,
            pid, N, f,
            aba_coin,
            aba_input.get,
            _b_queue.put_nowait,
            aba_bcast,
            aba_recv.get,
            put_thread,
            put_send_thread,
            logger
        )

        aba_overall_time = time.time() - aba_overall_time
        if verbose_log and logger: logger.info(f'aba time:{aba_overall_time}')

    b_queue = Queue(1)

    # ABA(flag_queue, b_queue)
    _t = gevent.spawn(ABA, flag_queue, b_queue)
    put_thread(_t)

    b = b_queue.peek()  # blocking
    if logger: logger.info('aba ends')

    if b == 0:
        output_queue.put_nowait(NULL)
        if logger: logger.warning('oops')
        return

    # upon_receiving_f_plus_1_vc_echo
    echo_qc = QueueCollection(echo_recvs)
    output_msg = echo_qc.get_k_matching_value(f + 1, allow_null=False)

    if output_msg is None:
        if logger: logger.error(f'this is impossible!')

    if input_msg != output_msg:
        if logger: logger.warning(f"mba result is different from input! {input_msg[:20]} vs. {output_msg[:20]}")
    output_queue.put_nowait(output_msg)
    
