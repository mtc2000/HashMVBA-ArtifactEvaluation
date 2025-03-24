from __future__ import annotations

import logging
import queue
import sys
from collections import namedtuple, defaultdict
from enum import Enum
import random
import traceback
from typing import Tuple, List, Callable, Dict

from hash_mvba.mba.mba_protocol import run_mba
from honeybadgerbft.core.reliablebroadcast import encode, decode, merkleTree as merkle_tree, \
    getMerkleBranch as get_merkle_branch, merkleVerify as verify_merkle_branch

import hashlib


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

    def __contains__(self, *args, **kwargs): # real signature unknown
        """ True if the dictionary has the specified key, else False. """
        with self.__dict__['_lock']:
            return self.__dict__['_obj'].__contains__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        with self.__dict__['_lock']:
            return self.__dict__['_obj'](*args, **kwargs)

    # Add other methods as needed

# alg 1 + alg 2

def run_hmvba(
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
    Run P-MVBA protocol
    Usage:

    round_input_queue = Queue(1)
    round_output_queue = Queue(1)

    #run_p_mvba(sid, pid, r, N, f, round_input_queue.get, recv, send, self.sPK, self.sSK, round_output_queue,
    #        self.aba_time, self.aba_time_interval, self.basetime)

    gevent.spawn(run_p_mvba, sid, pid, r, N, f, round_input_queue, recv, send, self.sPK, self.sSK, round_output_queue,
            self.aba_time, self.aba_time_interval, self.basetime)

    round_input_queue.put_nowait(tx_to_send)
    result = round_output_queue.get() # None or a result

    """
    # logger = None

    # logger = logging.getLogger("consensus-node-" + str(pid))
    if logger: logger.info(f'{pid} start mba!')

    spawn_time = time.time()

    pmvba_prefix = f'{sid}:PMVBA:{str(r)}'
    send_threads = Queue()

    class BroadcastTag(Enum):
        DIFFUSION = f'{pmvba_prefix}/DIFFUSION'
        ECHO = f'{pmvba_prefix}/ECHO'
        DONE = f'{pmvba_prefix}/DONE'
        FINISH = f'{pmvba_prefix}/FINISH'
        VALUE = f'{pmvba_prefix}/VALUE'
        ELECTION = f'{pmvba_prefix}/ELECT'
        MBA = f'{pmvba_prefix}/MBA'

    broadcast_receiver_queues = namedtuple(
        'broadcast_receiver_queues',
        (
            'DIFFUSION',
            'ECHO',
            'DONE',
            'FINISH',
            'VALUE',
            'ELECTION',
            'MBA'
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

        if tag_value not in (BroadcastTag.DIFFUSION.value, BroadcastTag.ELECTION.value):
            recv_queue: Queue = recv_queue[j]

        try:
            recv_queue.put_nowait((sender, msg))
        except queue.Full:
            if logger: logger.error(f'full?!/{recv_queue.qsize()}/{recv_queue.maxsize}/{recv_msg}', file=sys.stderr)

    def broadcast_receiver_loop(recv_func: Callable, recv_queues, unhandled_queue: Queue):
        while True:
            broadcast_receiver(recv_func, recv_queues, unhandled_queue)

    def broadcast(o):
        send(-1, o)
        # for j in range(N):
        #     send(j, o)

    diffusion_recv = Queue()
    echo_recvs: List[Queue] = [Queue(1) for _ in range(N)]
    done_recvs: List[Queue] = [Queue(1) for _ in range(N)]
    finish_recvs: List[Queue] = [Queue(1) for _ in range(N)]
    value_recvs: List[Queue] = [Queue() for _ in range(N)]
    election_recv = Queue()
    mba_recvs: List[Queue] = [Queue() for _ in range(N)]
    # sub-protocol messages are unhandled
    unhandled_recvs = Queue()

    recv_queues = broadcast_receiver_queues(
        DIFFUSION=diffusion_recv,
        ECHO=echo_recvs,
        DONE=done_recvs,
        FINISH=finish_recvs,
        VALUE=value_recvs,
        ELECTION=election_recv,
        MBA=mba_recvs
    )

    _t = gevent.spawn(broadcast_receiver_loop, recv, recv_queues, unhandled_recvs)
    put_thread(_t)

    flag = Event()
    store_dict = ThreadSafeWrapper(defaultdict(list)) if thread_safe else defaultdict(list)

    def upon_receiving_input(input_queue: Queue, predicate: Callable):
        def send_diffusion_all(i, erase_code_i, commitment_i, tree_i, num_node):
            for j in range(num_node):
                # open
                pi_i_j = get_merkle_branch(j, tree_i)
                erase_code_i_j = erase_code_i[j]
                send(j,
                     (BroadcastTag.DIFFUSION.value,
                      i,
                      (commitment_i, erase_code_i_j, pi_i_j)
                      )
                     )

        while True:
            v = input_queue.get()
            if not predicate(v): continue

            vc_time = time.time()
            # generate m, (f+1, n)-erasure code
            m = encode(f + 1, N, v)
            assert len(m) == N, f'{len(m)} != {N}'

            def vector_commitment(x) -> Tuple[bytes, List[bytes]]:
                mt = merkle_tree(x)
                root = mt[1]
                return root, mt

            vc_i, mt_i = vector_commitment(m)
            vc_time = time.time() - vc_time
            if logger: logger.info(f'vc time:{vc_time}')

            send_diffusion_all_time = time.time()
            _t = gevent.spawn(send_diffusion_all, pid, m, vc_i, mt_i, N)
            send_threads.put_nowait(_t)
            _t.join() # do not kill sending thread
            send_diffusion_all_time = time.time() - send_diffusion_all_time
            if logger: logger.debug(f'send_diffusion_all time:{send_diffusion_all_time}')

    # upon_receiving_input(input, predicate)
    _t = gevent.spawn(upon_receiving_input, _input, predicate)
    put_thread(_t)

    def upon_receiving_first_diffusion_from_j(diffusion_queue: Queue, abandon_event: Event, received_commitments: dict):
        upon_receiving_first_diffusion_from_j_time = time.time()
        received_sender = set()
        while True:
            sender, proof = diffusion_queue.get()
            _time = time.time_ns()
            if logger: logger.debug(
                f'diffusion from {sender} at {_time}')
            if len(received_sender) == 0:
                upon_receiving_first_diffusion_from_j_time = time.time() - upon_receiving_first_diffusion_from_j_time
                if logger: logger.debug(
                    f'upon_receiving_first_diffusion_from_j 1 time:{upon_receiving_first_diffusion_from_j_time}')
                upon_receiving_first_diffusion_from_j_time = time.time()
            else:
                pass
            i = pid
            j = sender
            if abandon_event.ready():
                if logger: logger.debug(
                    f'diffusion from {sender} at {_time} but abandoned')
                # break
            if sender in received_sender: continue
            received_sender.add(sender)
            commitment_j, erase_code_j_i, pi_j_i = proof
            if not verify_merkle_branch(N, erase_code_j_i, commitment_j, pi_j_i, i): continue
            if not abandon_event.ready():
                received_commitments[j] = (j, commitment_j, erase_code_j_i, pi_j_i)
                def send_echo_j():
                    send(
                        j,
                        (
                            BroadcastTag.ECHO.value,
                            i,
                            1
                        )
                    )
                _t = gevent.spawn(send_echo_j)
                send_threads.put_nowait(_t)
                _t.join() # do not kill sending thread
            if len(received_sender) == N:
                break
        upon_receiving_first_diffusion_from_j_time = time.time() - upon_receiving_first_diffusion_from_j_time
        if logger: logger.debug(
            f'upon_receiving_first_diffusion_from_j 2 time:{upon_receiving_first_diffusion_from_j_time}')

    S = ThreadSafeWrapper(dict()) if thread_safe else dict()
    abandon = Event()
    # has_received_N_minus_f_echo = Event()
    _t = gevent.spawn(upon_receiving_first_diffusion_from_j, diffusion_recv, abandon, S)
    put_thread(_t)

    def upon_receiving_N_minus_f_echo(echo_queues):
        upon_receiving_N_minus_f_echo_time = time.time()
        echo_qc = QueueCollection(echo_queues)
        echo_qc.wait(N - f)
        # has_received_N_minus_f_echo.set()
        upon_receiving_N_minus_f_echo_time = time.time() - upon_receiving_N_minus_f_echo_time
        if logger: logger.debug(f'upon_receiving_N_minus_f_echo time:{upon_receiving_N_minus_f_echo_time}')

        def multicast_done_all():
            broadcast(
                (
                    BroadcastTag.DONE.value,
                    pid,
                    1
                )
            )

        multicast_done_all_time = time.time()
        _t = gevent.spawn(multicast_done_all)
        send_threads.put_nowait(_t)
        _t.join() # do not kill sending thread
        multicast_done_all_time = time.time() - multicast_done_all_time
        if logger: logger.debug(f'multicast_done_all time:{multicast_done_all_time}')

    # upon_receiving_N_minus_f_echo(echo_recvs)
    _t = gevent.spawn(upon_receiving_N_minus_f_echo, echo_recvs)
    put_thread(_t)

    def upon_receiving_N_minus_f_done(done_queues: List[Queue]):
        done_qc = QueueCollection(done_queues)
        done_qc.wait(N - f)

    def upon_receiving_f_plus_1_finish(finish_queues: List[Queue]):
        finish_qc = QueueCollection(finish_queues)
        finish_qc.wait(f + 1)

    def multicast_finish_with_prerequisites(done_pre: Callable, done_queues: List[Queue],
                                            finish_pre: Callable, finish_queues: List[Queue]):

        multicast_finish_prerequisites = []
        upon_receiving_N_minus_f_done_thread = gevent.spawn(done_pre, done_queues)
        put_thread(upon_receiving_N_minus_f_done_thread)
        upon_receiving_f_plus_1_finish_thread = gevent.spawn(finish_pre, finish_queues)
        put_thread(upon_receiving_f_plus_1_finish_thread)

        multicast_finish_prerequisites.append(upon_receiving_N_minus_f_done_thread)
        multicast_finish_prerequisites.append(upon_receiving_f_plus_1_finish_thread)

        multicast_finish_prerequisites_time = time.time()
        gevent.joinall(multicast_finish_prerequisites, count=1)
        multicast_finish_prerequisites_time = time.time() - multicast_finish_prerequisites_time
        if logger: logger.debug(f'multicast_finish_prerequisites time:{multicast_finish_prerequisites_time}')

        def multicast_finish_all():
            broadcast(
                (
                    BroadcastTag.FINISH.value,
                    pid,
                    1
                )
            )

        multicast_finish_all_time = time.time()
        _t = gevent.spawn(multicast_finish_all)
        send_threads.put_nowait(_t)
        _t.join() # do not kill sending thread
        multicast_finish_all_time = time.time() - multicast_finish_all_time
        if logger: logger.debug(f'multicast_finish_all time:{multicast_finish_all_time}')

    # multicast_finish_with_prerequisites(
    #     upon_receiving_N_minus_f_done, done_recvs,
    #     upon_receiving_f_plus_1_finish, finish_recvs
    # )
    _t = gevent.spawn(multicast_finish_with_prerequisites,
                      upon_receiving_N_minus_f_done, done_recvs,
                      upon_receiving_f_plus_1_finish, finish_recvs
                      )
    put_thread(_t)

    def mba(k, v):
        mba_input_queue = Queue(1)
        mba_output_queue = Queue(1)

        def mba_send(j, o):
            send(j,
                 (BroadcastTag.MBA.value,
                  k,
                  o
                  )
                 )

        _t = gevent.spawn(
            run_mba,
            sid, pid, k, N, f,
            mba_input_queue,
            mba_recvs[k].get,
            mba_send,
            mba_output_queue,
            put_thread,
            send_threads.put,
            logger
        )
        put_thread(_t)
        mba_input_queue.put_nowait(v)
        M = mba_output_queue.get()
        return M

    def upon_receiving_N_minus_f_finish(
            finish_queues: Queue,
            value_queues: List[Queue],
            output: Callable,
            _store_dict: Dict[bytes, List[Tuple[int, bytes]]]
    ):
        upon_receiving_N_minus_f_finish_time = time.time()
        finish_qc = QueueCollection(finish_queues)
        finish_qc.wait(N - f)  # blocking
        upon_receiving_N_minus_f_finish_time = time.time() - upon_receiving_N_minus_f_finish_time
        if logger: logger.debug(f'upon_receiving_N_minus_f_finish time:{upon_receiving_N_minus_f_finish_time}')
        abandon.set()
        _time = time.time_ns()
        if logger: logger.debug(f'abandon now at {_time}')
        gevent.sleep(0)

        """
        Run a Coin instance to elect the leaders
        """

        # from hash_mvba.core.leaderelection import leader_election
        # elect = leader_election(pmvba_prefix, pid, N, N - f - 1, sPK_N_minus_f, sSK_N_minus_f, broadcast,
        #                         election_recv.get)

        # cheap election
        def elect(election_round: int):
            seed = int.from_bytes(_hash(pmvba_prefix + str(election_round)), byteorder='big') % (2 ** 10 - 1)
            return seed % N

        def multicast_value_all(k, l, s_leader):
            (_leader, commitment_leader, erase_code_leader_i, pi_leader_i) = s_leader
            assert _leader == l
            i = pid
            broadcast(
                (
                    BroadcastTag.VALUE.value,
                    k,
                    (
                        k, l, i,
                        commitment_leader,
                        erase_code_leader_i,
                        pi_leader_i
                    )
                )
            )

        def upon_receiving_first_value_from_i(
                my_leader: int,
                curr_round: int,
                _echo_queues: List[Queue],
                _value_queue: Queue,
                _store_dict: Dict[bytes, List[Tuple[int, bytes]]],
                flag_event: Event,
                _M_i_queue: Queue,
                _vc_i_queue: Queue
        ):
            upon_receiving_first_value_from_i_time = time.time()
            received_sender = set()

            while True:
                sender, (
                    k, l, i,
                    commitment_leader,
                    erase_code_leader_i,
                    pi_leader_i
                ) = _value_queue.get()

                first_time_seeing_sender = sender not in received_sender
                received_sender.add(sender)

                if len(received_sender) >= N - f and not flag_event.ready():
                    if _vc_i_queue.full():
                        if logger: logger.error("upon_receiving_N_minus_f_value error")
                    else:
                        _vc_i_queue.put(None)
                    flag_event.set()

                if logger: logger.debug(f"value info sender{sender} round{curr_round}")
                if k != curr_round:
                    # something has gone wrong very badly :(
                    if logger: logger.error(f"??? sender{sender} round{curr_round}")
                    continue
                if not first_time_seeing_sender:
                    if logger: logger.warning(f"repeated seeing sender{sender} round{curr_round}")
                    continue

                if commitment_leader is None:
                    if leader == pid:
                        # this may only happen if the leader has not yet received (N-f) ECHO messages
                        # check if sender has ECHOed
                        if not _echo_queues[sender].empty():
                            if logger: logger.error(f'sender{sender} gives bot value but has ECHOed')
                    if logger: logger.warning(f"leader is None! value sender{sender} round{curr_round}")
                    continue

                commitment_leader: bytes

                assert sender == i
                assert my_leader == l

                if not verify_merkle_branch(N, erase_code_leader_i, commitment_leader, pi_leader_i, i):
                    if logger: logger.warning(f"verification failed! value sender{sender} round{curr_round}")
                    continue

                _store_dict[commitment_leader].append((i, erase_code_leader_i))

                if logger: logger.debug(
                    f'leader {l} commit {commitment_leader[:10]} has length {len(_store_dict[commitment_leader])}')

                # TODO: upon?
                if len(_store_dict[commitment_leader]) >= N - 3 * f:
                    stripes = [None] * N
                    for idx, commitment_idx in _store_dict[commitment_leader]:
                        stripes[idx] = commitment_idx
                    # decode
                    decoded_msg = None
                    try:
                        decoded_msg = decode(f + 1, N, stripes)
                        _M_i_queue.put(decoded_msg)
                    except ValueError as e:
                        if logger: logger.warning("failed to decode 2")
                        if logger: logger.warning(str(e))
                    if predicate(decoded_msg):
                        _vc_i_queue.put(commitment_leader)
                        flag_event.set()

                if len(received_sender) == N:
                    if logger: logger.warning("force exit without termination")
                    break # TODO: check this

            upon_receiving_first_value_from_i_time = time.time() - upon_receiving_first_value_from_i_time
            if logger: logger.debug(
                f'upon_receiving_first_value_from_i_time time:{upon_receiving_first_value_from_i_time}')

        def upon_flag(_round_k: int, flag_event: Event,
                      _M_i_queue: Queue,
                      _vc_i_queue: Queue,
                      output_func: Callable,
                      _store_dict: Dict[bytes, List[Tuple[int, bytes]]]):
            flag_event.wait()  # blocking
            if logger: logger.info('flag is up')
            try:
                # v is VC^{(i)}
                _vc_i = _vc_i_queue.get_nowait()
            except queue.Empty:
                if logger: logger.error("upon_flag error")
                _vc_i = NULL
            if _vc_i is None: _vc_i = NULL

            mba_time = time.time()
            vc_prime = mba(_round_k, _vc_i)  # blocking
            mba_time = time.time() - mba_time
            if logger: logger.info(f'mba time:{mba_time}')
            print(f'{pmvba_prefix}:{round_k} mba time:{mba_time}', flush=True)

            if vc_prime != NULL:
                if vc_prime == _vc_i:
                    M_i = _M_i_queue.get()
                    output_func(M_i)                
                    if logger: logger.info(f'output {M_i[:40]}')
                    return True
                else:
                    # TODO
                    if logger: logger.warning(f'VC\' is NULL')
                    while len(_store_dict[vc_prime]) < f + 1:
                        new_store_ready.wait()
                    stripes = [None] * N
                    for idx, commitment_idx in _store_dict[vc_prime]:
                        stripes[idx] = commitment_idx
                    # decode
                    decoded_msg = None
                    try:
                        decoded_msg = decode(f + 1, N, stripes)
                        output_func(decoded_msg)
                        return True
                    except ValueError as e:
                        if logger: logger.warning("failed to decode 3")
                        if logger: logger.warning(str(e))
            else:
                if logger: logger.warning(f'no output, try again')
                return False

        for round_k in range(N):  # TODO
            if round_k > 0:
                if logger: logger.warning(f'oh no, this is round {round_k}')
            # leader election
            elect_time = time.time()
            leader = elect(round_k)
            # if logger: logger.info(f'leader is {leader}')
            elect_time = time.time() - elect_time
            if logger: logger.debug(f'elect time:{elect_time}')

            M_i_queue = Queue()
            vc_i_queue = Queue()

            S_leader = (leader, None, None, None)
            _time = time.time_ns()
            if leader in S:
                S_leader = S[leader]
            else:
                _time = (_time + time.time_ns()) // 2
                if logger: logger.warning(f'leader {leader} is None! {S.keys()} (at {_time})')

            _t = gevent.spawn(multicast_value_all, round_k, leader, S_leader)
            send_threads.put_nowait(_t)
            _t.join() # do not kill sending thread

            _t = gevent.spawn(upon_receiving_first_value_from_i,
                              leader, round_k,
                              echo_recvs,
                              value_queues[round_k], _store_dict, flag, M_i_queue,
                              vc_i_queue
                              )
            put_thread(_t)

            if upon_flag(round_k, flag, M_i_queue, vc_i_queue, output, _store_dict):
                if logger: logger.info(f"end of protocol {pmvba_prefix} at round {round_k}")
                return  # TODO

            # no need to clear M_i_queue and vc_i_queue
            # because they are local variables
            flag.clear()
            _store_dict.clear()
            # gevent.spawn(upon_flag, k, flag, M_i_queue, output, store_dict)

        if logger: logger.warning('no output?!')

    # upon_receiving_N_minus_f_finish(finish_recvs, value_recvs, output_queue.put_nowait, store)
    _t = gevent.spawn(upon_receiving_N_minus_f_finish, finish_recvs, value_recvs, output_queue.put_nowait, store_dict)
    put_thread(_t)

    spawn_time = time.time() - spawn_time
    if logger: logger.info(f'spawn time:{spawn_time}')

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
