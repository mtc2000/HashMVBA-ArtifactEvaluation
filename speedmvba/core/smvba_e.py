import logging
import queue
from typing import Callable

from gevent import monkey;
monkey.patch_all(thread=False)

from speedmvba.core.spbc_ec import strongprovablebroadcast
import hashlib
import pickle
import copy
import time
import traceback
from datetime import datetime
import gevent
import numpy as np
from collections import namedtuple
from gevent import Greenlet
from gevent.event import Event
from enum import Enum
from collections import defaultdict
from gevent.queue import Queue
from gevent.lock import BoundedSemaphore
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from honeybadgerbft.exceptions import UnknownTagError


# from pympler.classtracker import ClassTracker


class MessageTag(Enum):
    MVBA_SPBC = 'MVBA_SPBC'  # [Queue()] * N
    MVBA_ELECT = 'MVBA_ELECT'  #
    MVBA_ABA = 'MVBA_ABA'  # [Queue()] * Number_of_ABA_Iterations
    MVBA_HALT = 'MVBA_HALT'
    MVBA_DUM = 'MVBA_DUM'


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('MVBA_SPBC', 'MVBA_ELECT', 'MVBA_ABA', 'MVBA_HALT', 'MVBA_DUM'))


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def recv_loop(pid, recv_func, recv_queues):
    while True:
        sender, (tag, r, j, msg) = recv_func()
        # if logger: logger.debug(("recv2", (sender, (tag, j, msg))))

        if tag not in MessageTag.__members__:
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, MessageTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]
        if tag in {MessageTag.MVBA_SPBC.value}:
            recv_queue = recv_queue[r][j]
        elif tag in {MessageTag.MVBA_ELECT.value, MessageTag.MVBA_DUM.value}:
            recv_queue = recv_queue
        elif tag in {MessageTag.MVBA_HALT.value}:
            # if pid == 3: if logger: logger.debug(("-------------------------------- Receive a HALT msg from %d" % sender))
            recv_queue = recv_queue
        else:
            recv_queue = recv_queue[r]
        try:
            recv_queue.put((sender, msg))
            # if tag in {MessageTag.MVBA_HALT.value}:
            #     if pid == 3: if logger: logger.debug(("-------------------------------- HALT msg from %d is placed in the queue" % sender))
        except Exception as e:
            # if logger: logger.debug(((sender, msg)))
            traceback.print_exc(e)
        gevent.sleep(0)


def speedmvba(
        sid, pid, N, f,
        PK, SK,
        PK2s, SK2,
        input, decide, receive, send,
        put_thread: Callable,
        predicate=lambda x: True,
        logger: logging.Logger=None
    ):
    """Multi-valued Byzantine consensus. It takes an input ``vi`` and will
    finally writes the decided value into ``decide`` channel.
    :param sid: session identifier
    :param pid: my id number
    :param N: the number of parties
    :param f: the number of byzantine parties
    :param PK: ``boldyreva.TBLSPublicKey`` with threshold f+1
    :param SK: ``boldyreva.TBLSPrivateKey`` with threshold f+1
    :param PK1: ``boldyreva.TBLSPublicKey`` with threshold n-f
    :param SK1: ``boldyreva.TBLSPrivateKey`` with threshold n-f
    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide()`` is eventually called
    :param receive: receive channel
    :param send: send channel
    :param predicate: ``predicate()`` represents the externally validated condition
    :param put_thread: ``put_thread(t)`` is called to put a spawned thread ``t`` in a caller's queue
    """

    hasOutputedLock = BoundedSemaphore(1)
    hasOutputed = False
    s_t = time.time()
    # if logger: logger.debug(("Starts to run validated agreement..."))

    assert PK.k == f + 1, f'{PK.k} != {f} + 1'
    assert PK.l == N

    sign_threshold = N - f

    """ 
    """
    """ 
    Some instantiations
    """
    """ 
    """

    r = 0

    my_msg = Queue(1)

    my_spbc_input = Queue(1)

    halt_send = Queue()

    vote_recvs = defaultdict(lambda: Queue())
    aba_recvs = defaultdict(lambda: Queue())

    spbc_recvs = defaultdict(lambda: [Queue() for _ in range(N)])
    coin_recv = Queue()
    halt_recv = Queue()

    spbc_threads = [None] * N
    spbc_outputs = [Queue(1) for _ in range(N)]
    spbc_s1_list = [Queue(1) for _ in range(N)]
    s1_list = [Queue(1) for _ in range(N)]

    is_spbc_delivered = [0] * N
    is_s1_delivered = [0] * N

    # leaders = [Queue(1) for _ in range(50)]
    leaders = defaultdict(lambda: Queue(1))

    recv_queues = MessageReceiverQueues(
        MVBA_SPBC=spbc_recvs,
        MVBA_ELECT=coin_recv,
        MVBA_ABA=aba_recvs,
        MVBA_HALT=halt_recv,
        MVBA_DUM=Queue()
    )


    okay_to_stop = Event()
    okay_to_stop.clear()

    start_wait_for_halt = Event()
    start_wait_for_halt.clear()


    def broadcast(o):
        # for i in range(N):
        #     send(i, o)
        send(-1, o)

    recv_loop_thred = Greenlet(recv_loop, pid, receive, recv_queues)
    recv_loop_thred.start()


    def views():
        nonlocal hasOutputed, r

        def spbc_predicate(m):
            # if logger: logger.debug(("------", m))
            msg, proof, round, tag = m

            # both yes and no vote
            if round == 0:
                return 3
            if logger: logger.debug('before get')
            L = leaders[round].get()
            if logger: logger.debug('after get')
            if tag == 'yn':
                hash_e = hash(str((sid + 'SPBC' + str(L), msg, "ECHO")))
                try:
                    for (k, sig_k) in proof:
                        assert ecdsa_vrfy(PK2s[k], hash_e, sig_k)
                except AssertionError:
                    if logger: logger.warning("sig L verify failed!")
                    # if logger: logger.debug(("sig L verify failed!"))
                    return -1
                return 1
            if tag == 'no':
                digest_no_no = hash(str((sid, L, r - 1, 'vote')))
                try:
                    for (k, sig_nono) in proof:
                        assert ecdsa_vrfy(PK2s[k], digest_no_no, sig_nono)
                except AssertionError:
                    if logger: logger.warning("sig nono verify failed!")
                    # if logger: logger.debug(("sig nono verify failed!"))
                    return -2
                return 2

        while not start_wait_for_halt.is_set():
            """ 
            Setup the sub protocols Input Broadcast SPBCs"""
            for j in range(N):
                def make_spbc_send(j, r):  # this make will automatically deep copy the enclosed send func
                    def spbc_send(k, o):
                        """SPBC send operation.
                        :param k: Node to send.
                        :param o: Value to send.
                        """
                        # if logger: logger.debug(("node", pid, "is sending", o[0], "to node", k, "with the leader", j))
                        send(k, ('MVBA_SPBC', r, j, o))

                    return spbc_send

                # Only leader gets input
                spbc_input = my_spbc_input.get if j == pid else None
                spbc = gevent.spawn(
                    strongprovablebroadcast,
                    sid + 'SPBC' + str(j),
                    pid, N, f,
                    PK2s, SK2,
                    j,
                    spbc_input,
                    spbc_s1_list[j].put_nowait,
                    spbc_recvs[r][j].get,
                    make_spbc_send(j, r),
                    r,
                    logger,
                    spbc_predicate
                )

                spbc_threads[j] = spbc
                put_thread(spbc)

            """ 
            Setup the sub protocols permutation coins"""

            def coin_bcast(o):
                """Common coin multicast operation.
                :param o: Value to multicast.
                """
                broadcast(('MVBA_ELECT', r, 'leader_election', o))

            # permutation_coin = shared_coin(sid + 'PERMUTE', pid, N, f,
            #                               PK, SK, coin_bcast, coin_recv.get, single_bit=False)

            # if logger: logger.debug((pid, "coin share start"))
            # False means to get a coin of 256 bits instead of a single bit

            """ 
            """
            """ 
            Start to run consensus
            """
            """ 
            """

            """ 
            Run n SPBC instance to consistently broadcast input values
            """

            # cbc_values = [Queue(1) for _ in range(N)]
            def wait_for_input():
                v = input()
                my_msg.put_nowait(v)

                my_spbc_input.put_nowait((v, "null", 0, "first"))
                # if logger: logger.debug((v[0]))

            if r == 0:
                _t = gevent.spawn(wait_for_input)
                put_thread(_t)

            def get_spbc_s1(leader):
                if logger: logger.debug('before get')
                sid, pid, msg, sigmas1 = spbc_s1_list[leader].get()
                if logger: logger.debug('after get')
                if logger: logger.debug((sid, pid, "finish pcbc in round", r))
                if not s1_list[leader].empty():
                    if logger: logger.debug('before get')
                    s1_list[leader].get()
                    if logger: logger.debug('after get')

                s1_list[leader].put_nowait((msg, sigmas1))
                is_s1_delivered[leader] = 1

            spbc_s1_threads = [gevent.spawn(get_spbc_s1, node) for node in range(N)]
            for _t in spbc_s1_threads:
                put_thread(_t)

            wait_spbc_signal = Event()
            wait_spbc_signal.clear()

            def wait_for_spbc_to_continue(leader):
                # Receive output from CBC broadcast for input values
                try:
                    if logger: logger.debug('before get')
                    msg, sigmas2 = spbc_threads[leader].get()
                    if logger: logger.debug("spbc finished")
                    # if logger: logger.debug("and the msg is", msg[0])
                    if predicate(msg[0]):
                        try:
                            if not spbc_outputs[leader].empty():
                                if logger: logger.debug('before get')
                                spbc_outputs[leader].get()
                                if logger: logger.debug('after get')
                            spbc_outputs[leader].put_nowait((msg, sigmas2))
                            is_spbc_delivered[leader] = 1
                            # TODO: check this
                            if sum(is_spbc_delivered) >= sign_threshold:
                                wait_spbc_signal.set()
                        except:
                            pass
                    else:
                        pass
                except:
                    pass

            spbc_out_threads = [gevent.spawn(wait_for_spbc_to_continue, node) for node in range(N)]
            for _t in spbc_out_threads:
                put_thread(_t)

            wait_spbc_signal.wait()

            """
            Run a Coin instance to elect the leaders
            """
            # time.sleep(0.05)
            seed = int.from_bytes(hash(sid + str(r)), byteorder='big') % (2 ** 10 - 1)

            # seed = permutation_coin('permutation')  # Block to get a random seed to permute the list of nodes

            # if logger: logger.debug(("coin has a seed:", seed))
            leader = seed % N
            leaders[r].put(leader)
            if is_spbc_delivered[leader] == 1:
                if logger: logger.debug('before get')
                msg, s2 = spbc_outputs[leader].get()
                if logger: logger.debug('after get')
                halt_msg = (leader, 2, msg, s2)
                # broadcast(('MVBA_HALT', r, pid, ("halt", halt)))
                halt_send.put_nowait(('MVBA_HALT', r, pid, ("halt", halt_msg)))
                if logger: logger.warning("round %d smvba decide in shortcut. %f" % (r, time.time()-s_t))

                hasOutputedLock.acquire()
                hasOutputed = True
                hasOutputedLock.release()
                okay_to_stop.set()
                start_wait_for_halt.set()
                # except:
                #    if logger: logger.debug(("2 can not"))
                #    pass
                return 2
            if is_s1_delivered[leader] == 1:
                msg, s1 = s1_list[leader].queue[0]
                prevote = (leader, 1, msg, s1)
                # if logger: logger.debug((pid, sid, "prevote in round ", r))
            else:
                digest_no = hash(str((sid, leader, r, 'pre')))
                # digest_no = PK1.hash_message(str((sid, leader, r, 'pre')))
                prevote = (leader, 0, "bottom", ecdsa_sign(SK2, digest_no))
                # prevote = (leader, 0, "bottom", SK1.sign(digest_no))
                # if logger: logger.debug((pid, sid, "prevote no in round ", r))
            broadcast(('MVBA_ABA', r, r, ('prevote', prevote)))

            prevote_no_shares = dict()
            vote_yes_shares = dict()
            vote_no_shares = dict()


            def vote_loop():

                nonlocal hasOutputed, r

                okay_to_stop.clear()

                hasVoted = False
                while not hasOutputed and not okay_to_stop.is_set() and not start_wait_for_halt.is_set():
                    # gevent.sleep(0)
                    # hasOutputed = False
                    try:
                        # gevent.sleep(0.001)
                        if logger: logger.debug('before get')
                        sender, aba_msg = aba_recvs[r].get(0.001)
                        if logger: logger.debug('after get')
                        aba_tag, vote_msg = aba_msg
                        if aba_tag == 'prevote' and not hasVoted:
                            digest_no = hash(str((sid, leader, r, 'pre')))
                            vote_yes_msg = 0
                            # prevote no
                            if vote_msg[1] != 1:
                                # if logger: logger.debug((pid, "get prevote no in round", r))
                                try:
                                    assert vote_msg[0] == leader
                                    # assert (ecdsa_vrfy(PK2s[sender], digest_no, vote_msg[3]))
                                    # assert (PK1.verify_share(vote_msg[3], sender, digest_no) == 1)
                                except AssertionError:
                                    if logger: logger.warning("pre-vote no failed!")
                                    # if logger: logger.debug(("pre-vote no failed!"))
                                    pass
                                prevote_no_shares[sender] = vote_msg[3]
                                if len(prevote_no_shares) == sign_threshold:
                                    sigmas_no = tuple(list(prevote_no_shares.items())[:sign_threshold])
                                    digest_no_no = hash(str((sid, leader, r, 'vote')))
                                    vote = (leader, 0, "bottom", sigmas_no, ecdsa_sign(SK2, digest_no_no))
                                    broadcast(('MVBA_ABA', r, r, ('vote', vote)))
                                    # if logger: logger.debug((pid, "vote no in round", r))
                                    # if pid ==3: if logger: logger.debug(("VOTE 0"))
                                    hasVoted = True

                            elif vote_msg[1] == 1:
                                try:
                                    assert vote_msg[0] == leader
                                    # for (k, sig_k) in vote_msg[3]:
                                    #     assert ecdsa_vrfy(PK2s[k], _hash(str((sid + 'SPBC' + str(leader), vote_msg[2], "ECHO"))),
                                    #                       sig_k)
                                except AssertionError:
                                    if logger: logger.warning("pre-vote Signature failed!")
                                    # if logger: logger.debug(("pre-vote Signature failed!"))
                                    pass
                                pii = hash(str((sid + 'SPBC' + str(leader), vote_msg[2], "FINAL")))
                                vote = (leader, 1, vote_msg[2], vote_msg[3], ecdsa_sign(SK2, pii))
                                broadcast(('MVBA_ABA', r, r, ('vote', vote)))
                                # if pid ==3: if logger: logger.debug(("VOTE 1"))
                                hasVoted = True

                        # vote yes
                        if aba_tag == 'vote':
                            # if pid == 3: if logger: logger.debug(("Receive VOTE from %d towards %d" % (sender, vote_msg[1])))
                            if vote_msg[1] == 1:
                                if vote_msg[0] != leader:
                                    if logger: logger.debug(("wrong leader"))
                                    if logger: logger.warning("wrong leader")

                                hash_e = hash(str((sid + 'SPBC' + str(leader), vote_msg[2], "ECHO")))
                                try:
                                    for (k, sig_k) in vote_msg[3]:
                                        assert ecdsa_vrfy(PK2s[k], hash_e,
                                                          sig_k)
                                    # assert PK1.verify_signature(vote_msg[3], PK1.hash_message(str((sid + 'SPBC' + str(leader), vote_msg[2], "ECHO"))))
                                    assert ecdsa_vrfy(PK2s[sender],
                                                      hash(str((sid + 'SPBC' + str(leader), vote_msg[2], "FINAL"))),
                                                      vote_msg[4])
                                except AssertionError:
                                    if logger: logger.warning("vote Signature failed!")
                                    # if logger: logger.debug(("vote Signature failed!"))
                                    #continue
                                    pass

                                vote_yes_shares[sender] = vote_msg[4]
                                vote_yes_msg = vote_msg[2]
                                # 2f+1 vote yes

                                # if pid == 3: print("++++++++++++++++++++++++++++++++++round %d smvba vote numbers YES: %d, NO: %d" %
                                #                    (r, len(vote_yes_shares), len(vote_no_shares) )
                                #                    )


                                if len(vote_yes_shares) == sign_threshold:

                                    halt_msg = (leader, 2, vote_msg[2], tuple(list(vote_yes_shares.items())[:sign_threshold]))
                                    # broadcast(('MVBA_HALT', r, pid, ("halt", halt)))
                                    # if logger: logger.debug((pid, sid, "halt here 3"))
                                    if logger: logger.warning("round %d smvba decide in vote yes %f" % (r, time.time()-s_t))

                                    halt_send.put_nowait(('MVBA_HALT', r, pid, ("halt", halt_msg)))

                                    hasOutputedLock.acquire()
                                    hasOutputed = True
                                    hasOutputedLock.release()
                                    okay_to_stop.set()
                                    start_wait_for_halt.set()
                                    return 1
                            # vote no
                            if vote_msg[1] == 0:
                                if vote_msg[0] != leader:
                                    if logger: logger.debug(("wrong leader"))
                                    if logger: logger.warning("wrong leader")

                                hash_pre = hash(str((sid, leader, r, 'pre')))
                                try:
                                    # vrify sigmas_no
                                    for (k, sig_k) in vote_msg[3]:
                                        assert ecdsa_vrfy(PK2s[k], hash_pre, sig_k)

                                except AssertionError:
                                    if logger: logger.warning("vote no failed!")
                                    # if logger: logger.debug((pid, "vote no failed! sigmas in round", r))
                                    pass

                                try:
                                    # vrify no_no
                                    digest_no_no = hash(str((sid, leader, r, 'vote')))
                                    assert ecdsa_vrfy(PK2s[sender], digest_no_no, vote_msg[4])
                                except AssertionError:
                                    if logger: logger.warning("vote no failed!")
                                    # if logger: logger.debug(("vote no failed!, digest_no_no, in round", r))
                                    pass

                                vote_no_shares[sender] = vote_msg[4]

                                if len(vote_no_shares) == sign_threshold:
                                    pis = tuple(list(vote_no_shares.items())[:sign_threshold])
                                    # if logger: logger.debug((pid, sid, "n-f no vote, move to next round with in round", r))
                                    r += 1
                                    my_msg_error_flag = False
                                    if my_msg.qsize() < 1:
                                        if logger: logger.error('my_msg is not ready')
                                        my_msg_error_flag = True
                                    while my_msg.qsize() < 1:
                                        gevent.sleep(0.0001)
                                    if my_msg_error_flag:
                                        if logger: logger.error('my_msg is ready')
                                    _my_msg = my_msg.peek()
                                    my_spbc_input.put_nowait((_my_msg, pis, r, 'no'))
                                    # my_spbc_input.put_nowait(my_msg)

                                    prevote_no_shares.clear()
                                    vote_yes_shares.clear()
                                    vote_no_shares.clear()
                                    okay_to_stop.set()
                                    # r = r % 10
                                    break
                            # both vote no and vote yes
                            if (len(vote_no_shares) > 0) and (len(vote_yes_shares) > 0):
                                # if logger: logger.debug(("both vote no and vote yes, move to next round with"))
                                r += 1
                                my_spbc_input.put_nowait((vote_yes_msg[0], vote_msg[3], r, 'yn'))
                                # my_spbc_input.put_nowait(vote_yes_msg)

                                prevote_no_shares.clear()
                                vote_yes_shares.clear()
                                vote_no_shares.clear()
                                okay_to_stop.set()
                                # r = r % 10
                                break
                    except Exception as e:
                        if logger: logger.error(str(e))
                        #traceback.print_exc(e)
                        continue

            _t = gevent.spawn(vote_loop)
            put_thread(_t)
            if logger: logger.debug('before wait')
            okay_to_stop.wait()
            if logger: logger.debug('after wait')

    view_change_thred = gevent.Greenlet(views)
    view_change_thred.start()
    put_thread(view_change_thred)

    def recv_halt():
        nonlocal hasOutputed, r, decide, halt_recv

        while decide is not None and halt_recv is not None:
            gevent.sleep(0.0001)
            try:
                sender, halt = halt_recv.get_nowait()
            except queue.Empty:
                #traceback.print_exc()
                # if logger: logger.warning('halt_recv timeout')
                continue

            halt_tag, halt_msg = halt
            if halt_tag == 'halt':
                hash_f = hash(str((sid + 'SPBC' + str(halt_msg[0]), halt_msg[2], "FINAL")))
                try:
                    # if logger: logger.debug(("-----------------", halt_msg))
                    for (k, sig_k) in halt_msg[3]:
                        assert ecdsa_vrfy(PK2s[k], hash_f, sig_k)
                except AssertionError:
                    if logger: logger.warning("vote Signature failed!")
                    continue

                # send(-2, ('MVBA_HALT', r, pid, ("halt", halt_msg)))
                halt_send.put_nowait(('MVBA_HALT', r, pid, ("halt", halt_msg)))

                output_tx = halt_msg[2][0]
                try:
                    assert my_msg.qsize() > 0
                    _my_msg = my_msg.peek()
                    assert output_tx == _my_msg
                except AssertionError:
                    if logger: logger.warning('output_tx is not the same as input')
                    # try:
                    #     if logger: logger.warning(f'{output_tx[:400]}')
                    #     if logger: logger.warning(f'{_my_msg[:400]}')
                    # except Exception as e:
                    #     if logger: logger.error(str(e))
                    #     if logger: logger.error(traceback.format_exc())
                decide(output_tx)
                hasOutputedLock.acquire()
                hasOutputed = True
                hasOutputedLock.release()
                start_wait_for_halt.set()
                okay_to_stop.set()
                decide = None
                halt_recv = None

                if logger: logger.warning("round %d smvba decide in halt in %f second" % (r, time.time()-s_t))
                break
                # return 2
        return 2

    def send_halt():
        if logger: logger.debug('before get')
        o = halt_send.get()
        if logger: logger.debug('after get')
        for _ in range(3): # while True:
            # gevent.sleep(0.0001)
            try:
                (_, rx, pidx, (_, haltx)) = o
                send(-1, ('MVBA_HALT', rx, pidx, ("halt", haltx)))
                break
            except Exception as err:
                # traceback.print_exc(err)
                if logger: logger.error(str(err))
                continue

    halt_recv_thred = gevent.Greenlet(recv_halt)
    halt_send_thred = gevent.Greenlet(send_halt)
    put_thread(halt_recv_thred)
    put_thread(halt_send_thred)
    halt_recv_thred.start()
    halt_send_thred.start()
    halt_recv_thred.join()
    halt_recv_thred.kill()

    halt_send_thred.join()
    gevent.sleep(0.01)
    recv_loop_thred.kill()
