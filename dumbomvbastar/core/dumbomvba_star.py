import logging
from typing import Callable

import hashlib
import pickle
import traceback
import gevent
from gevent import monkey
monkey.patch_all(thread=False)

from collections import namedtuple
from gevent.event import Event
from enum import Enum
from collections import defaultdict
from gevent.queue import Queue
from gevent.lock import BoundedSemaphore

from crypto.ecdsa.ecdsa import ecdsa_vrfy
# from dumbomvbastar.core.provabledispersal import provabledispersalbroadcast
from dumbomvbastar.core.provabledispersal_star import provabledispersalbroadcast
from dumbomvbastar.core.recast import recastsubprotocol
from honeybadgerbft.exceptions import UnknownTagError
# from speedmvba.core.smvba_e_cp import speedmvba
from speedmvba_bls.core.smvba_bls import speedmvba as speedmvba_bls
from speedmvba.core.smvba_e import speedmvba as speedmvba_ecdsa

class MessageTag(Enum):
    MVBA_PD = 'MVBA_PD'  # [Queue()] * N
    MVBA_RC = 'MVBA_RC'
    MVBA_UNDER = 'MVBA_UNDER'


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('MVBA_PD', 'MVBA_RC', 'MVBA_UNDER'))


def recv_loop(recv_func, recv_queues):
    while True:
        gevent.sleep(0)
        sender, (tag, j, msg) = recv_func()
        if tag not in MessageTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, MessageTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]
        # if tag == MessageTag.MVBA_PD.value or tag == MessageTag.MVBA_RC:
        recv_queue = recv_queue[j]
        try:
            recv_queue.put_nowait((sender, msg))
            # if logger: logger.debug((tag, sender, j, msg[0]))
        except AttributeError as e:
            traceback.print_exc(e)


def smvbastar(
        sid, pid, N, f,
        PK, SK,
        PK1, SK1,
        PK2s, SK2,
        input, decide,
        receive, send,
        put_thread: Callable=lambda x: None,
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
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide()`` is eventually called
    :param receive: receive channel
    :param send: send channel
    :param predicate: ``predicate()`` represents the externally validated condition
    """
    assert PK.k == f + 1
    assert PK.l == N

    pd = [None for n in range(N)]

    store = [Queue(1) for _ in range(N)]
    lock = [Queue(1) for _ in range(N)]
    my_lock_queue = Queue()
    my_pd_input = Queue(1)

    pd_recvs = [Queue() for _ in range(N)]
    rc_recv = defaultdict(lambda: Queue())
    under_recv = defaultdict(lambda: Queue())

    pd_outputs = [Queue() for _ in range(N)]
    pd_leader_outputs = [Queue(1) for _ in range(N)]
    pd_abandon_events = [Event() for _ in range(N)]

    recv_queues = MessageReceiverQueues(
        MVBA_PD=pd_recvs,
        MVBA_RC=rc_recv,
        MVBA_UNDER=under_recv
    )

    recv_thread = gevent.spawn(recv_loop, receive, recv_queues)

    v = input()
    my_pd_input.put(str(v))

    # start n PD instances
    for j in range(N):
        def make_pd_send(j):  # this make will automatically deep copy the enclosed send func
            def pd_send(k, o):
                """PD send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # if logger: logger.debug(f"sender{pid} recevier{k} PD[{j}] {o}")
                send(k, ('MVBA_PD', j, o))

            return pd_send

        # Only leader gets input
        pd_input = my_pd_input.get if j == pid and predicate(v) else None
        #
        pd[j] = gevent.spawn(
            provabledispersalbroadcast,
            f'{sid}PD{j}',
            pid, N, f,
            PK2s, SK2,
            j,
            pd_input,
            pd_outputs[j].put_nowait,
            pd_recvs[j].get,
            make_pd_send(j),
            logger=logger
        )
        # pd_leader_outputs[j] = pd[j].get

    pd_count = [0 for _ in range(N)]
    pd_count_lock = [BoundedSemaphore for _ in range(N)]

    def hash(x):
        return hashlib.sha256(pickle.dumps(x)).digest()

    # def output_receve():
    #     def o_recv(j):
    #         def _recv():

    #             (mtype, context, sid_t, _pid) = pd_outputs[j].get()
    #             # print 'RECV %8s [%2d -> %2d]' % (o[0], i, j)
    #             return (mtype, context, sid_t, _pid)
    #         return _recv
    #     return [o_recv(j) for j in range(N)]

    # recv_pds = output_receve()

    # recv_pds = list()
    # for j in range(N):
    #     recv_pds.append(pd_outputs[j].get)

    wait_lock_signal = Event()
    wait_lock_signal.clear()

    def get_PD_output(recv_func, j):
        # TODO: check this
        while pd_count[j] < 2:
            gevent.sleep(0)
            # if logger: logger.debug(f'before recv PD[{j}] count{pd_count[j]}')
            (mtype, context, sid_t, _pid) = recv_func()
            # if logger: logger.debug(("output: ", (j, mtype, sid, _pid)))
            if mtype == 'STORE':
                store[j].put_nowait(context)
                pd_count[j] += 1
                # if logger: logger.debug(("A: count[] += 1", (j, mtype, sid, _pid)))
            elif mtype == 'LOCK':
                if lock[j].qsize() == 0:
                    lock[j].put_nowait((context[0], context[1]))
                    pd_count[j] += 1
                    # if logger: logger.debug(("B: count[] += 1", (j, mtype, sid, _pid)))
                if j == _pid:
                    try:
                        my_lock_queue.put_nowait((context[0], context[1]))
                    except Exception as e:
                        if logger: logger.warning('multiple my lock!!')
                        if logger: logger.error(str(e))
                        if logger: logger.error(traceback.format_exc())
                    wait_lock_signal.set()
        if logger: logger.debug(f'PD[{j}] output done')

    # for j in range(N):
    #     gevent.spawn(
    #         get_PD_output,
    #         recv_pds[j],
    #         j
    #     )

    for j in range(N):
        gevent.spawn(
            get_PD_output,
            pd_outputs[j].get,
            j
        )
    
    if logger: logger.debug('waiting lock signal')
    wait_lock_signal.wait()
    if logger: logger.debug('unblock lock signal')
    r = 0

    while True:
        def make_under_send(r):  # this make will automatically deep copy the enclosed send func
            def under_send(k, o):
                """MVBA under send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                send(k, ('MVBA_UNDER', r, o))
                # if logger: logger.debug(("node", pid, "is sending", o, "to node", k, "in round ", r))

            return under_send

        def make_rc_send(r):  # this make will automatically deep copy the enclosed send func
            def rc_send(k, o):
                """PD send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # if logger: logger.debug(("node", pid, "is sending", o, "to node", k))
                send(k, ('MVBA_RC', r, o))

            return rc_send

        # invoke mvba as a black box
        vaba_input = Queue(1)
        vaba_output = Queue(1)

        if logger: logger.debug("before peeking my_lock")
        _my_lock = my_lock_queue.peek()
        if logger: logger.debug("after peeking my_lock")
        vaba_input.put_nowait((pid, _my_lock))

        def make_under_predicate():
            def vaba_predicate(vj):
                (id_j, lock_msg) = vj
                (roothash, Sigma) = lock_msg
                try:
                    # assert stop == 0
                    digest = hash(str(('STORED', sid + 'PD' + str(id_j), roothash)))
                    try:
                        for (k, sig) in Sigma:
                            assert ecdsa_vrfy(PK2s[k], digest, sig)
                    except AssertionError as e:
                        if logger: logger.error(("Signature failed!", e))
                        return 0
                except Exception as e:
                    if logger: logger.error(("Failed to validate LOCK message:", e))
                    return 0
                return True

            return vaba_predicate


        # under_thread_r = gevent.spawn(
        #     speedmvba_bls,
        #     sid + 'MVBA-UNDER',
        #     pid, N, f,
        #     PK, SK,
        #     PK1, SK1,
        #     PK2s, SK2,
        #     vaba_input.get,
        #     vaba_output.put_nowait,
        #     under_recv[r].get,
        #     make_under_send(r),
        #     put_thread=put_thread,
        #     predicate=make_under_predicate(),
        #     logger=logger
        # )

        under_thread_r = gevent.spawn(
            speedmvba_ecdsa,
            sid + 'MVBA-UNDER',
            pid, N, f,
            PK, SK,
            PK2s, SK2,
            vaba_input.get,
            vaba_output.put_nowait,
            under_recv[r].get,
            make_under_send(r),
            put_thread=put_thread,
            predicate=make_under_predicate(),
            logger=logger
        )

        if logger: logger.debug("before vaba output")
        out = vaba_output.get()
        if logger: logger.debug(f"after vaba output")
        # if logger: logger.debug(f"{type(out)} {out}")

        (l, lock_l) = out
        if lock[l].qsize() == 0:
            lock[l].put_nowait(lock_l)
        if logger: logger.debug((pid, "start rc in ", sid))
        rc = gevent.spawn(
            recastsubprotocol,
            pid, sid + 'PD' + str(l),
            N, f,
            PK2s, SK2,
            rc_recv[r].get,
            make_rc_send(r),
            store[l].get,
            lock[l].get,
            logger=logger
        )
        rc_out = rc.get()
        # if logger: logger.debug((pid, "returns in ", sid))
        # if logger: logger.debug(tuple(eval(rc_out)))
        if predicate(rc_out):
            if rc_out != v:
                if logger: logger.warning('mvba input output mismatch')
            decide(rc_out)
            break
        else:
            r = r + 1
    gevent.joinall(pd)
    # recv_thread.join()
