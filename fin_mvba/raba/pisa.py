import math
import os
import queue
import traceback
from enum import Enum
from typing import Callable, Dict

import gevent
from gevent.queue import Queue
from gevent.event import Event
from collections import defaultdict
import logging

from honeybadgerbft.exceptions import RedundantMessageError, AbandonedNodeError

def reproposable_binaryagreement(sid, pid, N, f,
                                 coin: Callable,
                                 input_msg: Callable,
                                 decide: Callable,
                                 broadcast: Callable,
                                 receive: Callable,
                                 repropose_event: Event = Event(),
                                 put_thread: Callable = lambda x: None,
                                 put_send_thread: Callable = lambda x: None,
                                 logger: logging.Logger = None):
    """Binary consensus from [MMR14]. It takes an input ``vi`` and will
    finally write the decided value into ``decide`` channel.

    :param sid: session identifier
    :param pid: my id number
    :param N: the number of parties
    :param f: the number of byzantine parties
    :param coin: a ``common coin(r)`` is called to block until receiving a bit
    :param input_msg: ``input_msg()`` is called to receive an input
    :param decide: ``decide(0)`` or ``decide(1)`` is eventually called
    :param broadcast: broadcast channel
    :param receive: receive channel
    :param put_thread: ``put_thread(t)`` is called to put a spawned thread ``t`` in a caller's queue
    :param logger: a logger passed by caller
    """

    _bcast = broadcast

    def broadcast(msg):
        if logger: logger.debug(
            f"[{sid}:{pid}] broadcast {msg}",
            extra={"nodeid": pid, "epoch": msg[1]},
        )
        _bcast(msg)

    ba_prefix = f'{sid}:pillar'

    class BroadcastTag(Enum):
        BVAL = f'{ba_prefix}/BVAL'
        AUX = f'{ba_prefix}/AUX'

    # Messages received are routed to either a shared coin, the broadcast, or AUX
    bval_est_values = defaultdict(lambda: {
        0: set(),
        1: set(),
    })

    aux_msgs = defaultdict(set)
    round_msgs = defaultdict(Queue)

    delta_values = defaultdict(lambda: {
        0: False,
        1: False,
    })

    coin_values = defaultdict(lambda: None)

    next_est_values = dict()
    next_maj_values = dict()

    bval_sent = defaultdict(
        lambda: {
            (0, 0): False,
            (0, 1): False,
            (1, 0): False,
            (1, 1): False,
            (0, None): False,
            (1, None): False
        }
    )

    bval_est_handled = defaultdict(lambda: {
        0: False,
        1: False,
    })

    aux_sent = defaultdict(lambda: False)

    bin_values = defaultdict(lambda: {
        0: set(),
        1: set(),
    })

    maj_values = defaultdict(lambda: {
        0: set(),
        1: set(),
        None: set()
    })

    bval_stops_1 = defaultdict(lambda: {
        0: Event(),
        1: Event(),
    })
    bval_stops_2 = defaultdict(lambda: {
        0: Event(),
        1: Event(),
    })
    aux_stops = defaultdict(Event)

    # This event is triggered whenever bin_values or aux_values changes
    # bv_signal = Event()
    # bval_signal = Event()
    round_increment_signal = Event()
    already_decided_signal = Event()

    def V1(counter_dict: Dict, _b_value):
        counter_dict = counter_dict.copy()
        if _b_value not in counter_dict:
            if logger: logger.warning('')
            return False
        for key in counter_dict:
            if _b_value != key and len(counter_dict[key]) != 0:
                return False
        if len(counter_dict[_b_value]) == 0:
            if logger: logger.warning('V1 warning')
        return True

    def quorum_value(counter_dict: Dict):
        counter_dict = counter_dict.copy()
        q = None
        for key in counter_dict:
            if key is None:
                continue
            if len(counter_dict[key]) != 0:
                if q is None:
                    q = key
                else:
                    return None
        return q

    def V2(counter_dict: Dict, _b_value):
        counter_dict = counter_dict.copy()
        if _b_value not in counter_dict:
            return None
        for key in counter_dict:
            if key is None:
                continue
            if _b_value != key and len(counter_dict[key]) != 0:
                return None
        return len(counter_dict[_b_value])

    def majority(counter_dict: Dict):
        total_size = 0
        for s in counter_dict.values():
            total_size += len(s)
        if len(counter_dict[0]) >= math.ceil((total_size + 1) / 2):
            return 0
        if len(counter_dict[1]) >= math.ceil((total_size + 1) / 2):
            return 1
        return None

    def pisa_handle_bval(_sender, _msg):
        tag, recv_round_num, v, c = _msg
        assert recv_round_num == 0
        assert v in (0, 1)
        assert c in (0, 1, None)

        # maj_values[recv_round_num][c].add(_sender)
        bval_est_values[recv_round_num][v].add(_sender)
        try:
            maj_r = next_maj_values[recv_round_num]
        except KeyError as e:
            if logger: logger.error(traceback.format_exc())
            raise e

        if not bval_stops_1[recv_round_num][v].ready() and len(bval_est_values[recv_round_num][v]) == f + 1:
            bval_stops_1[recv_round_num][v].set()

            if not bval_sent[recv_round_num][(v, maj_r)]:
                bval_sent[recv_round_num][(v, maj_r)] = True
                broadcast(
                    (BroadcastTag.BVAL.value, recv_round_num, v, maj_r)
                )

            if v == 1:
                b = v
                if _sender in bin_values[recv_round_num][b]:
                    if logger: logger.warning('')
                else:
                    bin_values[recv_round_num][b].add(_sender)
                    if logger: logger.debug(f'bin_values r{recv_round_num} b{b} {bin_values[recv_round_num][b]}')
                if not aux_sent[recv_round_num]:
                    aux_sent[recv_round_num] = True
                    broadcast(
                        (BroadcastTag.AUX.value, recv_round_num, 1, 1)
                    )
        if not bval_stops_2[recv_round_num][v].ready() and len(bval_est_values[recv_round_num][v]) == N - f:
            bval_stops_2[recv_round_num][v].set()
            b = v
            if _sender in bin_values[recv_round_num][b]:
                if logger: logger.warning('')
            else:
                bin_values[recv_round_num][b].add(_sender)
                if logger: logger.debug(f'bin_values r{recv_round_num} b{b} {bin_values[recv_round_num][b]}')
            if not aux_sent[recv_round_num]:
                aux_sent[recv_round_num] = True
                broadcast(
                    (BroadcastTag.AUX.value, recv_round_num, b, b)
                )

    def handle_bval(_sender, _msg):
        tag, recv_round_num, v, c = _msg
        assert v in (0, 1)
        assert c in (0, 1, None)
        maj_values[recv_round_num][c].add(_sender)
        bval_est_values[recv_round_num][v].add(_sender)

        try:
            maj_r = next_maj_values[recv_round_num]
        except KeyError as e:
            if logger: logger.error(traceback.format_exc())
            raise e


        if not bval_stops_1[recv_round_num][v].ready() and len(bval_est_values[recv_round_num][v]) == f + 1:
            bval_stops_1[recv_round_num][v].set()
            if not bval_sent[recv_round_num][(v, maj_r)]:
                bval_sent[recv_round_num][(v, maj_r)] = True
                broadcast(
                    (BroadcastTag.BVAL.value, recv_round_num, v, maj_r)
                )
            return


        b = None
        if not bval_est_handled[recv_round_num][0] and len(bval_est_values[recv_round_num][0]) == N - f:
            b = 0
            bval_est_handled[recv_round_num][0] = True
        elif not bval_est_handled[recv_round_num][1] and len(bval_est_values[recv_round_num][1]) == N - f:
            b = 1
            bval_est_handled[recv_round_num][1] = True

        if logger: logger.debug(f'{b}')
        if b is None:
            return

        if not bval_stops_2[recv_round_num][v].ready():
            bval_stops_2[recv_round_num][v].set()

        if _sender in bin_values[recv_round_num][b]:
            if logger: logger.warning('')
        else:
            bin_values[recv_round_num][b].add(_sender)
            if logger: logger.debug(f'bin_values r{recv_round_num} b{b} {bin_values[recv_round_num][b]}')

        if logger: logger.debug('')

        if recv_round_num == 0:
            delta_values[recv_round_num][b] = True
        else:
            if coin_values[recv_round_num - 1] is not None:
                s_r_1 = coin_values[recv_round_num - 1]
            else:
                if logger: logger.warning('')
                s_r_1 = coin(recv_round_num - 1)
            only_b_in_majs = V1(maj_values[recv_round_num], b)
            not_b_is_not_in_majs = len(maj_values[recv_round_num][1 - b]) == 0
            if logger: logger.debug(f'only_b_in_majs {only_b_in_majs} not_b_is_not_in_majs {not_b_is_not_in_majs}')
            if logger: logger.debug(f'maj_values[r {recv_round_num}] {maj_values[recv_round_num]}')
            delta_values[recv_round_num][b] = (((b == 1 - s_r_1) and only_b_in_majs)
                                               or ((b == s_r_1) and not_b_is_not_in_majs))
        if logger: logger.debug(f'delta_r[b {b}] {delta_values[recv_round_num][b]}')

        if not aux_sent[recv_round_num]:
            if delta_values[recv_round_num][b]:
                if logger: logger.debug('')
                broadcast(
                    (BroadcastTag.AUX.value, recv_round_num, b, b)
                )
            else:
                if logger: logger.debug('')
                broadcast(
                    (BroadcastTag.AUX.value, recv_round_num, None, b)
                )
            aux_sent[recv_round_num] = True
        else:
            if logger: logger.error(f'attempt to send aux twice in round {recv_round_num}')

        if logger: logger.debug('')

    def pisa_handle_aux(_sender, _msg):
        tag, recv_round_num, v1, v2 = _msg

        assert v1 in (0, 1, None)
        assert v2 in (0, 1, None)

        # ignore invalid AUX message
        if v2 is None:
            if logger: logger.warning('')
            return
        if (v1 == 0 and v2 == 1) or (v1 == 1 and v2 == 0):
            if logger: logger.warning('')
            return

        aux_msgs[recv_round_num].add((_sender, v1, v2))
        local_aux_v1_values = {
            0: set(),
            1: set(),
            None: set(),
        }

        local_aux_v2_values = {
            0: set(),
            1: set(),
        }

        for (_sender, v1, v2) in aux_msgs[recv_round_num]:
            # TODO: questionable
            if v1 is not None:
                # ignore aux message if v1 or v2 is not in bin_values (hence not in the subset)
                if len(bin_values[recv_round_num][v1]) == 0 or len(bin_values[recv_round_num][v2]) == 0:
                    if logger: logger.warning(f'ignore {(v1, v2)} since bin_values {bin_values[recv_round_num]}')
                    continue

                # discard message if \delta_r(\not v1) == 1
                if delta_values[recv_round_num][1 - v1]:
                    if logger: logger.warning('strange ignore')
                    # return

            local_aux_v1_values[v1].add(_sender)
            local_aux_v2_values[v2].add(_sender)

        total_size = 0
        for _v2 in (0, 1):
            total_size += len(local_aux_v2_values[_v2])

        if logger: logger.debug(f'total size {total_size}')
        # if total_size != N - f: # TODO check this
        #     return
        if total_size < N - f:
            return

        if aux_stops[recv_round_num].ready():
            if logger: logger.debug(f'repeat handle aux')
            return
        else:
            aux_stops[recv_round_num].set()

        if logger: logger.debug(f'coin a in round {recv_round_num}')
        if coin_values[recv_round_num] is None:
            coin_values[recv_round_num] = coin(recv_round_num)

        quorum_b = quorum_value(local_aux_v1_values)
        quorum_maj = quorum_value(local_aux_v2_values)

        if logger: logger.debug(f'quorum_b {quorum_b} quorum_maj {quorum_maj}')

        if quorum_b is not None and V2(local_aux_v1_values, quorum_b) >= math.ceil((N + f + 1) / 2):
            next_est_values[recv_round_num + 1] = quorum_b
            next_maj_values[recv_round_num + 1] = quorum_b
            if quorum_b == 1:
                if logger: logger.info(f'decide {quorum_b} in round {recv_round_num}')
                if not already_decided_signal.ready():
                    if logger: logger.info(f'decide!!!')
                    decide(quorum_b)
                    already_decided_signal.set()
                else:
                    if logger: logger.warning('oops, attempt to re-decide')
            # increment round
            round_increment_signal.set()
            return

        if (recv_round_num + 1) not in next_est_values:
            next_est_values[recv_round_num + 1] = 1
            next_maj_values[recv_round_num + 1] = 1
            # increment round
            round_increment_signal.set()
            return

    def handle_aux(_sender, _msg):
        tag, recv_round_num, v1, v2 = _msg

        assert v1 in (0, 1, None)
        assert v2 in (0, 1, None)

        # ignore invalid AUX message
        if v2 is None:
            if logger: logger.warning('')
            return
        if (v1 == 0 and v2 == 1) or (v1 == 1 and v2 == 0):
            if logger: logger.warning('')
            return

        aux_msgs[recv_round_num].add((_sender, v1, v2))
        local_aux_v1_values = {
            0: set(),
            1: set(),
            None: set(),
        }

        local_aux_v2_values = {
            0: set(),
            1: set(),
        }

        for (_sender, v1, v2) in aux_msgs[recv_round_num]:
            # TODO: questionable
            if v1 is not None:
                # ignore aux message if v1 or v2 is not in bin_values (hence not in the subset)
                if len(bin_values[recv_round_num][v1]) == 0 or len(bin_values[recv_round_num][v2]) == 0:
                    if logger: logger.warning(f'ignore {(v1, v2)} since bin_values {bin_values[recv_round_num]}')
                    continue

                # discard message if \delta_r(\not v1) == 1
                if delta_values[recv_round_num][1 - v1]:
                    if logger: logger.warning('strange ignore')
                    # return

            local_aux_v1_values[v1].add(_sender)
            local_aux_v2_values[v2].add(_sender)

        total_size = 0
        for _v2 in (0, 1):
            total_size += len(local_aux_v2_values[_v2])

        # if total_size != N - f: # TODO
        #     return
        if total_size < N - f:
            return

        if aux_stops[recv_round_num].ready():
            if logger: logger.debug(f'repeat handle aux')
            return
        else:
            aux_stops[recv_round_num].set()

        if logger: logger.debug(f'coin a in round {recv_round_num}')
        if coin_values[recv_round_num] is None:
            coin_values[recv_round_num] = coin(recv_round_num)

        if logger: logger.debug(f'coin b in round {recv_round_num}')
        s_r = coin_values[recv_round_num]
        if logger: logger.debug(f'coin c in round {recv_round_num}')

        quorum_b = quorum_value(local_aux_v1_values)
        quorum_maj = quorum_value(local_aux_v2_values)

        if logger: logger.debug(f'quorum_b {quorum_b} quorum_maj {quorum_maj}')

        if quorum_b is not None and V2(local_aux_v1_values, quorum_b) >= math.ceil((N + f + 1) / 2):
            next_est_values[recv_round_num + 1] = quorum_b
            next_maj_values[recv_round_num + 1] = quorum_b
            if quorum_b == s_r:
                if logger: logger.info(f'decide {quorum_b} in round {recv_round_num}')
                if not already_decided_signal.ready():
                    if logger: logger.info(f'decide!!!')
                    decide(quorum_b)
                    already_decided_signal.set()
                else:
                    if logger: logger.warning('oops, attempt to re-decide')
            # increment round
            round_increment_signal.set()
            return

        if recv_round_num > 0:
            if (V1(local_aux_v1_values, None)
                    or (quorum_b is not None and V2(local_aux_v1_values, quorum_b) < math.ceil(
                        (N + f + 1) / 2))):
                s_r_1 = coin_values[recv_round_num - 1]
                result = V2(local_aux_v2_values, quorum_maj)
                if logger: logger.debug(f'quorum_maj {quorum_maj} result {result}, s_r {s_r} s_r-1 {s_r_1}')
                if result is not None and result >= math.ceil((N + f + 1) / 2):
                    next_est_values[recv_round_num + 1] = quorum_maj
                    next_maj_values[recv_round_num + 1] = quorum_maj
                    if quorum_maj == s_r_1 and quorum_maj == s_r:
                        if logger: logger.info(f'decide {quorum_maj} in round {recv_round_num}')
                        if not already_decided_signal.ready():
                            if logger: logger.info(f'decide!!!')
                            decide(quorum_maj)
                            already_decided_signal.set()
                        else:
                            if logger: logger.warning('oops, attempt to re-decide')
                        return
                elif len(local_aux_v2_values[0]) > 0 and len(
                        local_aux_v2_values[1]) > 0 and quorum_maj == s_r_1:
                    next_est_values[recv_round_num + 1] = quorum_maj
                    next_maj_values[recv_round_num + 1] = quorum_maj

                # increment round
                round_increment_signal.set()
                return

        if (recv_round_num + 1) not in next_est_values:
            next_est_values[recv_round_num + 1] = s_r
            if recv_round_num == 0:
                next_maj_values[recv_round_num + 1] = s_r
            else:
                next_maj_values[recv_round_num + 1] = majority(local_aux_v1_values)
            # increment round
            round_increment_signal.set()
            return

    def _recv(_shared_round_num):
        while True:  # not finished[pid]:
            _round_num = _shared_round_num[0]
            if not round_msgs[_round_num].empty():
                (sender, msg) = round_msgs[_round_num].get()
            else:
                (sender, msg) = receive()
            if logger: logger.debug(
                f"[{sid}:{pid}] receive {msg} from node {sender}",
                extra={"nodeid": pid, "epoch": msg[1]},
            )
            assert sender in range(N)

            tag = msg[0]
            recv_round_num = msg[1]

            if recv_round_num > _round_num:
                round_msgs[recv_round_num].put_nowait((sender, msg))
                continue

            if tag == BroadcastTag.BVAL.value:
                if recv_round_num == 0:
                    pisa_handle_bval(sender, msg)
                else:
                    handle_bval(sender, msg)
                continue

            elif tag == BroadcastTag.AUX.value:
                if recv_round_num == 0:
                    pisa_handle_aux(sender, msg)
                else:
                    handle_aux(sender, msg)
                continue

    def repropose(_repropose_event: Event):
        _repropose_event.wait()
        if not bval_sent[0][(1, None)]:
            bval_sent[0][(1, None)] = True
            if logger: logger.debug(
                f"[{sid}:{pid}] repropose",
                extra={"nodeid": pid},
            )
            _bcast(
                (BroadcastTag.BVAL.value, 0, 1, None)
            )

    # Block waiting for the input
    vi = input_msg()
    assert vi in (0, 1)
    next_est_values[0] = vi
    next_maj_values[0] = None
    round_num = 0
    shared_round_num = [0]

    # Run the receive loop in the background
    _thread_recv = gevent.spawn(_recv, shared_round_num)
    put_thread(_thread_recv)

    _repropose_thread = gevent.spawn(repropose, repropose_event)
    put_thread(_thread_recv)

    try:
        while True:  # Unbounded number of rounds
            try:
                est = next_est_values[round_num]
                maj = next_maj_values[round_num]
            except KeyError as e:
                if logger: logger.error(traceback.format_exc())
                raise e

            if logger: logger.debug(
                f"[{sid}:{pid}] Starting with est = {est} in round {round_num}", extra={"nodeid": pid, "epoch": round_num}
            )

            # bin_values[r] is empty by default

            # broadcast bval(r, est, maj)
            if not bval_sent[round_num][(est, maj)]:
                bval_sent[round_num][(est, maj)] = True
                broadcast(
                    (BroadcastTag.BVAL.value, round_num, est, maj)
                )

            # pisa
            if round_num == 0:
                if est == 1:
                    bin_values[round_num][1].add(pid)
                    if logger: logger.debug(f'bin_values r{round_num} b{1} {bin_values[round_num][1]}')
                    if not aux_sent[round_num]:
                        aux_sent[round_num] = True
                        broadcast(
                            (BroadcastTag.AUX.value, round_num, 1, 1)
                        )

            round_increment_signal.wait()
            round_increment_signal.clear()

            # if already_decided_signal.ready():
            #     break

            round_num += 1
            shared_round_num[0] += 1
    finally:
        _thread_recv.kill()

