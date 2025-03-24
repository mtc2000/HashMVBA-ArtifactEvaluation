import logging
from queue import Queue
import traceback

from gevent import monkey;

monkey.patch_all(thread=False)

from datetime import datetime
from collections import defaultdict
import hashlib, pickle
from crypto.threshsig.boldyreva import serialize, deserialize1
from crypto.threshsig.boldyreva import TBLSPrivateKey, TBLSPublicKey

def ec_hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

from charm.toolbox.pairinggroup import PairingGroup, G1

group = PairingGroup('MNT224')

def bls_hash(x):
    raw_hash = hashlib.sha256(pickle.dumps(x)).digest()
    return group.hash(raw_hash, G1)

_hash = bls_hash

from charm.core.math.pairing import pc_element
from crypto.threshsig.boldyreva import serialize

def measure_secret(secret) -> int:
    secret_bytes = None
    if isinstance(secret, pc_element):
        secret_bytes = serialize(secret)
    else:
        secret_bytes = pickle.dumps(secret)
    return len(secret_bytes)

def strongprovablebroadcast(
        sid,
        pid, N, f,
        PK1: TBLSPublicKey, SK1: TBLSPrivateKey,
        leader,
        input, output,
        receive, send, r,
        logger: logging.Logger=None,
        predicate=lambda x: True
    ):
    """Consistent broadcast
    :param str sid: session identifier
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param PK1: ``boldyreva.TBLSPublicKey`` with threshold n-f
    :param SK1: ``boldyreva.TBLSPrivateKey`` with threshold n-f
    :param int leader: ``0 <= leader < N``
    :param input: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::
            (i, (tag, ...)) = receive()
        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``
    :return str: ``m`` after receiving ``CBC-FINAL`` message
        from the leader
        .. important:: **Messages**
            ``CBC_VAL( m )``
                sent from ``leader`` to each other party
            ``CBC_ECHO( m, sigma )``
                sent to leader after receiving ``CBC-VAL`` message
            ``CBC_FINAL( m, Sigma )``
                sent from ``leader`` after receiving :math:``N-f`` ``CBC_ECHO`` messages
                where Sigma is computed over {sigma_i} in these ``CBC_ECHO`` messages
    """
    try:
        assert N >= 3 * f + 1
        assert f >= 0
        assert 0 <= leader < N
        assert 0 <= pid < N

        EchoThreshold = N - f
        m = None
        digest1FromLeader = None
        digest2 = None
        echoSent = False
        finalSent = False
        cbc_echo_sshares = dict()
        cbc_echo_sshares2 = dict()
        def broadcast(o):
            # o_copy = list(o)
            # for idx, obj in enumerate(o):
            #     if isinstance(obj, pc_element):
            #         obj_bytes = serialize(obj)
            #         o_copy[idx] = obj_bytes
            # o = tuple(o_copy)
            #for i in range(N):
            #    send(i, o)
            send(-1, o)

        # print("SPBC starts...")

        if pid == leader:
            # The leader sends the input to each participant
            # print("block to wait for SPBC input")

            input_m = input()  # block until an input is received

            # print("SPBC input received: ", m[1], m[2])


            assert isinstance(input_m, (str, bytes, list, tuple))
            digest1FromLeader = _hash(str((sid, input_m, "ECHO")))
            if logger: logger.debug(f"{leader} digest1 is " + str(digest1FromLeader))
            if logger: logger.debug(f"{leader} digest1 raw is " + str((sid, input_m, "ECHO")))
            # print("leader", pid, "has digest:", digestFromLeader)
            # secret_share = ecdsa_sign(SK2, digest1FromLeader)
            secret_share = SK1.sign(digest1FromLeader, allow_pickle=True)

            # if logger: logger.warning(f'size of secret share {measure_secret(secret_share)}')
            #cbc_echo_sshares[pid] = secret_share
            broadcast(('SPBC_SEND', input_m))
            # print("Leader %d broadcasts SPBC SEND messages" % leader)

        # Handle all consensus messages
        while True:
            # gevent.sleep(0)

            (j, msg) = receive()
            # print("recv", (j, msg))

            if msg[0] == 'SPBC_SEND':
                # CBC_SEND message
                (_, m) = msg
                if j != leader:
                    if logger is not None: logger.info("A SPBC_SEND message from node %d other than leader %d" % (j, leader))
                    print("A SPBC_SEND message from node %d other than leader %d" % (j, leader), msg)
                    continue
                digest1FromLeader = _hash(str((sid, m, "ECHO")))
                if logger: logger.debug(f"{leader} digest1 is " + str(digest1FromLeader))
                if logger: logger.debug(f"{leader} digest1 raw is " + str((sid, m, "ECHO")))
                # print("Node", pid, "has message", m)
                # send(leader, ('SPBC_ECHO', ecdsa_sign(SK2, digest1FromLeader)))
                _sig = SK1.sign(digest1FromLeader, allow_pickle=True)
                send(leader, ('SPBC_ECHO', _sig))

            elif msg[0] == 'SPBC_ECHO':
                # CBC_READY message
                # print("I receive CBC_ECHO from node %d" % j)
                if pid != leader:
                    if logger is not None: logger.info(
                        "reject SPBC_ECHO from %d as %d is not the leader:" % (j, pid))
                    print("reject SPBC_ECHO from %d as %d is not the leader:" % (j, pid))
                    continue
                (_, sig1) = msg
                digest1FromLeader = _hash(str((sid, input_m, "ECHO")))
                try:
                    assert PK1.verify_share(sig1, j, digest1FromLeader, allow_pickle=True)
                    # assert ecdsa_vrfy(PK2s[j], digest1FromLeader, sig1)
                except AssertionError:
                    # print("1-Signature share failed in SPBC!", (r, sid, pid, j, msg))
                    if logger is not None: logger.error("Signature share failed in SPBC!", (sid, pid, j, msg))
                    # continue
                if logger: logger.debug(f"{j} passed share verification")
                cbc_echo_sshares[j] = sig1
                if len(cbc_echo_sshares) == EchoThreshold and not echoSent:
                    ___sigmas = dict(list(cbc_echo_sshares.items())[:EchoThreshold])

                    # TODO

                    try:
                        sigmas = PK1.combine_shares(___sigmas, allow_pickle=True)
                    except Exception as e1:
                        raise e1
                    
                    if logger is not None: logger.info(str(digest1FromLeader))
                    # if logger is not None: logger.info(str(sigmas))
                    try:
                        assert PK1.verify_signature(sigmas, digest1FromLeader, allow_pickle=True)
                    except AssertionError as e1:
                        if logger: logger.error(str(e1))
                        if logger: logger.error(traceback.format_exc())
                        if logger is not None: logger.error(f"{___sigmas}")
                    except Exception as e2:
                        pass
                    # if logger: logger.warning(f'size of sigmas {measure_secret(sigmas)}')
                    echoSent = True
                    broadcast(('SPBC_READY', m, sigmas))
                    # print("Leader %d broadcasts SPBC READY messages" % leader)

            elif msg[0] == 'SPBC_READY':
                # SPBC_READY message
                if j != leader:
                    if logger is not None: logger.info(
                        "A SPBC_SEND message from node %d other than leader %d" % (j, leader))
                    print("A SPBC_SEND message from node %d other than leader %d" % (j, leader), msg)
                    continue
                (_, m, sigmas) = msg
                try:
                    hash_e = _hash(str((sid, m, "ECHO")))
                    if logger is not None: logger.info(str(hash_e))
                    # for (k, sig) in sigmas:
                    #     assert ecdsa_vrfy(PK2s[k], hash_e, sig)
                    assert PK1.verify_signature(sigmas, hash_e, allow_pickle=True)
                except AssertionError:
                    if logger is not None: logger.error("Signature failed!", (sid, pid, j, msg))
                    # print("1-Signature failed!", (r, sid, pid, j, msg))
                    # continue
                # print("CBC finished for leader", leader)
                digest2 = _hash(str((sid, m, "FINAL")))
                # send(leader, ('SPBC_FINAL', ecdsa_sign(SK2, digest2)))
                send(leader, ('SPBC_FINAL', SK1.sign(digest2, allow_pickle=True)))
                if output is not None:
                    output((sid, pid, m, sigmas))

            elif msg[0] == 'SPBC_FINAL':
                # CBC_READY message
                # print("I receive CBC_ECHO from node %d" % j)
                if pid != leader:
                    if logger is not None: logger.info(
                        "reject SPBC_FINAL from %d as %d is not the leader:" % (j, pid))
                    print("reject SPBC_FINAL from %d as %d is not the leader:" % (j, pid))
                    continue
                (_, sig2) = msg
                digest2 = _hash(str((sid, m, "FINAL")))
                try:
                    # assert ecdsa_vrfy(PK2s[j], digest2, sig2)
                    assert PK1.verify_share(sig2, j, digest2, allow_pickle=True)
                except AssertionError:
                    # print("2-Signature share failed in SPBC!", (sid, pid, j, msg))
                    if logger is not None: logger.error("Signature share failed in SPBC!", (sid, pid, j, msg))
                    # continue
                # print("I accept CBC_ECHO from node %d" % j)
                cbc_echo_sshares2[j] = sig2
                if len(cbc_echo_sshares2) == EchoThreshold and not finalSent:
                    # print("---------------------")
                    sigmas2 = dict(list(cbc_echo_sshares2.items())[:EchoThreshold])

                    # TODO
                    try:
                        sigmas2 = PK1.combine_shares(sigmas2, allow_pickle=True)
                    except Exception as e1:
                        raise e1
                    try:
                        assert PK1.verify_signature(sigmas2, digest2, allow_pickle=True)
                    except AssertionError as e1:
                        pass
                    except Exception as e2:
                        pass

                    # if logger: logger.warning(f'size of sigmas {measure_secret(sigmas2)}')
                    # if logger: logger.warning(f'size of m {measure_secret(m)}')
                    
                    finalSent = True
                    broadcast(('SPBC_DONE', m, sigmas2))
                    # print("Leader %d broadcasts SPBC DONE messages" % leader)

            elif msg[0] == 'SPBC_DONE':
                # SPBC_DONE message
                if j != leader:
                    if logger is not None: logger.info(
                        "A SPBC_SEND message from node %d other than leader %d" % (j, leader))
                    print("A SPBC_SEND message from node %d other than leader %d" % (j, leader), msg)
                    continue
                (_, m, sigmas2) = msg
                try:
                    hash_f = _hash(str((sid, m, "FINAL")))
                    # for (k, sig) in sigmas2:
                    #     assert ecdsa_vrfy(PK2s[k], hash_f, sig)
                    assert PK1.verify_signature(sigmas2, hash_f, allow_pickle=True)
                    # assert PK1.verify_signature(sigmas2, PK1.hash_message(str((sid, m, "FINAL"))))
                except AssertionError:
                    if logger is not None: logger.error("Signature failed!", (sid, pid, j, msg))
                    # print("2-Signature failed!", (sid, pid, j, msg))
                    # continue
                return m, sigmas2
    except Exception as e:
        if logger: logger.error(str(e))
        if logger: logger.error(traceback.format_exc())
