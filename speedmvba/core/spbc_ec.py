import logging
import traceback
from queue import Queue

from gevent import monkey;

monkey.patch_all(thread=False)

from datetime import datetime
from collections import defaultdict
import hashlib, pickle
from crypto.threshsig.boldyreva import serialize, deserialize1
from crypto.threshsig.boldyreva import TBLSPrivateKey, TBLSPublicKey
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()



def strongprovablebroadcast(
        sid, pid, N, f,
        PK2s, SK2,
        leader,
        input, output,
        receive, send,
        r,
        logger: logging.Logger=None,
        predicate=lambda x: True
    ):
    """Consistent broadcast
    :param str sid: session identifier
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
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
        #for i in range(N):
        #    send(i, o)
        send(-1, o)

    # if logger: logger.debug(("SPBC starts..."))

    if pid == leader:
        # The leader sends the input to each participant
        # if logger: logger.debug(("block to wait for SPBC input"))

        m = input()  # block until an input is received
        # if logger: logger.debug((f"SPBC input type {type(m)}"))
        # for _ in m:
        #     if logger: logger.debug((f"SPBC input type {type(_)}"))

        # if logger: logger.debug(("SPBC input received: ", m[1], m[2]))
        if logger: logger.debug(("SPBC input received"))

        assert isinstance(m, (str, bytes, list, tuple))
        digest1FromLeader = hash(str((sid, m, "ECHO")))
        # if logger: logger.debug(("leader", pid, "has digest:", digestFromLeader))
        secret_share = ecdsa_sign(SK2, digest1FromLeader)
        if logger: logger.warning(f'size of secret share {len(pickle.dumps(secret_share))}')
        cbc_echo_sshares[pid] = secret_share
        broadcast(('SPBC_SEND', m))
        # if logger: logger.debug(("Leader %d broadcasts SPBC SEND messages" % leader))

    # Handle all consensus messages
    while True:
        # gevent.sleep(0)

        (j, msg) = receive()
        # if logger: logger.debug(("recv", (j, msg)))

        if msg[0] == 'SPBC_SEND':
            # CBC_SEND message
            (_, m) = msg
            if j != leader:
                if logger: logger.info("A SPBC_SEND message from node %d other than leader %d" % (j, leader))
                if logger: logger.debug(("A SPBC_SEND message from node %d other than leader %d" % (j, leader), msg))
                continue
            digest1FromLeader = hash(str((sid, m, "ECHO")))
            # if logger: logger.debug(("Node", pid, "has message", m))
            send(leader, ('SPBC_ECHO', ecdsa_sign(SK2, digest1FromLeader)))

        elif msg[0] == 'SPBC_ECHO':
            # CBC_READY message
            # if logger: logger.debug(("I receive CBC_ECHO from node %d" % j))
            if pid != leader:
                if logger: logger.info(
                    "reject SPBC_ECHO from %d as %d is not the leader:" % (j, pid))
                if logger: logger.debug(("reject SPBC_ECHO from %d as %d is not the leader:" % (j, pid)))
                continue
            (_, sig1) = msg
            digest1FromLeader = hash(str((sid, m, "ECHO")))
            try:
                # assert PK1.verify_share(sig1, j, digest1FromLeader)
                assert ecdsa_vrfy(PK2s[j], digest1FromLeader, sig1)
            except AssertionError:
                # if logger: logger.debug(("1-Signature share failed in SPBC!", (r, sid, pid, j, msg)))
                try:
                    if logger: logger.warning(("Signature share failed in SPBC!", (sid, pid, j, msg)))
                except Exception as e:
                    if logger: logger.warning("Signature failed!")
                    if logger: logger.error(str(e))
                    if logger: logger.error(traceback.format_exc())
                # continue
            cbc_echo_sshares[j] = sig1
            if len(cbc_echo_sshares) == EchoThreshold and not echoSent:
                sigmas = tuple(list(cbc_echo_sshares.items())[:N - f])
                # sigmas = PK1.combine_shares(cbc_echo_sshares)
                # assert PK.verify_signature(Sigma, digestFromLeader)
                if logger: logger.warning(f'size of sigmas {len(pickle.dumps(sigmas))}')
                echoSent = True
                broadcast(('SPBC_READY', m, sigmas))
                # if logger: logger.debug(("Leader %d broadcasts SPBC READY messages" % leader))

        elif msg[0] == 'SPBC_READY':
            # SPBC_READY message
            if j != leader:
                if logger: logger.info(
                    "A SPBC_SEND message from node %d other than leader %d" % (j, leader))
                if logger: logger.debug(("A SPBC_SEND message from node %d other than leader %d" % (j, leader), msg))
                continue
            (_, m, sigmas) = msg
            try:
                hash_e = hash(str((sid, m, "ECHO")))
                for (k, sig) in sigmas:
                    assert ecdsa_vrfy(PK2s[k], hash_e, sig)
            except AssertionError:
                try:
                    if logger: logger.warning(("Signature failed!", (sid, pid, j, msg)))
                except Exception as e:
                    if logger: logger.warning("Signature failed!")
                    if logger: logger.error(str(e))
                    if logger: logger.error(traceback.format_exc())
                # if logger: logger.debug(("1-Signature failed!", (r, sid, pid, j, msg)))
                # continue
            # if logger: logger.debug(("CBC finished for leader", leader))
            digest2 = hash(str((sid, m, "FINAL")))
            send(leader, ('SPBC_FINAL', ecdsa_sign(SK2, digest2)))
            if output is not None:
                output((sid, pid, m, sigmas))

        elif msg[0] == 'SPBC_FINAL':
            # CBC_READY message
            # if logger: logger.debug(("I receive CBC_ECHO from node %d" % j))
            if pid != leader:
                if logger: logger.info(
                    "reject SPBC_FINAL from %d as %d is not the leader:" % (j, pid))
                if logger: logger.debug(("reject SPBC_FINAL from %d as %d is not the leader:" % (j, pid)))
                continue
            (_, sig2) = msg
            digest2 = hash(str((sid, m, "FINAL")))
            try:
                assert ecdsa_vrfy(PK2s[j], digest2, sig2)
                # assert PK1.verify_share(sig2, j, digest2)
            except AssertionError:
                # if logger: logger.debug(("2-Signature share failed in SPBC!", (sid, pid, j, msg)))
                try:
                    if logger: logger.warning(("Signature share failed in SPBC!", (sid, pid, j, msg)))
                except Exception as e:
                    if logger: logger.warning("Signature failed!")
                    if logger: logger.error(str(e))
                    if logger: logger.error(traceback.format_exc())
                # continue
            # if logger: logger.debug(("I accept CBC_ECHO from node %d" % j))
            cbc_echo_sshares2[j] = sig2
            if len(cbc_echo_sshares2) == EchoThreshold and not finalSent:
                # if logger: logger.debug(("---------------------"))
                sigmas2 = tuple(list(cbc_echo_sshares2.items())[:N - f])
                # sigmas2 = PK1.combine_shares(cbc_echo_sshares2)
                # assert PK.verify_signature(Sigma, digestFromLeader)
                if logger: logger.warning(f'size of sigmas {len(pickle.dumps(sigmas2))}')
                if logger: logger.warning(f'size of m {len(pickle.dumps(m))}')
                if logger: logger.warning(f'size of bcast {len(pickle.dumps(("SPBC_DONE", m, sigmas2)))}')
                finalSent = True
                broadcast(('SPBC_DONE', m, sigmas2))
                # if logger: logger.debug(("Leader %d broadcasts SPBC DONE messages" % leader))

        elif msg[0] == 'SPBC_DONE':
            # SPBC_DONE message
            if j != leader:
                if logger: logger.info(
                    "A SPBC_SEND message from node %d other than leader %d" % (j, leader))
                if logger: logger.debug(("A SPBC_SEND message from node %d other than leader %d" % (j, leader), msg))
                continue
            (_, m, sigmas2) = msg
            try:
                hash_f = hash(str((sid, m, "FINAL")))
                for (k, sig) in sigmas2:
                    assert ecdsa_vrfy(PK2s[k], hash_f, sig)
                    # assert PK1.verify_signature(sigmas2, PK1.hash_message(str((sid, m, "FINAL"))))
            except AssertionError:
                try:
                    if logger: logger.warning(("Signature failed!", (sid, pid, j, msg)))
                except Exception as e:
                    if logger: logger.warning("Signature failed!")
                    if logger: logger.error(str(e))
                    if logger: logger.error(traceback.format_exc())
                # if logger: logger.debug(("2-Signature failed!", (sid, pid, j, msg)))
                # continue
            return m, sigmas2