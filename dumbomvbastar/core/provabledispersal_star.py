
# using ecdsa
import hashlib
import pickle
import time
from collections import defaultdict
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from honeybadgerbft.core.reliablebroadcast import encode, decode, merkleTree, getMerkleBranch, merkleVerify
from gevent import monkey
monkey.patch_all(thread=False)
from gevent.event import Event
import logging
import traceback
import gevent


def provabledispersalbroadcast(
        sid, pid, N, f,
        PK2s, SK2,
        leader,
        input, output,
        receive, send,
        logger: logging.Logger=None,
        stop: Event=Event()
    ):
    """Reliable broadcast

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

    :return str: ``m`` after receiving :math:`2f+1` ``READY`` messages
        and :math:`N-2f` ``ECHO`` messages

        .. important:: **Messages**

            ``VAL( roothash, branch[i], stripe[i] )``
                sent from ``leader`` to each other party
            ``ECHO( roothash, branch[i], stripe[i] )``
                sent after receiving ``VAL`` message
            ``READY( roothash, sigma )``
                sent after receiving :math:`N-f` ``ECHO`` messages
                or after receiving :math:`f+1` ``READY`` messages

    """
    # if logger: logger.debug("pd start pid:", pid, "leder:",leader)
    assert N >= 3 * f + 1
    assert f >= 0
    assert 0 <= leader < N
    assert 0 <= pid < N

    K = f + 1 # Need this many to reconstruct. (# noqa: E221)
    # EchoThreshold = N - f  # Wait for this many ECHO to send READY. (# noqa: E221)
    # ReadyThreshold = f + 1  # Wait for this many READY to amplify READY. (# noqa: E221)
    SignThreshold = N - f  # Wait for this many READY to output
    roothash = 0
    def hash(x):
        return hashlib.sha256(pickle.dumps(x)).digest()

    def broadcast(o):
        send(-1, o)
    

    if pid == leader:
        m = input()
        # if logger: logger.debug("m=", m)
        assert isinstance(m, (str, bytes, list, tuple))
        start = time.time()
        stripes = encode(K, N, m)
        mt = merkleTree(stripes)
        roothash = mt[1]
        for i in range(N):
            branch = getMerkleBranch(i, mt)
            send(i, ('STORE', sid, roothash, stripes[i], branch))
        end = time.time()
        if logger: logger.info("vc time: " + str(end - start))

    # stop = Event()
    recstorefromleader = 0
    recstored = [0 for n in range(N)]
    stored = defaultdict(set)
    storedSenders = set()  # Peers that have sent us READY messages
    storedSigShares = defaultdict(lambda: None)
    LOCKSEND = False
    SELFLOCKSEND = False
    lock = ()
    store = ()

    while True:
        if logger: logger.debug(f"sid{sid} leader{leader} waiting recv")
        sender, msg = receive()
        if logger: logger.debug(f"sid{sid} leader{leader} recv")
        # if logger: logger.debug(f"{(sender, msg)}")

        if stop.ready():
            if not SELFLOCKSEND and pid == leader:
                if logger: logger.warning(f"sid{sid} leader{leader} this PD should stop, but SELFLOCK NOT SEND")
                continue
            if logger: logger.info(f"{sid}exit leader{leader}")
            RETURN_VALUE = 0
        if msg[0] == 'STORE':
            (_, sid, roothash, stripe, branch) = msg
            if sender != leader:
                # if logger: logger.debug("STORE message from other than leader:", sender)
                continue
            elif recstorefromleader != 0:
                # if logger: logger.debug("not the first time receive STORE from leader")
                continue
            try:
                assert not stop.ready()
                assert merkleVerify(N, stripe, roothash, branch, pid)
            except Exception as e:
                if logger: logger.error(("Failed to validate STORE message:", e))
                continue
            # UPDATE
            store = (roothash, pid, stripe, branch)
            output(('STORE', store, sid, pid))
            # getStore(store, sid)
            recstorefromleader += 1
            digest1 = hash(str(('STORED', sid, roothash)))
            sig = ecdsa_sign(SK2, digest1)
            send(leader, ('STORED', sid, sig))
            # if logger: logger.info(f"STORED sent: sid{sid} leader{leader}")

        # receiving STORED message from pi
        elif msg[0] == 'STORED':

            if pid != leader:
                if logger: logger.warning((pid, " is not a leader in this pd instance"))
                continue
            elif recstored[sender] != 0:
                if logger: logger.warning(("not the first time receive STORED from node:", sender))
                continue

            (_, sid, sigma) = msg
            # if logger: logger.debug(sender, "send ", sigma)

            try:
                assert not stop.ready()
                digest = hash(str(('STORED', sid, roothash)))
                assert ecdsa_vrfy(PK2s[sender], digest, sigma)
            except AssertionError:
                try:
                    if logger: logger.warning(("Signature share failed in PD!", (sid, pid, sender, msg)))
                except Exception as e:
                    if logger: logger.warning("Signature share failed in PD!")
                    if logger: logger.error(str(e))
                    if logger: logger.error(traceback.format_exc())
                continue
            # if logger: logger.debug("receive the stored! from ", sender )
            # UPDATE S1
            recstored[sender] += 1
            stored[roothash].add(sender)
            storedSenders.add(sender)
            storedSigShares[sender] = sigma

            # if logger: logger.debug(f'stored_len {len(stored[roothash])} LOCKSEND{LOCKSEND}')
            if len(stored[roothash]) == SignThreshold and not LOCKSEND:
                Sigmas1 = tuple(storedSigShares.items())
                lock = (roothash, Sigmas1)
                output(('LOCK', lock, sid, pid))
                gevent.sleep(0.1)
                if logger: logger.info(f'PD[{leader}] pid{pid} {sid}exit')
                return 0
        else:
            if logger: logger.warning(f'unknown tag {sender} {msg}')
        
        if pid != leader and recstorefromleader == 1:
            gevent.sleep(0.1)
            if logger: logger.info(f'PD[{leader}] pid{pid} {sid}exit')
            return 0
