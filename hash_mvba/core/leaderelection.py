import logging
from typing import Callable

from crypto.threshsig.boldyreva import serialize, deserialize1
from collections import defaultdict
from gevent import Greenlet
from gevent.queue import Queue

_orig_print = print

def print(*args, **kwargs):
    _orig_print(*args, flush=True, **kwargs)

logger = logging.getLogger(__name__)

import hashlib
def hash(x):
    return hashlib.sha256(x).digest()

class CommonCoinFailureException(Exception):
    """Raised for common coin failures."""
    pass


def hash(x):
    return hashlib.sha256(x).digest()


def leader_election(sid, pid, N, f, PK, SK, broadcast: Callable, receive: Callable):
    """A leader election phase same as common coin logic

    :param sid: a unique instance id
    :param pid: my id number
    :param N: number of parties
    :param f: fault tolerance, :math:`f+1` shares needed to get the coin
    :param PK: ``boldyreva.TBLSPublicKey``
    :param SK: ``boldyreva.TBLSPrivateKey``
    :param broadcast: broadcast channel
    :param receive: receive channel
    :return: a function ``getCoin()``, where ``getCoin(r)`` blocks
    """
    assert PK.k == f+1
    assert PK.l == N    # noqa: E741
    received = defaultdict(dict)
    outputQueue = defaultdict(lambda: Queue(1))
    protocol_name = f'{sid}/ELECT'

    def _recv():
        while True:     # main receive loop
            logger.debug(f'entering loop',
                         extra={'nodeid': pid, 'epoch': '?'})
            # New shares for some round r, from sender i
            msg = receive()
            # print(msg)
            (i, (r, sig_srl)) = msg
            sig = deserialize1(sig_srl)
            logger.debug(f'received i, r, sig: {i, r, sig}',
                         extra={'nodeid': pid, 'epoch': r})
            assert i in range(N)
            assert r >= 0
            if i in received[r]:
                print("redundant coin sig received", (sid, pid, i, r))
                continue

            h = PK.hash_message(str((sid, r)))

            # TODO: Accountability: Optimistically skip verifying
            # each share, knowing evidence available later
            try:
                PK.verify_share(sig, i, h)
            except AssertionError:
                print("Signature share failed!", (sid, pid, i, r))
                continue

            received[r][i] = sig

            # After reaching the threshold, compute the output and
            # make it available locally
            logger.debug(
                f'if len(received[r]) == f + 1: {len(received[r]) == f + 1}',
                extra={'nodeid': pid, 'epoch': r},
            )
            if len(received[r]) == f + 1:

                # Verify and get the combined signature
                sigs = dict(list(received[r].items())[:f+1])
                sig = PK.combine_shares(sigs)
                assert PK.verify_signature(sig, h)

                # Compute the bit from the least bit of the _hash
                bit = hash(serialize(sig))[0] % N
                logger.debug(f'put bit {bit} in output queue',
                             extra={'nodeid': pid, 'epoch': r})
                outputQueue[r].put_nowait(bit)

    # greenletPacker(Greenlet(_recv), 'shared_coin', (pid, N, f, broadcast, receive)).start()
    Greenlet(_recv).start()

    def getCoin(round):
        """Gets a coin.

        :param round: the epoch/round.
        :returns: a coin.

        """
        # I have to do mapping to 1..l
        h = PK.hash_message(str((sid, round)))
        logger.debug(f"broadcast {(protocol_name, round, SK.sign(h))}",
                     extra={'nodeid': pid, 'epoch': round})
        broadcast(
            (
                protocol_name,
                pid,
                (
                    round,
                    serialize(SK.sign(h))
                )
            )
        )
        return outputQueue[round].get()

    return getCoin
