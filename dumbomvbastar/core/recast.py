# new rc
import hashlib
import pickle
import time
from collections import defaultdict

import gevent
from gevent import monkey
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from honeybadgerbft.core.reliablebroadcast import encode, decode, merkleTree, getMerkleBranch, merkleVerify
import logging


def recastsubprotocol(pid, sid, N, f,  PK2s, SK2, receive, send, getstore, getlock, logger: logging.Logger=None):

    assert N >= 3 * f + 1
    assert f >= 0
    assert 0 <= pid < N
    
    K = f + 1

    rclocksend = False
    rcstorerec = [0 for n in range(N)]
    commit = defaultdict(lambda: [None for _ in range(N)])
    # commit = defaultdict(set)

    def hash(x):
        return hashlib.sha256(pickle.dumps(x)).digest()

    def broadcast(o):
        send(-1, o)

    def getinput():
        nonlocal rclocksend

        getinputcount = 0
        while getinputcount < 2:
            gevent.sleep(0)
            try:
                lock = getlock()
                if logger: logger.debug((pid, "get lock"))
                if not rclocksend:
                    broadcast(('RCLOCK', sid, lock))
                    rclocksend = True
                    getinputcount += 1
            except:
                pass
            try:
                store = getstore()
                if logger: logger.debug((pid, "get store"))
                broadcast(('RCSTORE', sid, store))
                getinputcount += 1
            except:
                pass
    gevent.spawn(getinput)

    while True:
        gevent.sleep(0)
        if logger: logger.debug('before recv')
        sender, msg = receive()
        if logger: logger.debug('after recv')
        # if logger: logger.debug(sid, pid, ": receive", msg[0])
        if msg[0] == 'RCLOCK':
            (_, sid, lock) = msg
            (roothash, raw_Sigma1) = lock
            # try:
            #     if logger: logger.debug(lock)
            # except Exception:
            #     pass
            try:
                digest = hash(str(('STORED', sid, roothash)))
                try:
                    for (k, sig) in raw_Sigma1:
                        assert ecdsa_vrfy(PK2s[k], digest, sig)
                except AssertionError as e:
                    if logger: logger.error(("Signature failed!", e))
                    continue
                # assert PK1.verify_signature(deserialize1(raw_Sigma1), digest)
            except Exception as e:
                if logger: logger.error(("Failed to validate LOCK message:", e))
                continue
            if not rclocksend:
                broadcast(('RCLOCK', sid, lock))
                rclocksend = True
            if sum(x is not None for x in commit[roothash]) >= K:
                # if logger: logger.debug(pid, sid, "f+1")
                start = time.time()
                v = decode(K, N, commit[roothash])
                expected_roothash = merkleTree(encode(K, N, v))[1]
                # if logger: logger.debug((K, N, commit[roothash]))
                # if logger: logger.debug((v, roothash, expected_roothash))
                end = time.time()
                if logger: logger.info("vc time: " + str(end - start))
                if expected_roothash == roothash:
                    # if logger: logger.debug(("now print v:", bytes.decode(v)))
                    if logger: logger.info((pid, "return rc", sid))
                    return bytes.decode(v)
                else:
                    if logger: logger.error(('roothash mismatch', roothash, expected_roothash))
                    return ''

        if msg[0] == 'RCSTORE':
            (_, sid, store) = msg
            (roothash, sender, stripe, branch) = store
            if rcstorerec[sender] != 0:
                if logger: logger.warning(("not the first time receive rcstore from node ", sender))
                continue
            try:
                assert merkleVerify(N, stripe, roothash, branch, sender)
            except Exception as e:
                if logger: logger.error(("Failed to validate STORE message:", e))
                continue
            rcstorerec[sender] += 1

            # if logger: logger.debug(stripe)
            commit[roothash][sender] = stripe

            if rclocksend and sum(x is not None for x in commit[roothash]) == K:
                # if logger: logger.debug(pid, ": has K=3f+1 stripes")
                start = time.time()
                v = decode(K, N, commit[roothash])
                expected_roothash = merkleTree(encode(K, N, v))[1]
                # if logger: logger.debug((K, N, commit[roothash]))
                # if logger: logger.debug((v, roothash, expected_roothash))
                end = time.time()
                if logger: logger.info("vc time: " + str(end - start))
                if expected_roothash == roothash:
                    # if logger: logger.debug(("now print v:", bytes.decode(v)))
                    if logger: logger.info((pid, "return rc", sid))
                    return bytes.decode(v)
                else:
                    if logger: logger.error(('roothash mismatch', roothash, expected_roothash))
                    return ''
