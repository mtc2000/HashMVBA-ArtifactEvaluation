import logging
import math
import os
import sys
from queue import Empty

import gevent
from gevent import monkey;

import network

monkey.patch_all(thread=False)

import time
import random
import traceback
from typing import List, Callable
from gevent import Greenlet
from mvba_node.node import MVBA
from hash_mvba.mba.mba_node import MBA
from hash_mvba.core.hmvba_node import P_MVBA
from fin_mvba.core.fin_mvba_node import FIN_MVBA
from network.socket_server import NetworkServer
from network.socket_client_mvba import NetworkClient
from multiprocessing import Value as mpValue, Queue as mpQueue, Event as mpEvent
from ctypes import c_bool


SLEEP_INTERVAL = 0.0001

def instantiate_mvba_node(sid, i, B, N, f, K, mvba_from_server: Callable, mvba_to_client: Callable, ready: mpValue,
                         stop: mpValue, protocol="mvba", mute=False, F=100, debug=False, omitfast=False, countpoint=0):
    mvba = None
    if protocol == 'mba':
        mvba = MBA(sid, i, B, N, f, mvba_from_server, mvba_to_client, ready, stop, K, countpoint, mute=mute, debug=debug)
    elif protocol == 'pmvba':
        from hash_mvba.core.hmvba_protocol import run_hmvba
        mvba = MVBA(sid, i, B, N, f, mvba_from_server, mvba_to_client, ready, stop, K, countpoint, mute=mute, debug=debug, mvba_func=run_hmvba)
    elif protocol == 'finmvba':
        from fin_mvba.core.fin_mvba_protocol import run_fin_mvba
        mvba = MVBA(sid, i, B, N, f, mvba_from_server, mvba_to_client, ready, stop, K, countpoint, mute=mute, debug=debug, mvba_func=run_fin_mvba)
    elif protocol == 'dumbomvbastar':
        from mvba_node.dumbo_node import MVBA as DUMBO_MVBA
        from dumbomvbastar.core.dumbomvba_star import smvbastar
        mvba = DUMBO_MVBA(sid, i, B, N, f, mvba_from_server, mvba_to_client, ready, stop, K, countpoint, mute=mute, debug=debug, mvba_func=smvbastar)
    elif protocol == 'dumbomvbastarbls':
        from mvba_node.dumbo_node import MVBA as DUMBO_MVBA
        from dumbomvbastar_bls.core.dumbomvba_star import smvbastar as smvbastar_bls
        mvba = DUMBO_MVBA(sid, i, B, N, f, mvba_from_server, mvba_to_client, ready, stop, K, countpoint, mute=mute, debug=debug, mvba_func=smvbastar_bls)
    else:
        print("Only support mvba", flush=True)
    return mvba

def set_node_log(id: int):
    logger = logging.getLogger("testing-node-" + str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.makedirs(os.getcwd() + '/log', exist_ok=True)
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "testing-node-" + str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def main():
    if not os.path.isfile('hosts.config'):
        print('host config does not exists!', file=sys.stderr)
        return 1
    
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--sid', metavar='sid', required=True,
                        help='identifier of node', type=str)
    parser.add_argument('--id', metavar='id', required=True,
                        help='identifier of node', type=int)
    parser.add_argument('--N', metavar='N', required=True,
                        help='number of parties', type=int)
    parser.add_argument('--f', metavar='f', required=True,
                        help='number of faulties', type=int)
    parser.add_argument('--B', metavar='B', required=True,
                        help='size of batch', type=int)
    parser.add_argument('--K', metavar='K', required=False,
                        help='instance to execute', type=int, default=10)
    parser.add_argument('--P', metavar='P', required=False,
                        help='protocol to execute', type=str, default="mvba")
    parser.add_argument('--M', metavar='M', required=False,
                        help='whether to mute a third of nodes', type=bool, default=False)
    parser.add_argument('--F', metavar='F', required=False,
                        help='batch size of fallback path', type=int, default=100)
    parser.add_argument('--D', metavar='D', required=False,
                        help='whether to debug mode', type=bool, default=False)
    parser.add_argument('--O', metavar='O', required=False,
                        help='whether to omit the fast path', type=bool, default=False)
    parser.add_argument('--C', metavar='C', required=False,
                        help='point to start measure tps and latency', type=int, default=0)
    args = parser.parse_args()

    # Some parameters
    sid = args.sid
    i = args.id
    N = args.N
    f = args.f
    B = args.B
    K = args.K
    P = args.P
    M = args.M
    F = args.F
    D = args.D
    O = args.O
    C = args.C

    logger: logging.Logger = set_node_log(i)

    # Random generator
    rnd = random.Random(sid)

    # Nodes list
    addresses = [None] * N
    try:
        with open('hosts.config', 'r') as hosts:
            for line_num, line in enumerate(hosts):
                params = line.split()
                pid = line_num
                priv_ip = 'localhost'
                pub_ip = params[0]
                port = 10000
                if pub_ip in ('127.0.0.1', 'localhost'):
                    port += pid * 200
                if len(params) > 1:
                    port = int(params[1])
                if pid not in range(N):
                    continue
                if pid == i:
                    my_address = (pub_ip, port)
                assert (pub_ip, port) not in addresses, 'duplicated client!'
                addresses[pid] = (pub_ip, port)
        assert all([node is not None for node in addresses])
        # print("hosts.config is correctly read", flush=True)


        client_mvba_mpq = mpQueue()
        client_from_mvba = lambda: client_mvba_mpq.get(timeout=0.00001)

        from multiprocessing.reduction import ForkingPickler

        def mvba_to_client(x):
            try:
                #gevent.sleep(0.00001 * (1 + random.random()))
                _x = ForkingPickler.dumps(x)
                client_mvba_mpq.put_nowait(x)
            except Exception as e:
                if logger:
                    logger.error(e)
                    logger.error(traceback.format_exc())
                    logger.error(x)
                else:
                    raise(e)

        server_mvba_mpq = mpQueue()
        mvba_from_server = lambda: server_mvba_mpq.get(timeout=0.00001)

        def server_to_mvba(x):
            #gevent.sleep(0.00001 * (1 + random.random()))
            try:
                _x = ForkingPickler.dumps(x)
                server_mvba_mpq.put_nowait(x)
            except Exception as e:
                if logger:
                    logger.error(e)
                    logger.error(traceback.format_exc())
                    logger.error(x)
                else:
                    raise(e)

        client_ready = mpValue(c_bool, False)
        server_ready = mpValue(c_bool, False)
        net_ready = mpValue(c_bool, False)
        stop = mpValue(c_bool, False)

        test_termination = mpValue(c_bool, False)

        net_client = NetworkClient(my_address[1], my_address[0], i, addresses, client_from_mvba, client_ready, stop, test_termination)
        net_server = NetworkServer(my_address[1], my_address[0], i, addresses, server_to_mvba, server_ready, stop, test_termination)
        mvba = instantiate_mvba_node(sid, i, B, N, f, K, mvba_from_server, mvba_to_client, net_ready, stop, P, M, F, D, O, C)

        net_server.start()
        net_client.start()

        while not client_ready.value or not server_ready.value:
            gevent.sleep(SLEEP_INTERVAL)
            logger.info("waiting for network ready...")

        with net_ready.get_lock():
            net_ready.value = True

        mvba_thread = Greenlet(mvba.run)
        mvba_thread.start()
        mvba_thread.join()

        logger.info('test ends')

        with stop.get_lock():
            stop.value = True
        
        with test_termination.get_lock():
            test_termination.value = True

        net_client.terminate()
        net_client.join()
        gevent.sleep(1)
        net_server.terminate()
        net_server.join()

    except FileNotFoundError or AssertionError as e:
        traceback.print_exc()


if __name__ == '__main__':
    main()
