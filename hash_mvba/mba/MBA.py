from typing import Dict

from hash_mvba.mba.mba_protocol import run_mba

import hashlib


def hash(x):
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
from gevent import monkey

monkey.patch_all()

try:
    import cPickle as pickle
except ImportError:
    import pickle

from honeybadgerbft.core.newnetwork import listen_to_channel, connect_to_channel

class MBA():

    def __init__(self, sid, pid, B, N, f, sPK, sSK, sPKNf2, sSKNf2, ePK, eSK, node_list, Inner_IP, K=3):
        self.sid = sid
        self.pid = pid
        self.B = B
        self.N = N
        self.f = f
        self.sPK = sPK
        self.sSK = sSK
        self.ePK = ePK
        self.eSK = eSK
        self.sPKNf2 = sPKNf2
        self.sSKNf2 = sSKNf2
        self.Inner_IP = Inner_IP

        self.round = 0  # Current block number
        self.transaction_buffer = []
        self._per_round_recv: Dict[int, Queue] = {}  # Buffer of incoming messages

        self.K = K
        self.node_list = node_list
        self.buffer_queue = Queue()
        self.send_queue = Queue()
        # self.send_socket = [None for _ in range(N)]
        self.send_per_queue = [Queue() for _ in range(N)]

        self.output_tx_num = 0
        self.overall_time = -1
        self.aba_time = [-1] * N
        self.basetime = time.time()
        self.aba_time_interval = [(-1, -1)] * N

        self.log_file_name = "../log_" + "mba" + ".txt"

    def submit_tx(self, tx):
        self.transaction_buffer.append(tx)

    def storage_re_init(self, N):  # 以前的那一批存储结构，已经成了“无法被指向的存在”，尽管那些东西可能还在，但是他们的存在、执行、消亡，应该不会对最新这轮的总程序产生影响吧？
        self.overall_time = -1
        self.ABA_overall_time = [-1]
        self.aba_time = [-1] * N
        self.basetime = time.time()
        self.aba_time_interval = [(-1, -1)] * N

    def run(self):
        """Run the HoneyBadgerBFT protocol."""

        try:
            self.buffer_queue = listen_to_channel(self.Inner_IP)
        except Exception as e:
            print(self.Inner_IP, "when starts listen fails, the erro:")
            print(e)

        for i in range(self.N):
            try:
                gevent.spawn(connect_to_channel, self.node_list[i], self.send_per_queue[i])
            except Exception as e:
                print('send_per_queue when initialization fails', self.Inner_IP, 'to', str(self.node_list[i]), e)

        def _recv():
            """Receive messages."""
            while True:
                msg = self.buffer_queue.get()
                # print(msg)
                # print(f"verbose recv:{self.sid}/{self.pid}:::{msg}")
                (sender, (r, msg)) = msg  ##阻塞方法,get()

                # Maintain an *unbounded* recv queue for each epoch
                if r not in self._per_round_recv:
                    # Buffer this message
                    assert r >= self.round  # pragma: no cover
                    self._per_round_recv[r] = Queue()

                _recv = self._per_round_recv[r]
                if _recv is not None:
                    # Queue it
                    _recv.put((sender, msg))

        _recv_thread = gevent.spawn(_recv)

        while True:
            # For each round...
            r = self.round

            self.storage_re_init(self.N)

            if r not in self._per_round_recv:
                self._per_round_recv[r] = Queue()

            tx_to_send_all = self.transaction_buffer[:self.B]
            assert self.B > 0

            len_my_tx_set = self.B

            my_tx_set_extend = []
            for x in range(len_my_tx_set):
                my_tx_set_extend.append(
                    tx_to_send_all[x])  # append是Python列表操作高效的方式，推荐使用；extend也是原地操作。而+则不推荐使用，需要创建较多对象，不推荐使用！
                my_tx_set_extend.append('/')

            str_to_send = "".join(my_tx_set_extend)

            # TODO: Wait a bit if transaction buffer is not full

            def _make_send(r):
                def _send(j, o):
                    if callable(o):
                        o = o()
                    # print(f'verbose send: {r}, {self.pid}, {j}, {o}')
                    self.send_per_queue[j].put_nowait((self.pid, (r, o)))

                return _send

            send_r = _make_send(r)
            recv_r = self._per_round_recv[r].get

            new_tx = self._run_round(r, str_to_send, send_r, recv_r)
            print('new_tx:::', str(len(new_tx)))

            self.output_tx_num += len(new_tx)

            # Remove all of the new transactions from the buffer
            self.transaction_buffer = [_tx for _tx in self.transaction_buffer if _tx not in new_tx]

            print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! k=', self.round,
                  ' !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')

            print('\n--- --- --- --- ---')
            print('The time statistics of node --', str(self.pid), '-- in round --', str(r), '-- is --:')

            print('ABA time:::')
            print(self.aba_time)
            print(self.aba_time_interval)

            print('ABA overall time:::')
            print(self.ABA_overall_time)
            print('Total time:::')
            print(str(round(time.time() - self.overall_time, 2)))
            print('--- --- --- --- ---\n')

            """
            log_string = 'new_tx:::'+ str(len(new_tx)) +'\n'+ '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! k='+ str(self.round) + ' !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' +'\n'+'\n--- --- --- --- ---'+'\n'+'The time statistics of node --'+ str(self.pid)+ '-- in round --'+ str(r)+ '-- is --:'+'\n'+'proof-CBC time:::' +'\n'+str(self.proof_cbc_time) +'\n'+str(self.proof_cbc_time_interval) +'\n'+'commit-CBC time:::' +'\n'+str(self.commit_cbc_time) +'\n'+str(self.commit_cbc_time_interval) +'\n'+'ABA time:::' +'\n'+str(self.aba_time) +'\n'+str(self.aba_time_interval) +'\n'+'CBC overall time:::' +'\n'+str(self.CBC_overall_time) +'\n'+'ABA overall time:::' +'\n'+str(self.ABA_overall_time) +'\n'+'Total time:::' +'\n'+str(round(time.time() - self.overall_time, 2)) +'\n'+'--- --- --- --- ---\n' +'\n'

            with open(self.log_file_name, "a+") as log_file:
                log_file.write(log_string)
            """

            self.round += 1  # Increment the round

            if self.round >= self.K:
                _recv_thread.kill()
                break  # TODO: Only run one round for now

        time.sleep(2)
        return self.output_tx_num

    def _run_round(self, r, tx_to_send, send, recv):
        """Run one protocol round."""

        self.overall_time = time.time()
        self.basetime = time.time()

        sid = self.sid
        pid = self.pid
        N = self.N
        f = self.f

        round_input_queue = Queue(1)
        round_output_queue = Queue(1)

        #run_mba(sid, pid, r, N, f, round_input_queue.get, recv, send, self.sPK, self.sSK, round_output_queue,
        #        self.aba_time, self.aba_time_interval, self.basetime)

        gevent.spawn(run_mba, sid, pid, r, N, f, round_input_queue, recv, send, self.sPK, self.sSK, round_output_queue,
                self.aba_time, self.aba_time_interval, self.ABA_overall_time, self.basetime)

        round_input_queue.put_nowait(tx_to_send)
        result = round_output_queue.get()

        return [result]
