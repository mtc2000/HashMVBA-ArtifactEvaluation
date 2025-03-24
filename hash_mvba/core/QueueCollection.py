from collections import defaultdict
from typing import List

from gevent import monkey
from gevent.event import Event

monkey.patch_all(thread=False)

import gevent
from gevent.queue import Queue

try:
    import cPickle as pickle
except ImportError:
    import pickle

NULL = b'0'

class QueueCollection:
    TIMEOUT = 0

    def __init__(self, queues):
        self.queues: List[Queue] = queues.copy()
        self.N = len(self.queues)
        self._get_queue = Queue()
        def _get_watcher(watched_queue: Queue, target_queue: Queue):
            # Watcher function to check if the queue is non-empty
            e = watched_queue.peek()  # blocking; avoid busy-waiting
            target_queue.put_nowait(e)

        self._get_threads = []
        for i in range(len(self.queues)):
            self._get_threads.append(gevent.spawn(_get_watcher, self.queues[i], self._get_queue))


    def get(self):
        return self._get_queue.get()


    def wait(self, k):
        if not (0 < k <= len(self.queues)):
            raise ValueError("Invalid value of k")

        non_empty_set = set()

        while True:
            for i in range(self.N):
                if i in non_empty_set: continue
                if self.queues[i].qsize() > 0:
                    non_empty_set.add(i)
                if len(non_empty_set) >= k:
                    return list(non_empty_set)
            gevent.sleep(QueueCollection.TIMEOUT)


    def wait_value(self, value, k):
        if not (0 < k <= len(self.queues)):
            raise ValueError("Invalid value of k")

        non_empty_set = set()
        matched_value_set = set()

        while True:
            for i in range(self.N):
                if i in non_empty_set: continue
                if self.queues[i].qsize() > 0:
                    non_empty_set.add(i)
                sender, received_value = self.queues[i].peek()
                if received_value == value:
                    matched_value_set.add(i)
                if len(matched_value_set) >= k:
                    return list(matched_value_set)
            gevent.sleep(QueueCollection.TIMEOUT)


    def get_k_matching_value(self, k, allow_null=True):
        queues = self.queues.copy()
        if not (0 < k <= len(queues)):
            raise ValueError("Invalid value of k")

        counter = defaultdict(set)
        non_empty_set = set()

        while True:
            for i in range(self.N):
                if i in non_empty_set: continue
                if self.queues[i].qsize() > 0:
                    non_empty_set.add(i)
                sender, received_value = self.queues[i].peek()
                counter[received_value].add(i)
                if len(counter[received_value]) >= k:
                    if allow_null:
                        return received_value
                    elif received_value != NULL:
                        return received_value
                if len(non_empty_set) >= len(queues):
                    return None
            gevent.sleep(QueueCollection.TIMEOUT)


    def get_value_at_least_k1_count_within_k2_count(self, k1, k2):
        queues = self.queues.copy()
        if not (0 < k1 <= k2 <= len(queues)):
            raise ValueError("Invalid value of k1 or k2")

        counter = defaultdict(set)
        non_empty_set = set()

        while True:
            for i in range(self.N):
                if i in non_empty_set: continue
                if self.queues[i].qsize() > 0:
                    non_empty_set.add(i)
                sender, received_value = self.queues[i].peek()
                counter[received_value].add(i)
                if len(counter[received_value]) >= k1:
                    return received_value, sorted(counter[received_value])
                if len(non_empty_set) >= k2:
                    return None, list()
            gevent.sleep(QueueCollection.TIMEOUT)

    def get_non_zero_value_at_least_k1_count_within_k2_count(self, k1, k2):
        queues = self.queues.copy()
        if not (0 < k1 <= k2 <= len(queues)):
            raise ValueError("Invalid value of k1 or k2")

        counter = defaultdict(set)
        non_empty_set = set()

        while True:
            for i in range(self.N):
                if i in non_empty_set: continue
                if self.queues[i].qsize() > 0:
                    non_empty_set.add(i)
                sender, received_value = self.queues[i].peek()
                counter[received_value].add(i)
                if received_value != NULL and len(counter[received_value]) >= k1:
                    return received_value, sorted(counter[received_value])
                if len(non_empty_set) >= k2:
                    return None, list()
            gevent.sleep(QueueCollection.TIMEOUT)


class QueueCollectionThreads:
    def __init__(self, queues):
        self.queues = queues.copy()
        self._get_queue = Queue()
        def _get_watcher(watched_queue: Queue, target_queue: Queue):
            # Watcher function to check if the queue is non-empty
            e = watched_queue.peek()  # blocking; avoid busy-waiting
            target_queue.put_nowait(e)

        self._get_threads = []
        for i in range(len(self.queues)):
            self._get_threads.append(gevent.spawn(_get_watcher, self.queues[i], self._get_queue))


    def get(self):
        return self._get_queue.get()


    def wait(self, k):
        # if not (0 < k <= len(self.queues)):
        #     raise ValueError("Invalid value of k")
        #
        # events = [Event() for _ in range(len(self.queues))]
        #
        # def watcher(queue: Queue, event):
        #     # Watcher function to check if the queue is non-empty
        #     queue.peek()  # blocking; avoid busy-waiting
        #     event.set()  # Set the event when the queue is non-empty
        #
        # threads = []
        # for i in range(len(self.queues)):
        #     threads.append(gevent.spawn(watcher, self.queues[i], events[i]))
        #
        # # Wait for at least k of the events to be set
        # gevent.joinall(events, count=k)
        # gevent.killall(threads)
        #
        # return [i for i, event in enumerate(events) if event.is_set()]
        return self.wait_value(None, k)

    def wait_value(self, value, k):
        if not (0 < k <= len(self.queues)):
            raise ValueError("Invalid value of k")

        events = [Event() for _ in range(len(self.queues))]

        def watcher(queue: Queue, event):
            # Watcher function to check if the queue is non-empty
            e = queue.peek()  # blocking; avoid busy-waiting

            if value is None:
                event.set()
                return

            try:
                sender, received_value = e
                if value == received_value:
                    event.set()  # Set the event when the queue is non-empty
            except Exception as e:
                print('watcher!?')
                print(e)

        threads = []
        for i in range(len(self.queues)):
            threads.append(gevent.spawn(watcher, self.queues[i], events[i]))

        # Wait for at least k of the events to be set
        gevent.joinall(events, count=k)
        gevent.killall(threads)

        return [i for i, event in enumerate(events) if event.is_set()]

    def get_k_matching_value(self, k, allow_null=True):
        queues: List[Queue] = self.queues.copy()
        if not (0 < k <= len(queues)):
            raise ValueError("Invalid value of k1 or k2")

        events = [Event() for _ in range(len(queues))]

        def watcher(queue: Queue, event):
            # Watcher function to check if the queue is non-empty
            e = queue.peek()  # blocking; avoid busy-waiting
            event.set()

        threads = []
        for i in range(len(queues)):
            threads.append(gevent.spawn(watcher, queues[i], events[i]))

        # at least k events is set!
        gevent.joinall(events, count=k)

        counter = dict()
        finished_threads = list()
        finished_events = list()

        while len(finished_events) < len(queues):
            gevent.joinall(events, count=1)
            for i in range(len(threads) - 1, -1, -1):
                if events[i].is_set():
                    try:
                        sender, received_value = queues[i].peek()
                        counter.setdefault(received_value, set())
                        counter[received_value].add(sender)
                        finished_events.append(events.pop(i))
                        finished_threads.append(threads.pop(i))
                        queues.pop(i)
                        if len(counter[received_value]) >= k:
                            if allow_null:
                                gevent.killall(finished_threads)
                                gevent.killall(threads)
                                return received_value
                            elif received_value != NULL:
                                gevent.killall(finished_threads)
                                gevent.killall(threads)
                                return received_value

                    except Exception as e:
                        print('watcher!?')
                        print(e)
            gevent.killall(finished_threads)
            finished_threads.clear()

        gevent.killall(threads)
        return None


    def get_value_at_least_k1_count_within_k2_count(self, k1, k2):
        queues = self.queues.copy()
        if not (0 < k1 <= k2 <= len(queues)):
            raise ValueError("Invalid value of k1 or k2")

        events = [Event() for _ in range(len(queues))]

        def watcher(queue: Queue, event):
            # Watcher function to check if the queue is non-empty
            e = queue.peek()  # blocking; avoid busy-waiting
            event.set()

        threads = []
        for i in range(len(queues)):
            threads.append(gevent.spawn(watcher, queues[i], events[i]))

        # at least k1 events is set!
        gevent.joinall(events, count=k1)

        counter = dict()
        finished_threads = list()
        finished_events = list()

        while len(finished_events) < k2:
            gevent.joinall(events, count=1)
            for i in range(len(threads) - 1, -1, -1):
                if events[i].is_set():
                    try:
                        sender, received_value = queues[i].peek()
                        counter.setdefault(received_value, set())
                        counter[received_value].add(sender)
                        finished_events.append(events.pop(i))
                        finished_threads.append(threads.pop(i))
                        queues.pop(i)
                        if len(counter[received_value]) >= k1:
                            gevent.killall(finished_threads)
                            gevent.killall(threads)
                            return received_value, sorted(counter[received_value])
                    except Exception as e:
                        print('watcher!?')
                        print(e)
            gevent.killall(finished_threads)
            finished_threads.clear()

        gevent.killall(threads)
        return None, list()

    def get_non_zero_value_at_least_k1_count_within_k2_count(self, k1, k2):
        queues = self.queues.copy()
        if not (0 < k1 <= k2 <= len(queues)):
            raise ValueError("Invalid value of k1 or k2")

        events = [Event() for _ in range(len(queues))]

        def watcher(queue: Queue, event):
            # Watcher function to check if the queue is non-empty
            e = queue.peek()  # blocking; avoid busy-waiting
            event.set()

        threads = []
        for i in range(len(queues)):
            threads.append(gevent.spawn(watcher, queues[i], events[i]))

        # at least k1 events is set!
        gevent.joinall(events, count=k1)

        counter = dict()
        finished_threads = list()
        finished_events = list()

        while len(finished_events) < k2:
            gevent.joinall(events, count=1)
            for i in range(len(threads) - 1, -1, -1):
                if events[i].is_set():
                    try:
                        sender, received_value = queues[i].peek()
                        counter.setdefault(received_value, set())
                        counter[received_value].add(sender)
                        finished_events.append(events.pop(i))
                        finished_threads.append(threads.pop(i))
                        queues.pop(i)
                        if received_value != NULL and len(counter[received_value]) >= k1:
                            gevent.killall(finished_threads)
                            gevent.killall(threads)
                            return received_value, sorted(counter[received_value])
                    except Exception as e:
                        print('watcher!?')
                        print(e)
            gevent.killall(finished_threads)
            finished_threads.clear()

        gevent.killall(threads)
        return None, list()
