import threading

class CustomThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super(CustomThread, self).__init__(*args, **kwargs)
        self._stopper = threading.Event()
    
    def stop(self):
        self._stopper.set()

    def stopped(self):
        return self._stopper.is_set()

    def run(self):
        while not self.stopped():
            self._target(*self._args, **self._kwargs)