import signal

def handler(signum, frame):
  print('Forever is over!')
  raise Exception("end of time")

def loop_forever():
  import time
  while 1:
    print("sec")
    time.sleep(1)

signal.signal(signal.SIGLARM, handler)
signal.alarm(10)

loop_forever()
