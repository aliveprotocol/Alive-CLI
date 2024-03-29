from time import sleep
from alivecli.alivedb import AliveDB
import sys
import string
import random

def main():
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print('Usage: alivedb_usercreate <new_alivedb_password> [new_alivedb_userid]')
        sys.exit(0)

    uid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))

    if (len(sys.argv) == 3):
        uid = sys.argv[2]

    new_pass = sys.argv[1]

    alivedb = AliveDB()
    alivedb.start()
    alivedb.create_user(id=uid,key=new_pass)
    sleep(1)
    alivedb.stop()

    print('User ID: ' + alivedb.userid)
    print('Public Key: ' + alivedb.userpub)