from alivedb import AliveDB
import sys
import string
import random

if len(sys.argv) != 2 and len(sys.argv) != 3:
    print('Usage: ' + sys.argv[0] + ' <new_alivedb_password> [new_alivedb_userid]')
    sys.exit(0)

uid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))

if (len(sys.argv) == 3):
    uid = sys.argv[2]

new_pass = sys.argv[1]

alivedb = AliveDB()
alivedb.start()
alivedb.create_user(id=uid,key=new_pass)
alivedb.stop()

print('User ID: ' + alivedb.userid)
print('Public Key: ' + alivedb.userpub)