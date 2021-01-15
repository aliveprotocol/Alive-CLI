import os
import sys
import subprocess
import signal
import requests_unixsocket
import time

default_data_dir = os.path.expanduser(os.path.join('~', '.alive'))

def alivedb_install(alivedir: str = default_data_dir) -> None:
    """
    Clones AliveDB repository and installs npm dependencies.
    """
    # TODO: Download NodeJS and npm if not available?
    if os.system('node -v') > 0 or os.system('npm -v') > 0:
        raise RuntimeError('NodeJS and/or npm is not installed')
    os.chdir(alivedir)
    # TODO: Download tagged zip source code?
    os.system('git clone https://github.com/techcoderx/AliveDB')
    os.chdir('AliveDB')
    os.system('npm i')

class AliveDB:
    """
    Main AliveDB daemon class.
    """
    recent_hashes = []
    recent_lengths = []
    last_pop_ts = time.time()
    userid = None
    userpub = None
    userkey = None

    def __init__(self, alivedir: str = default_data_dir+'/AliveDB', peers: list = [], gun_port = None) -> None:
        """
        Instantiates an AliveDB instance.

        :alivedir: AliveDB working directory for databases etc.
        :peers: List of GunDB P2P endpoints
        :gun_port: GunDB P2P port to bind to
        """
        self.process = None
        self.alivedir = alivedir
        self.peers = peers
        self.gun_port = gun_port
        self.socket = alivedir + '/alivedb.sock'
        self.socketurl = 'http+unix://'+('%2F'.join(self.socket.split('/')))
        self.session = requests_unixsocket.Session()

        if os.path.exists(self.socket):
            os.remove(self.socket)

    def start(self) -> None:
        """
        Starts AliveDB daemon.
        """
        # TODO Check AliveDB installation
        if self.process is not None:
            return
        os.chdir(self.alivedir)
        cmd = ['node','src/index.js']
        if len(self.peers) > 0:
            cmd.append('--peers='+str(self.peers))
        cmd.append('--http_port='+str(self.socket))
        if self.gun_port is not None:
            cmd.append('--gun_port='+str(self.gun_port))
        self.process = subprocess.Popen(cmd)
        time.sleep(2)

    def stop(self) -> None:
        """
        Sends SIGINT to AliveDB daemon.
        """
        assert self.process is not None, 'AliveDB is not running'
        os.kill(self.process.pid,signal.SIGINT)
        os.remove(self.alivedir+'/alivedb.sock')
        self.process = None

    def create_user(self, id: str, key: str) -> None:
        """
        Create AliveDB user.
        """
        assert self.process is not None, 'AliveDB is not running'
        json = {
            'id': id,
            'key': key
        }
        r = self.session.post(self.socketurl+'/createUser',json=json)
        if r.status_code == 200:
            self.userid = r.json()['id']
            self.userpub = r.json()['pub']
            self.userkey = key
        else:
            # TODO: Proper error handling. Raise exception?
            print(r.json()['error'])

    def login(self, key: str, id: str = '', pub: str = '') -> None:
        """
        Login with AliveDB user ID or public key (one of which must not be blank) and key.
        """
        assert self.process is not None, 'AliveDB is not running'
        if len(id) == 0 and len(pub) == 0:
            raise ValueError('User ID or public key is required')
        json = { 'key': key }
        if len(id) > 0:
            json['id'] = id
        elif len(pub) > 0:
            json['pub'] = pub
        else:
            raise AssertionError
        r = self.session.post(self.socketurl+'/loginUser',json=json)
        if r.status_code == 200:
            r = self.session.get(self.socketurl+'/currentUser')
            self.userid = r.json()['alias']
            self.userpub = r.json()['pub']
            self.userkey = key
        else:
            # TODO: Proper error handling
            print(r.json()['error'])

    def is_logged_in(self) -> bool:
        """
        Checks if current AliveDB instance is logged in.
        """
        return self.userid is not None and self.userkey is not None and self.userpub is not None

    def push_stream(self, network: str, streamer: str, link: str, src: str, length: float) -> bool:
        """
        Push new stream to AliveDB.
        """
        assert self.process is not None, 'AliveDB is not running'
        assert network == 'dtc' or network == 'hive', 'Network must be dtc or hive'
        new_stream = {
            'src': src,
            'len': length
        }
        json = {
            'network': network,
            'streamer': streamer,
            'link': link,
            'stream': new_stream
        }
        r = self.session.post(self.socketurl+'/pushStream',json=json)
        if r.status_code == 200:
            self.recent_hashes.append(src)
            self.recent_lengths.append(length)
            return True
        else:
            # TODO: Proper error handling
            print(r.json()['error'])
            return False

    def pop_recent_streams(self) -> tuple:
        """
        Pops recently pushed streams and returns it.
        """
        streams = (self.recent_hashes, self.recent_lengths)
        self.recent_hashes = []
        self.recent_lengths = []
        self.last_pop_ts = time.time()
        return streams