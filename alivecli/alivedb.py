import os
import subprocess
import signal
import requests
import requests_unixsocket
import time
import hashlib
from oneloveipfs import sign_message

if '.' in __name__:
    from .alivedb_integrity import integrity
else:
    from alivedb_integrity import integrity

default_data_dir = os.path.expanduser(os.path.join('~', '.alive'))
default_tag = 'master'

def alivedb_setup_nvm() -> None:
    """
    Setup Node Version Manager for use in AliveDB.
    """
    nvm_dir = os.environ['HOME'] + '/.nvm'
    os.system('[ -s "'+nvm_dir+'/nvm.sh" ] && \. "'+nvm_dir+'/nvm.sh"')
    os.system('[ -s "'+nvm_dir+'/bash_completion" ] && \. "'+nvm_dir+'/bash_completion"')

def alivedb_install(alivedir: str = default_data_dir, tag: str = default_tag) -> None:
    """
    Clones AliveDB repository and installs npm dependencies.
    """
    alivedb_setup_nvm()
    alivedb_dependency_check()
    os.chdir(alivedir)
    # TODO: Download tagged zip source code?
    os.system('git clone https://github.com/techcoderx/AliveDB')
    os.chdir('AliveDB')
    os.system('git checkout '+tag)
    os.system('npm i')

def alivedb_dependency_check() -> bool:
    """
    Test NodeJS, npm and Git installation.
    """
    alivedb_setup_nvm()
    if os.system('node -v') > 0:
        raise RuntimeError('NodeJS is not installed')
    if os.system('npm -v') > 0:
        raise RuntimeError('npm is not installed')
    if os.system('git --version') > 0:
        raise RuntimeError('Git is not installed')
    return True

def alivedb_integrity(alivedir: str = default_data_dir, dev_mode: bool = False, dependency_check: bool = False) -> bool:
    """
    Verifies the integrity of AliveDB installation.
    """
    if dependency_check:
        try:
            alivedb_dependency_check()
        except RuntimeError:
            return False
    for f in integrity:
        test_file = alivedir+'/AliveDB/'+f
        if os.path.exists(test_file) is False:
            return False
        if dev_mode is False:
            sha256_hash = hashlib.sha256()
            with open(test_file,"rb") as opened_file:
                for byte_block in iter(lambda: opened_file.read(4096),b""):
                    sha256_hash.update(byte_block)
                if sha256_hash.hexdigest() != integrity[f]:
                    return False
    return True

def alivedb_installation_check(alivedir: str = default_data_dir, dev_mode: bool = False):
    """
    Checks AliveDB installation and returns its type.

    Returns 1 for source code installation, 0 otherwise.
    """
    if alivedb_integrity(alivedir,dev_mode,True) is True:
        return 1
    else:
        return 0

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
    requires_access_token = False
    access_token = ''
    auth_identifier = ''

    def __init__(self, alivedir: str = default_data_dir+'/AliveDB', peers: list = [], gun_port = None, chat_listener: str = '') -> None:
        """
        Instantiates an AliveDB instance.

        :alivedir: AliveDB working directory for databases etc.
        :peers: List of GunDB P2P endpoints
        :gun_port: GunDB P2P port to bind to
        """
        self.process = None
        self.external_process = alivedir.startswith('http://') or alivedir.startswith('https://')

        if self.external_process is False:
            self.alivedir = alivedir
            self.peers = peers
            self.gun_port = gun_port
            self.chat_listener = chat_listener
            self.socket = alivedir + '/alivedb.sock'
            self.socketurl = 'http+unix://'+('%2F'.join(self.socket.split('/')))
            self.session = requests_unixsocket.Session()

            if os.path.exists(self.socket):
                os.remove(self.socket)
        else:
            self.socketurl = alivedir
            self.session = requests

            # fetch login
            alivedb_session_login = self.session.get(self.socketurl+'/currentUser')
            if alivedb_session_login.status_code != 200:
                raise RuntimeError('Failed to fetch AliveDB login status from external process, status code: '+str(alivedb_session_login.status_code))
            external_login = alivedb_session_login.json()
            if 'pub' in external_login:
                self.userpub = external_login['pub']
            if 'alias' in external_login:
                self.userid = external_login['alias']
            if 'requiresAccessToken' in external_login and external_login['requiresAccessToken']:
                self.requires_access_token = True
                self.auth_identifier = external_login['authId']

    def start(self) -> None:
        """
        Starts AliveDB daemon.
        """
        # TODO Check AliveDB installation
        if self.process is not None or self.external_process is False:
            return
        os.chdir(self.alivedir)
        cmd = ['node','src/index.js']
        if len(self.peers) > 0:
            cmd.append('--peers='+str(self.peers))
        cmd.append('--http_port='+str(self.socket))
        if self.gun_port is not None:
            cmd.append('--gun_port='+str(self.gun_port))
        if self.chat_listener != '':
            cmd.append('--chat_listener='+self.chat_listener)
        self.process = subprocess.Popen(cmd)
        if self.gun_port is None:
            while os.path.exists(self.socket) is False:
                time.sleep(1)
        else:
            time.sleep(2)

    def stop(self) -> None:
        """
        Sends SIGINT to AliveDB daemon.
        """
        assert self.external_process is False, 'Cannot stop AliveDB external process'
        assert self.process is not None, 'AliveDB is not running'
        os.kill(self.process.pid,signal.SIGINT)
        os.remove(self.alivedir+'/alivedb.sock')
        self.process = None

    def create_user(self, id: str, key: str) -> None:
        """
        Create AliveDB user.
        """
        assert self.external_process is False, 'Unable to create user on external process'
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
        assert self.external_process is False, 'Unable to login on external process'
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
        return self.userid is not None and (self.userkey is not None or self.external_process is True) and self.userpub is not None

    def fetch_participants_keys(self) -> None:
        assert self.external_process is True or self.process is not None, 'AliveDB is not running'
        self.session.get(self.socketurl+'/fetchParticipantsKeys')

    def push_stream(self, network: str, streamer: str, link: str, src: str, length: float) -> bool:
        """
        Push new stream to AliveDB.
        """
        assert self.external_process is True or self.process is not None, 'AliveDB is not running'
        assert network == 'hive', 'Network must be hive'
        if self.requires_access_token:
            assert len(self.access_token) > 0, 'Access token is missing, please authenticate with authenticate_token() first.'
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
        headers = None
        if self.requires_access_token:
            headers = { 'Authorization': 'Bearer '+self.access_token }
        r = self.session.post(self.socketurl+'/pushStream',json=json, headers=headers)
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
    
    def authenticate_token(self, wif: str, username: str, link: str, api: str, network: str = 'hive') -> None:
        """
        Retrive access token for endpoints that require it
        """
        if self.requires_access_token is False:
            return
        signed_msg = sign_message(AliveDB.generate_message_to_sign(username, link, network, self.auth_identifier, api),wif)
        headers = { 'Content-Type': 'text/plain' }
        loginsig = requests.post(self.socketurl+'/getToken',data=signed_msg,headers=headers)
        if loginsig.status_code != 200:
            raise RuntimeError('Could not authenticate to endpoint')
        result = loginsig.json()
        self.access_token = result['access_token']

    @staticmethod
    def generate_message_to_sign(username: str, link: str, network: str, auth_id: str, api: str) -> str:
        """
        Generate message to sign for AliveDB external endpoint auth
        """
        message = username+':'+link+':'+auth_id+':'+network+':'
        if network == 'hive':
            try:
                props = requests.post(api,json={
                    'jsonrpc': '2.0',
                    'id': 1,
                    'method': 'condenser_api.get_dynamic_global_properties',
                    'params': []
                }).json()['result']
                message = message+str(props['head_block_number'])+':'+str(props['head_block_id'])
            except:
                raise RuntimeError('Could not fetch dynamic global properties')
        return message