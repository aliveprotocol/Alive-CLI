from typing import List
import os
import subprocess
import signal
import requests
import requests_unixsocket
import time
import hashlib
import zipfile
import io
from .exceptions import *
from .oneloveipfs import sign_message
from .alivedb_integrity import integrity

default_data_dir = os.path.expanduser(os.path.join('~', '.alive'))
default_tag = 'master'
default_repo = 'https://github.com/techcoderx/AliveDB'

def is_git_installed() -> bool:
    """
    Check for git installation
    """
    return os.system('git --version') == 0

def quicksort(arr: List[str]) -> List[str]:
    """
    Quicksort algorithm for list of strings ascending
    """
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quicksort(left) + middle + quicksort(right)

def alivedb_list_src(alivedir: str = default_data_dir) -> List[str]:
    """
    List source files in AliveDB for checksum computation
    """
    alivedb_dir_root = os.path.join(alivedir,'AliveDB')
    alivedb_dir_src = os.path.join(alivedb_dir_root,'src')
    files = []
    package_files = ['package.json','package-lock.json']
    for i in package_files:
        if os.path.isfile(os.path.join(alivedb_dir_root,i)):
            files.append(i)
    if os.path.isdir(alivedb_dir_src):
        for i in quicksort(os.listdir(alivedb_dir_src)):
            files.append('src/'+i)
    return files

def alivedb_calculate_sha256(alivedir: str = default_data_dir) -> str:
    """
    Calculate SHA256 hash of AliveDB source files
    """
    alivedb_dir_root = os.path.join(alivedir,'AliveDB')
    files = alivedb_list_src(alivedir)
    m = hashlib.sha256()
    for i in files:
        with open(os.path.join(alivedb_dir_root,i),'rb') as opened:
            for byte_block in iter(lambda: opened.read(4096),b""):
                m.update(byte_block)
    return m.hexdigest()

def alivedb_is_installed_with_git(alivedir: str = default_data_dir) -> bool:
    """
    Check if AliveDB is installed using git
    """
    return os.path.exists(os.path.join(alivedir,'AliveDB','.git'))

def alivedb_setup_nvm() -> None:
    """
    Setup Node Version Manager for use in AliveDB.
    """
    nvm_dir = os.path.join(os.environ['HOME'], '.nvm')
    if os.path.exists(nvm_dir):
        os.system('[ -s "'+nvm_dir+'/nvm.sh" ] && \. "'+nvm_dir+'/nvm.sh"')
        os.system('[ -s "'+nvm_dir+'/bash_completion" ] && \. "'+nvm_dir+'/bash_completion"')

def alivedb_install(alivedir: str = default_data_dir, tag: str = default_tag) -> None:
    """
    Clones AliveDB repository and installs npm dependencies.
    """
    alivedb_dependency_check()
    os.chdir(alivedir)
    if is_git_installed():
        os.system(f'git clone -b {tag} {default_repo}')
    else:
        r = requests.get(f'{default_repo}/archive/{tag}.zip')
        r.raise_for_status()
        z = zipfile.ZipFile(io.BytesIO(r.content))
        z.extractall(path=alivedir)
        os.rename(f'AliveDB-{tag}','AliveDB')
    os.chdir('AliveDB')
    os.system('npm i')

def alivedb_dependency_check() -> bool:
    """
    Test NodeJS and npm installation.
    """
    alivedb_setup_nvm()
    if os.system('node -v') > 0:
        raise AliveMissingDependencyExeption('NodeJS is not installed')
    if os.system('npm -v') > 0:
        raise AliveMissingDependencyExeption('npm is not installed')
    return True

def alivedb_integrity(alivedir: str = default_data_dir, dev_mode: bool = False, dependency_check: bool = False) -> str:
    """
    Verifies the integrity of AliveDB installation.

    Returns the installed version, or `dev` if `dev_mode` is `True`.

    Raises `AliveMissingDependencyExeption` for missing dependencies and `AliveDBIntegrityException` for invalid checksums.
    """
    if dependency_check:
        alivedb_dependency_check()
    if dev_mode is False:
        checksum = alivedb_calculate_sha256(alivedir)
        for i in integrity:
            if integrity[i] == checksum:
                return i
        raise AliveDBIntegrityException('AliveDB checksum error')
    else:
        return 'dev'

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
    dev_mode = False

    def __init__(self, alivedir: str = default_data_dir+'/AliveDB', peers: list = [], gun_port = None, chat_listener: str = '', dev_mode: bool = False) -> None:
        """
        Instantiates an AliveDB instance.

        :alivedir: AliveDB working directory for databases etc.
        :peers: List of GunDB P2P endpoints
        :gun_port: GunDB P2P port to bind to
        """
        self.dev_mode = dev_mode
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
                raise AliveRequestException('Failed to fetch AliveDB login status from external process, status code: '+str(alivedb_session_login.status_code))
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
        if self.process is not None or self.external_process is False:
            return
        os.chdir(self.alivedir)
        print('AliveDB version:',alivedb_integrity(self.alivedir,self.dev_mode,True))
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
            raise AliveAuthException('User ID or public key is required')
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
            raise AliveAuthRequestException('Could not authenticate to endpoint')
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
                raise AliveBlockchainAPIException('Could not fetch dynamic global properties')
        return message