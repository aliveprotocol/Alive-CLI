import os
import sys
import subprocess
import signal

default_data_dir = os.path.expanduser(os.path.join('~', '.alive'))

def alivedb_install(alivedir: str = default_data_dir):
    """
    Clones AliveDB repository and installs npm dependencies
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
    def __init__(self, alivedir: str = default_data_dir+'/AliveDB', peers: list = [], http_port = None, gun_port = None):
        """
        Instantiates an AliveDB instance.

        :alivedir: AliveDB working directory for databases etc.
        :peers: List of GunDB P2P endpoints
        :http_port: Port number or unix socket to bind to
        :gun_port: GunDB P2P port to bind to
        """
        self.process = None
        self.alivedir = alivedir
        self.peers = peers

        if http_port is None:
            self.http_port = alivedir + '/alivedb.sock'
        else:
            self.http_port = http_port

        self.gun_port = gun_port

    def start(self):
        """
        Starts AliveDB daemon
        """
        # TODO Check AliveDB installation
        os.chdir(self.alivedir)
        cmd = ['node','src/index.js']
        if len(self.peers) > 0:
            cmd.append('--peers='+str(self.peers))
        cmd.append('--http_port='+str(self.http_port))
        if self.gun_port is not None:
            cmd.append('--gun_port='+str(self.gun_port))
        self.process = subprocess.Popen(cmd)

    def stop(self):
        """
        Sends SIGINT to AliveDB daemon
        """
        assert self.process is not None, 'AliveDB is not running'
        os.kill(self.process.pid,signal.SIGINT)
        self.process = None