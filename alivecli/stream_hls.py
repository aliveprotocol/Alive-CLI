from dataclasses import dataclass
from typing import List
from enum import Enum
import re
import logging
import os
import sys
import glob
import cv2
import requests
import json
import shutil
from tabulate import tabulate
from threading import Thread
import time
from beem import Hive
from beemgraphenebase import account
from . import oneloveipfs
from . import constants
from .exceptions import *
from .alivedb import AliveDB

class FileStatus(Enum):
    WAITING_FOR_FILE = ' '
    UPLOAD_QUEUED = '.'
    UPLOADING = '↑'
    REUPLOAD_QUEUED = '↔'
    REUPLOADING = '↨'
    SHARE_QUEUED = '▒'
    SHARING = '▓'
    SHARED = '█'
    SHARE_FAILED = 'x'

def touchDir(dir, strict = False):
    if (strict == True and os.path.isdir(dir)):
        raise Exception('Folder already exists: ' + dir)
    if not os.path.isdir(dir):
        os.mkdir(dir)

def get_length(filename):
    cap = cv2.VideoCapture(filename)
    fps = cap.get(cv2.CAP_PROP_FPS)      # OpenCV2 version 2 used "CV_CAP_PROP_FPS"
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration = frame_count/fps
    return duration

def get_latest_m3u8(recordFolder):
    pattern = os.path.join(recordFolder, '*.m3u8')
    list_of_files = glob.glob(pattern) # * means all if need specific format then *.csv
    if not list_of_files:
        return False
    latest_file = max(list_of_files, key=os.path.getctime)
    return latest_file

def check_ts(recordFolder):
    for file in os.listdir(recordFolder):
        if file.endswith(".ts"):
            return True
    return False

def updateDisplay(filearr):
    print_str = '\n\n\n\n\n\n\n\n\n'
    print_str += 'Status symbols:\n'
    symbarray = []
    
    for s in FileStatus:
        symbarray.append([s.name.lower().replace('_', ' '), s.value])
    table = (tabulate(symbarray, headers=['symbol', 'status'], tablefmt='orgtbl'))
    print_str += table + '\n\n\n'

    file = ['File']
    status = ['Status']
    length = ['Length']
    uptime = ['Upload time']
    terminalColumns, _ = shutil.get_terminal_size()
    showRows = int(terminalColumns/7) - 3
    ran = len(filearr) if (len(filearr) < showRows) else showRows
    for i in range(ran):
        ind = -ran+i
        file.append(filearr[ind].fileId)
        status.append(filearr[ind].status.value)
        videoLength = round(filearr[ind].length)
        if (videoLength == -1):
            length.append('')
        else:
            length.append(str(videoLength) + 's')
        uploadTime = filearr[ind].uploadTime
        if (uploadTime == -1):
            uptime.append('')
        else:
            uptime.append(str(uploadTime) + 's')

    table = (tabulate([file, status, length, uptime], tablefmt='orgtbl'))
    print_str += table
    print(print_str)

class VideoFile:
    def __init__(self, fileId):
        self.fileId = fileId
        self.status = FileStatus.WAITING_FOR_FILE
        self.uploadTime = -1
        self.length = -1
        self.skylink = ''
    def __str__(self):
        return str(self.__dict__)

@dataclass
class AliveInstance:
    """
    Data class that holds configuration for AliveDaemon.
    """
    upload_endpoint: str
    api: str
    halive_api: str
    username: str
    private_key: str
    link: str
    protocol: str = 'IPFS'
    network: str = 'hive'
    data_dir: str = os.path.expanduser(os.path.join('~', '.alive'))
    record_folder: str = 'record_here'
    purge_files: bool = False
    next_seq = 0
    batch_interval: int = 300 # 5 minutes

    def __post_init__(self) -> None:
        """
        Validates each value passed in AliveInstance and performs neccessary authentication.
        """
        if self.protocol == 'skynet':
            raise AliveDeprecationException('Skynet is deprecated')
        elif self.protocol not in constants.valid_protocols:
            raise ValueError('Invalid P2P protocol. Valid values are IPFS.')

        if self.network not in constants.valid_networks:
            raise ValueError('Invalid network. Valid values are hive.')

        if self.batch_interval > 300 or self.batch_interval < 0:
            raise ValueError('Batch interval must be between 0 and 300 seconds')

        # Validate link
        self.__link_validator__(self.link)

        # Init record folder
        if (os.path.isabs(self.record_folder) == False):
            self.record_folder = os.path.join(self.data_dir, self.record_folder)

        # Network authentication and sequence check
        if self.network == 'avalon':
            raise AliveDeprecationException('Avalon network is deprecated')
        elif self.network == 'hive':
            hive_pubkey = str(account.PrivateKey(wif=self.private_key).get_public_key())[3:]
            valid_key = False
            hive_accreq = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'condenser_api.get_accounts',
                'params': [[self.username]]
            }
            # support posting authorities from other accounts?
            hive_acckeys_req = requests.post(self.api,json=hive_accreq)
            if hive_acckeys_req.status_code != 200:
                raise AliveBlockchainAPIException('Could not fetch Hive account, status code: '+str(hive_acckeys_req.status_code))
            hive_acckeys = hive_acckeys_req.json()['result'][0]['posting']
            for i in range(len(hive_acckeys['key_auths'])):
                if hive_acckeys['key_auths'][i][0][3:] == hive_pubkey:
                    valid_key = True
                    break
            if valid_key != True:
                raise AliveAuthException('Invalid Hive private posting key')
            self.graphene_client = Hive(node=self.api,keys=[self.private_key])

            # Fetch playlist from HAF node
            playlist = requests.get(self.halive_api+'/get_stream_info?stream_author='+self.username+'&stream_link='+self.link)
            if playlist.status_code != 200:
                raise AliveRequestException('Failed to fetch stream info')
            playlistJson = playlist.json()
            if 'error' in playlistJson:
                raise AliveRequestException(playlistJson['error'])
            if playlistJson['chunk_finalized'] is not None:
                self.next_seq = playlistJson['chunk_finalized']+1
                print('Next sequence: '+str(self.next_seq))
            else:
                self.next_seq = 0

        # Upload endpoint authentication
        self.access_token = self.__upload_endpoint_auth__()

    def __link_validator__(self, link: str) -> None:
        """
        Validates Alive streams permlink
        """
        if len(link) < 1 or len(link) > 50:
            raise ValueError('Link must be between 1 and 50 characters long')

        if len(re.findall('^[A-Za-z0-9-_]*$',link)) < 1:
            raise ValueError('Link must only contain letters, digits, dashes and underscores')

    def __upload_endpoint_auth__(self) -> str:
        if self.protocol == 'IPFS' and self.upload_endpoint in constants.authenticated_ipfs_upload_endpoints:
            signed = ''
            if self.network == 'hive':
                signed = oneloveipfs.sign_message(oneloveipfs.generate_message_to_sign(self.username,'hive','oneloveipfs_login',self.api),self.private_key)

            # Obtain access token
            token = oneloveipfs.login(signed)
            if token['error']:
                raise AliveAuthRequestException(token['error'])
            return token['access_token']
        elif self.protocol == 'IPFS':
            return 'ipfsdaemon'
        return 'noauth'


class AliveDaemon:
    """
    Main daemon for Alive streams.
    """
    concurrent_uploads = 0
    nextStreamFilename = 0
    last_shared_fileid = -1
    chunk_count = 0
    stream_filename = ''
    is_running = False
    stopped = False

    def __init__(self, instance: AliveInstance, alivedb_instance: AliveDB = None):
        """
        Instantiates Alive stream daemon. AliveDB instance must be running and logged in.
        """
        if alivedb_instance is not None:
            assert alivedb_instance.external_process is True or alivedb_instance.process is not None, 'AliveDB is not running'
        assert alivedb_instance.is_logged_in(), 'AliveDB is not logged in'
        # Setup instance
        self.instance = instance
        self.alivedb_instance = alivedb_instance
        self.alivedb_instance.authenticate_token(self.instance.private_key,self.instance.username,self.instance.link,self.instance.api,self.instance.network)
        touchDir(self.instance.data_dir)
        
        if self.instance.next_seq:
            self.chunk_count = self.instance.next_seq

        self.filearr = [VideoFile(self.nextStreamFilename)]

        # Logging
        logFile = os.path.join(self.instance.data_dir, "stream_hls.log")
        logging.basicConfig(filename=logFile,
            filemode='a',
            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
            datefmt='%H:%M:%S',
            level=logging.DEBUG)
        logging.info('LOGGING STARTED')

    def start_worker(self):
        touchDir(self.instance.record_folder)

        cntr = 0
        while True:
            latest_m3u8 = get_latest_m3u8(self.instance.record_folder)
            if not latest_m3u8:
                if not (check_ts(self.instance.record_folder)):
                    print('Waiting for recording, no .m3u8 file found in ' + self.instance.record_folder + ' folder (%ds)' %(cntr))
                else:
                    print('Starting uploading... Waiting for first chunk and for .m3u8 file in ' + self.instance.record_folder + ' folder')
                cntr += 1
                time.sleep(1)
            else:
                filetime = os.path.getctime(latest_m3u8)
                now = time.time()
                if now-60 > filetime:
                    print("We found a stream, but it's older than a minute (maybe it is an old recording). Please start (or restart) the recording into " + self.instance.record_folder)
                    time.sleep(1)
                else:
                    # Start uplaoding
                    break

        self.is_running = True
        self.stream_filename = os.path.basename(latest_m3u8).replace('.m3u8', '')

        Thread(target=self.share_thread).start()
        while self.is_running:
            nextFile = os.path.join(self.instance.record_folder, self.stream_filename + str(self.nextStreamFilename) + ".ts")
            nextAfterFile = os.path.join(self.instance.record_folder, self.stream_filename + str(self.nextStreamFilename + 1) + ".ts")
            updateDisplay(self.filearr)
            if self.concurrent_uploads < 10 and ( os.path.isfile(nextAfterFile) or ( self.isPlaylistFinished(self.instance.record_folder) and os.path.isfile(nextFile) ) ):
                self.filearr.append(VideoFile(self.nextStreamFilename + 1))
                self.filearr[self.nextStreamFilename].status = FileStatus.UPLOAD_QUEUED
                nextLen = get_length(nextFile)
                self.filearr[self.nextStreamFilename].length = nextLen
                Thread(target=self.upload, args=(nextFile, self.nextStreamFilename, nextLen)).start()
                self.nextStreamFilename += 1
            else:
                time.sleep(1)

    def stop_worker(self, exit: bool) -> None:
        if self.stopped:
            return
        print('Stopping Alive daemon...')
        self.stopped = True
        self.is_running = False
        
        # Push all remaining AliveDB stream data to blockchains if any
        if self.alivedb_instance is not None:
            hashes, lengths = [], []
            nextToShare = self.last_shared_fileid + 1
            while self.filearr[nextToShare].status == FileStatus.SHARE_QUEUED or self.filearr[nextToShare].status == FileStatus.SHARE_FAILED:
                hashes.append(self.filearr[nextToShare].skylink)
                lengths.append(round(self.filearr[nextToShare].length,3))
                nextToShare = nextToShare + 1
            if len(hashes) > 1 and len(lengths) > 1:
                print('Pushing ' + str(len(hashes)) + ' stream chunks from AliveDB to ' + self.instance.network + '...')
                chunk_hash = self.process_chunk(hashes,lengths)
                if chunk_hash == '':
                    print('Failed to process chunks')
                elif self.instance.network == 'hive':
                    self.push_stream_graphene(chunk_hash)
            elif len(hashes) == 1 and len(lengths) == 1:
                print('Pushing ' + str(len(hashes)) + ' stream chunks from AliveDB to ' + self.instance.network + '...')
                if self.instance.network == 'hive':
                    self.push_stream_graphene(hashes[0],lengths[0])
            if self.alivedb_instance.external_process is False:
                self.alivedb_instance.stop()

        print('Alive daemon stopped successfully')
        if exit:
            sys.exit(0)

    def sigint_handler(self, signal_received, frame) -> None:
        """
        Stops Alive daemon when SIGINT or SIGTERM received.
        """
        self.stop_worker(True)

    def upload(self, filePath, fileId, length):
        start_time = time.time()
        self.concurrent_uploads += 1
        self.filearr[fileId].status = FileStatus.UPLOADING

        # upload file until success
        while True:
            skylink = ''
            if self.instance.protocol == 'IPFS':
                skylink = self.ipfs_push(filePath)

            push_success = self.alivedb_instance.push_stream(self.instance.network,self.instance.username,self.instance.link,skylink,round(self.filearr[fileId].length,3))

            if (len(skylink) >= 46) and push_success:
                self.filearr[fileId].skylink = skylink
                if self.filearr[fileId].status != FileStatus.SHARE_FAILED:
                    self.filearr[fileId].status = FileStatus.SHARE_QUEUED
                self.filearr[fileId].uploadTime = round(time.time() - start_time)
                self.concurrent_uploads -= 1
                if self.instance.purge_files == True:
                    os.remove(filePath)
                return True
            else:
                logging.error('Upload failed for ' + str(filePath))
                self.filearr[fileId].status = FileStatus.REUPLOAD_QUEUED
                time.sleep(10)
                self.filearr[fileId].status = FileStatus.REUPLOADING

    def isPlaylistFinished(self,recordFolder):
        playlistFile = os.path.join(recordFolder, self.stream_filename + ".m3u8")
        if (os.stat(playlistFile).st_size == 0):
            return False
        with open(playlistFile, 'r') as f:
            lines = f.read().splitlines()
            last_line = lines[-1]
            if last_line == '#EXT-X-ENDLIST':
                return True
            else:
                return False

    def share_thread(self):
        while self.is_running:
            toShare = []
            nextToShare = self.last_shared_fileid + 1
            while self.filearr[nextToShare].status == FileStatus.SHARE_QUEUED or self.filearr[nextToShare].status == FileStatus.SHARE_FAILED:
                toShare.append(nextToShare)
                nextToShare = nextToShare + 1
            if len(toShare) > 0 and (self.alivedb_instance is None or time.time() - self.alivedb_instance.last_pop_ts >= self.instance.batch_interval):
                if self.share(toShare) == True:
                    self.last_shared_fileid = toShare[len(toShare)-1]
                else:
                    time.sleep(10)
            time.sleep(0.2)

    def share(self, fileIds: List[int]) -> bool:
        assert len(fileIds) > 0, 'fileIds must contain at least one item'
        link, length = [], []
        if self.alivedb_instance is None:
            fileIds = [fileIds[0]]
        for i in fileIds:
            self.filearr[i].status = FileStatus.SHARING
            link.append(self.filearr[i].skylink)
            length.append(round(self.filearr[i].length,3))

        broadcast_stream = False
        chunk_hash = None
        single_segment = len(link) == 1 and len(length) == 1

        if single_segment is False:
            chunk_hash = self.process_chunk(link,length)
            if chunk_hash == '':
                logging.error('failed to upload chunk')
                for i in fileIds:
                    self.filearr[i].status = FileStatus.SHARE_FAILED
                return False

        if self.instance.network == 'hive':
            if single_segment:
                broadcast_stream = self.push_stream_graphene(link[0],length[0])
            else:
                broadcast_stream = self.push_stream_graphene(chunk_hash)

        if broadcast_stream is True:
            for i in fileIds:
                self.filearr[i].status = FileStatus.SHARED
            self.alivedb_instance.pop_recent_streams()
        else:
            logging.error('Failed to push stream')
            for i in fileIds:
                self.filearr[i].status = FileStatus.SHARE_FAILED

        return broadcast_stream

    def process_chunk(self, hashes: list, lengths: list):
        if self.instance.protocol == 'IPFS':
            return self.ipfs_chunk(hashes,lengths)

    def ipfs_push(self,filePath):
        if self.instance.upload_endpoint in constants.authenticated_ipfs_upload_endpoints:
            fileToUpload = {'segment': open(filePath,'rb')}
            jsonbody = {'streamId':self.instance.link}
            postUrl = self.instance.upload_endpoint + '/uploadStream?access_token=' + self.instance.access_token
            try:
                upload = requests.post(postUrl,files=fileToUpload,data=jsonbody)
                fileToUpload['segment'].close()
                if upload.status_code == 200:
                    return json.loads(upload.text)['hash']
                else:
                    logging.error('IPFS upload errored',upload.text)
                    return ''
            except Exception:
                logging.error('IPFS upload failed')
                return ''
        else:
            # Assume IPFS API unless stated otherwise
            fileToAdd = {'file': open(filePath,'rb')}
            try:
                upload = requests.post(self.instance.upload_endpoint+'/api/v0/add',files=fileToAdd)
                fileToAdd['file'].close()
                if upload.status_code == 200:
                    return upload.json()['Hash']
                else:
                    logging.error('IPFS add failed')
                    return ''
            except Exception as e:
                fileToAdd['file'].close()
                logging.error('IPFS add request failed',e)
                return ''

    def ipfs_chunk(self, hashes: list, lengths: list) -> str:
        assert len(hashes) == len(lengths), 'hashes and lengths lists should have the same length'
        
        csv_content = self.csv_chunk(hashes,lengths)

        if self.instance.upload_endpoint in constants.authenticated_ipfs_upload_endpoints:
            postUrl = self.instance.upload_endpoint + '/uploadChunk?access_token=' + self.instance.access_token
            upload = requests.post(postUrl,data={'content':csv_content})
            if upload.status_code == 200:
                return json.loads(upload.text)['hash']
            else:
                logging.error('IPFS upload failed')
                return ''
        else:
            try:
                fileToAdd = {'file': csv_content}
                upload = requests.post(self.instance.upload_endpoint+'/api/v0/add',files=fileToAdd)
                if upload.status_code == 200:
                    return upload.json()['Hash']
                else:
                    logging.error('IPFS add chunk failed')
                    return ''
            except Exception as e:
                logging.error('IPFS add chunk failed',e)
                return ''

    def csv_chunk(self, hashes: list, lengths: list) -> str:
        assert len(hashes) == len(lengths), 'hashes and lengths lists should have the same length'

        csv_content = ''
        for i in range(len(hashes)):
            if len(csv_content) > 0:
                csv_content += '\n'
            csv_content += hashes[i] + ',' + str(lengths[i])

        return csv_content

    def push_stream_graphene(self, chunk_hash: str, length: float = None) -> bool:
        json_data = {
            'op': 0,
            'seq': self.chunk_count,
            'link': self.instance.link,
            'src': chunk_hash
        }
        if length is not None:
            json_data['len'] = length
        logging.info('Broadcasting custom_json to Hive: ' + json.dumps(json_data))
        try:
            self.instance.graphene_client.custom_json(constants.hive_custom_json_id,json_data,required_posting_auths=[self.instance.username])
            self.chunk_count += 1
            return True
        except Exception as e:
            logging.error('Broadcast error: ' + str(e))
            logging.error('Custom JSON: ' + json.dumps(json_data))
            return False