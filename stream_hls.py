from dataclasses import dataclass
import re
import constants
import logging
import os
import sys
import glob
from cv2 import cv2
import requests
import json
import shutil
import siaskynet as skynet
from tabulate import tabulate
from threading import Thread
import time
import base58
import secp256k1
import hashlib
import ipfshttpclient
import decrypt
from beem import Hive
from beemgraphenebase import account
from alivedb import AliveDB

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

def updateDisplay(filearr, symbols):
	print_str = '\n\n\n\n\n\n\n\n\n'
	print_str += 'Status symbols:\n'
	symbarray = []
	idx = 0
	
	for key, value in symbols.items():
		symbarray.append([value, key])
		idx += 1
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
		symbolCode = filearr[ind].status
		file.append(filearr[ind].fileId)
		status.append(symbols[symbolCode])
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
		self.status = 'waiting for file'
		self.uploadTime = -1
		self.length = -1
		self.skylink = 'skylink'
	def __str__(self):
		return str(self.__dict__)

@dataclass
class AliveInstance:
	"""
	Data class that holds configuration for AliveDaemon.
	"""
	protocol: str
	upload_endpoint: str
	network: str
	api: str
	username: str
	private_key: str
	link: str
	data_dir: str = os.path.expanduser(os.path.join('~', '.alive'))
	record_folder: str = 'record_here'
	purge_files: bool = False

	def __post_init__(self) -> None:
		"""
		Validates each value passed in AliveInstance and performs neccessary authentication.
		"""
		if self.protocol not in constants.valid_protocols:
			raise ValueError('Invalid P2P protocol. Valid values are IPFS and Skynet.')

		if self.network not in constants.valid_networks:
			raise ValueError('Invalid network. Valid values are dtc and hive.')

		# Init record folder
		if (os.path.isabs(self.record_folder) == False):
			self.record_folder = os.path.join(self.data_dir, self.record_folder)

		# Network authentication
		if self.network == 'dtc':
			# Avalon username
			avalon_account = requests.get(self.api + '/account/' + self.username)
			if avalon_account.status_code != 200:
				raise RuntimeError('Avalon username does not exist')

			# Avalon key
			avalon_pubkey = base58.b58encode(secp256k1.PrivateKey(base58.b58decode(self.private_key)).pubkey.serialize()).decode('UTF-8')
			if avalon_account.json()['pub'] != avalon_pubkey:
				valid_key = False
				for i in range(0,len(avalon_account.json()['keys'])):
					# TODO: Update with the correct op # on livestreaming HF
					if avalon_account.json()['keys'][i]['pub'] == avalon_pubkey and all(x in avalon_account.json()['keys'][i]['types'] for x in [19, 20]):
						self.custom_keyid = avalon_account.json()['keys'][i]['id']
						valid_key = True
						break
				if valid_key == False:
					raise RuntimeError('Invalid Avalon key')
				else:
					print('Logged in with custom key')
			else:
				self.custom_keyid = None
				print('Logged in with master key')
		elif self.network == 'hive':
			hive_pubkey = account.PrivateKey(wif=self.private_key,prefix='TST').get_public_key()
			valid_key = False
			hive_accreq = {
				'jsonrpc': '2.0',
				'id': 1,
				'method': 'condenser_api.get_accounts',
				'params': [[self.username]]
			}
			# support posting authorities from other accounts?
			hive_acckeys = requests.post(self.api,json=hive_accreq).json()['result'][0]['posting']
			for i in range(len(hive_acckeys['key_auths'])):
				if hive_acckeys['key_auths'][i][0] == str(hive_pubkey):
					valid_key = True
					break
			if valid_key != True:
				raise RuntimeError('Invalid Hive private posting key')
			self.graphene_client = Hive(node=self.api,keys=[self.private_key])

		# Validate link
		self.__link_validator__(self.link)

		# TODO: Check if stream has ended already?

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
			loginUrl = self.upload_endpoint + '/login?user=' + self.username + '&network=' + self.network
			if self.network == 'dtc' and self.custom_keyid != None:
				loginUrl += '&dtckeyid=' + self.custom_keyid
			auth_request = requests.get(loginUrl)
			if auth_request.status_code != 200:
				# TODO: Raise appropriate error message
				raise RuntimeError('Could not authenticate to upload endpoint')

			# Decrypt with Avalon key
			encrypted_memo = auth_request.json()['encrypted_memo']
			decrypted_memo = None
			if self.network == 'dtc':
				decrypt.ecies_decrypt(base58.b58decode(self.private_key),decrypt.js_to_py_encrypted(encrypted_memo))
			elif self.network == 'hive':
				raise NotImplementedError('Alive Protocol coming soon to Hive...')

			# Obtain access token
			headers = { 'Content-Type': 'text/plain' }
			access_token_request = requests.post(self.upload_endpoint + '/logincb',data=decrypted_memo,headers=headers)
			if access_token_request.status_code != 200:
				# TODO: Raise appropriate error
				raise RuntimeError('Could not authenticate to upload endpoint')
			else:
				return access_token_request.json()['access_token']
		elif self.protocol == 'IPFS':
			self.ipfs_api = ipfshttpclient.connect(self.upload_endpoint)
		elif self.protocol == 'Skynet':
			self.skynet_api = skynet.SkynetClient(self.upload_endpoint)
		return 'noauth'


class AliveDaemon:
	"""
	Main daemon for Alive streams.
	"""
	alivedb_batch_interval = 300 # 5 minutes
	concurrent_uploads = 0
	nextStreamFilename = 0
	stream_filename = ''
	is_running = False

	def __init__(self, instance: AliveInstance, alivedb_instance: AliveDB = None):
		"""
		Instantiates Alive stream daemon. AliveDB instance must be running and logged in.
		"""
		assert alivedb_instance.process is not None, 'AliveDB is not running'
		assert alivedb_instance.is_logged_in(), 'AliveDB is not logged in'
		# Setup instance
		self.instance = instance
		self.alivedb_instance = alivedb_instance
		touchDir(self.instance.data_dir)

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
		symbols = {
			'waiting for file':				' ',
			'upload queued':				'.',
			'uploading':					'↑',
			'uploading with backup portal':	'↕',
			'queued for re-uploading':		'↔',
			're-uploading':					'↨',
			'share queued':					'▒',
			'sharing':						'▓',
			'shared':						'█',
			'share failed':					'x'
		}
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
			updateDisplay(self.filearr, symbols)
			if self.concurrent_uploads < 10 and ( os.path.isfile(nextAfterFile) or ( self.isPlaylistFinished(self.instance.record_folder) and os.path.isfile(nextFile) ) ):
				self.filearr.append(VideoFile(self.nextStreamFilename + 1))
				self.filearr[self.nextStreamFilename].status = 'upload queued'
				nextLen = get_length(nextFile)
				self.filearr[self.nextStreamFilename].length = nextLen
				Thread(target=self.upload, args=(nextFile, self.nextStreamFilename, nextLen)).start()
				self.nextStreamFilename += 1
			else:
				time.sleep(1)

	def stop_worker(self) -> None:
		print('Stopping Alive daemon...')
		self.is_running = False
		
		# Push all remaining AliveDB stream data to blockchains if any
		if self.alivedb_instance is not None:
			hashes, lengths = self.alivedb_instance.pop_recent_streams()
			if len(hashes) > 0 and len(lengths) > 0:
				print('Pushing ' + str(len(hashes)) + ' stream chunks from AliveDB to ' + self.instance.network + '...')
				if self.instance.network == 'dtc':
					self.push_stream_avalon(hashes,lengths)
				elif self.instance.network == 'hive':
					self.push_stream_graphene(hashes,lengths)
			self.alivedb_instance.stop()

		print('Alive daemon stopped successfully')

	def sigint_handler(self, signal_received, frame) -> None:
		"""
		Stops Alive daemon when SIGINT or SIGTERM received.
		"""
		self.stop_worker()
		sys.exit(0)

	def upload(self, filePath, fileId, length):
		start_time = time.time()
		self.concurrent_uploads += 1
		self.filearr[fileId].status = 'uploading'

		# upload file until success
		while True:
			# upload and retry if fails with backup portals
			skylink = False
			if self.instance.protocol == 'Skynet':
				for upload_portal in constants.skynet_upload_portals:
					skylink = self.skynet_push(filePath, upload_portal)
					if skylink != False:
						break
					else:
						self.filearr[fileId].status = 'uploading with backup portal'
			elif self.instance.protocol == 'IPFS':
				skylink = self.ipfs_push(filePath)

			if (skylink != False and len(skylink) >= 46):
				skylink = skylink.replace("sia://", "")
				self.filearr[fileId].skylink = skylink
				if self.filearr[fileId].status != 'share failed':
					self.filearr[fileId].status = 'share queued'
				self.filearr[fileId].uploadTime = round(time.time() - start_time)
				self.concurrent_uploads -= 1
				if self.instance.purge_files == True:
					os.remove(filePath)
				return True
			else:
				logging.error('Upload failed with all portals for ' + str(filePath))
				self.filearr[fileId].status = 'queued for re-uploading'
				time.sleep(10)
				self.filearr[fileId].status = 're-uploading'

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
		lastSharedFileId = -1
		while self.is_running:
			nextToShare = lastSharedFileId + 1
			if self.filearr[nextToShare].status == 'share queued' or self.filearr[nextToShare].status == 'share failed':
				if self.share(nextToShare) == True:
					lastSharedFileId += 1
				else:
					time.sleep(10)
			time.sleep(0.2)

	def share(self,fileId):
		self.filearr[fileId].status = 'sharing'

		link = [self.filearr[fileId].skylink]
		length = [round(self.filearr[fileId].length,3)]

		broadcast_stream = None
		should_push_to_chains = self.alivedb_instance is None or time.time() - self.alivedb_instance.last_pop_ts >= self.alivedb_batch_interval

		if self.alivedb_instance is not None:
			broadcast_stream = self.alivedb_instance.push_stream(self.instance.network,self.instance.username,self.instance.link,link[0],length[0])
		if self.alivedb_instance is not None and should_push_to_chains:
			link, length = self.alivedb_instance.pop_recent_streams()

		if self.instance.network == 'dtc' and should_push_to_chains:
			broadcast_stream = self.push_stream_avalon(link,length)
		elif self.instance.network == 'hive' and should_push_to_chains:
			broadcast_stream = self.push_stream_graphene(link,length)

		if broadcast_stream != True:
			logging.error('Failed to push stream')
			self.filearr[fileId].status = 'share failed'
			return False
		else:
			self.filearr[fileId].status = 'shared'
			return True

	def skynet_push(self,filePath, portal):
		logging.debug('Uploading ' + str(filePath) + ' with ' + str(portal))

		opts = type('obj', (object,), {
			'portal_url': portal,
			'timeout': 60,
			'timeout_seconds': 60
		})

		try:
			try:
				return self.instance.skynet_api.upload_file(filePath, opts)            
			except TimeoutError:
				logging.error('Uploading timeout with ' + str(portal))
				return False
		except:
			logging.error('Uploading failed with ' + str(portal))
			return False

	def ipfs_push(self,filePath):
		# TODO: Multiple upload endpoints
		if self.instance.upload_endpoint in constants.authenticated_ipfs_upload_endpoints:
			fileToUpload = {'chunk': open(filePath,'rb')}
			postUrl = self.instance.upload_endpoint + '/uploadStream?access_token=' + self.instance.access_token
			upload = requests.post(postUrl,files=fileToUpload)
			if upload.status_code == 200:
				return json.loads(upload.text)['hash']
			else:
				logging.error('IPFS upload failed')
				return False
		else:
			# Assume IPFS API unless stated otherwise
			ipfs_add = self.instance.ipfs_api.add(filePath,trickle=True)
			return ipfs_add['Hash']

	def push_stream_avalon(self, hashes: list, lengths: list) -> bool:
		tx = {
			'type': 19,
			'data': {
				'link': self.instance.link,
				'len': lengths,
				'src': hashes
			},
			'sender': self.instance.username,
			'ts': round(time.time() * 1000)
		}
		stringifiedTxToHash = json.dumps(tx,separators=(',', ':'))
		tx['hash'] = hashlib.sha256(stringifiedTxToHash.encode('UTF-8')).hexdigest()

		pk = secp256k1.PrivateKey(base58.b58decode(self.instance.private_key))
		hexhash = bytes.fromhex(tx['hash'])
		sign = pk.ecdsa_sign(hexhash,raw=True,digest=hashlib.sha256)
		signature = base58.b58encode(pk.ecdsa_serialize_compact(sign)).decode('UTF-8')
		tx['signature'] = signature
		headers = {
			'Accept': 'application/json, text/plain, */*',
			'Content-Type': 'application/json'
		}
		broadcast = requests.post(self.instance.api + '/transact',data=json.dumps(tx,separators=(',', ':')),headers=headers)
		if broadcast.status_code == 200:
			return True
		else:
			try:
				err = broadcast.json()
				logging.error(err['error'])
			except Exception as e:
				logging.error('Broadcast error: ' + e)
			logging.error('Transaction: ' + json.dumps(tx))
			return False

	def push_stream_graphene(self, hashes: list, lengths: list) -> bool:
		json_data = {
			'op': 0,
			'link': self.instance.link,
			'len': lengths,
			'src': hashes
		}
		try:
			self.instance.graphene_client.custom_json('alive-test',json_data,required_posting_auths=[self.instance.username])
			return True
		except Exception as e:
			logging.error('Broadcast error: ' + str(e))
			logging.error('Custom JSON: ' + json.dumps(json_data))
			return False