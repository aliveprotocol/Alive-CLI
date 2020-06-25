import argparse
import config
import logging
import sys
import os
import cv2
import requests
import json
import shutil
from siaskynet import Skynet
import subprocess
from tabulate import tabulate
from threading import Thread
import time
import base58
import secp256k1
import hashlib
import decrypt

def runBash(command):
	os.system(command)

def touchDir(dir, strict = False):
	if (strict == True and os.path.isdir(dir)):
		raise Exception('Folder already exists: ' + dir)
	if not os.path.isdir(dir):
		os.mkdir(dir)

def folderIsEmpty(folder):
	if not os.path.isdir(folder):
		return True
	if os.listdir(folder):
		return False
	else:    
		return True

def rmdir(dir):
	if os.path.isdir(dir):
		shutil.rmtree(dir)

def skynet_push(filePath, portal):
	logging.debug('Uploading ' + str(filePath) + ' with ' + str(portal))

	opts = type('obj', (object,), {
		'portal_url': portal,
		'timeout': 60,
		'timeout_seconds': 60
	})

	try:
		try:
			return Skynet.upload_file(filePath, opts)            
		except TimeoutError:
			logging.error('Uploading timeout with ' + str(portal))
			return False
	except:
		logging.error('Uploading failed with ' + str(portal))
		return False

def ipfs_push(filePath):
	# TODO: Multiple upload endpoints
	if upload_endpoint in config.authenticated_ipfs_upload_endpoints:
		fileToUpload = {'chunk': open(filePath,'rb')}
		postUrl = upload_endpoint + '/uploadStream?access_token=' + access_token
		upload = requests.post(postUrl,files=fileToUpload)
		if upload.status_code == 200:
			return json.loads(upload.text)['hash']
		else:
			logging.error('IPFS upload failed')
			return False
	else:
		return False

def upload(filePath, fileId, length):
	global concurrent_uploads, filearr
	start_time = time.time()
	concurrent_uploads += 1
	filearr[fileId].status = 'uploading'

	# upload file until success
	while True:
		# upload and retry if fails with backup portals
		skylink = False
		if upload_protocol == 'Skynet':
			for upload_portal in config.skynet_upload_portals:
				skylink = skynet_push(filePath, upload_portal)
				if skylink != False:
					break
				else:
					filearr[fileId].status = 'uploading with backup portal'
		elif upload_protocol == 'IPFS':
			skylink = ipfs_push(filePath)

		if (skylink != False and len(skylink) >= 46):
			skylink = skylink.replace("sia://", "")
			filearr[fileId].skylink = skylink
			if filearr[fileId].status != 'share failed':
				filearr[fileId].status = 'share queued'
			filearr[fileId].uploadTime = round(time.time() - start_time)
			concurrent_uploads -= 1
			return True
		else:
			logging.error('Upload failed with all portals for ' + str(filePath))
			filearr[fileId].status = 'queued for re-uploading'
			time.sleep(10)
			filearr[fileId].status = 're-uploading'

def upload_endpoint_auth():
	if upload_protocol == 'IPFS' and upload_endpoint in config.authenticated_ipfs_upload_endpoints:
		loginUrl = upload_endpoint + '/login?dtc=true&user=' + avalon_user
		if avalon_keyid != None:
			loginUrl += '&dtckeyid=' + avalon_keyid
		auth_request = requests.get(loginUrl)
		if auth_request.status_code != 200:
			return False

		# Decrypt with Avalon key
		encrypted_memo = auth_request.json()['encrypted_memo']
		decrypted_memo = decrypt.ecies_decrypt(base58.b58decode(avalon_privkey),decrypt.js_to_py_encrypted(encrypted_memo))

		# Obtain access token
		headers = { 'Content-Type': 'text/plain' }
		access_token_request = requests.post(upload_endpoint + '/logincb',data=decrypted_memo,headers=headers)
		if access_token_request.status_code != 200:
			return False
		else:
			return access_token_request.json()['access_token']
	else:
		return 'noauth'

def get_length(filename):
	cap = cv2.VideoCapture(filename)
	fps = cap.get(cv2.CAP_PROP_FPS)      # OpenCV2 version 2 used "CV_CAP_PROP_FPS"
	frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
	duration = frame_count/fps
	return duration

def check_m3u8(recordFolder):
	for file in os.listdir(recordFolder):
		if file.endswith(".m3u8"):
			return True
	return False

def check_ts(recordFolder):
	for file in os.listdir(recordFolder):
		if file.endswith(".ts"):
			return True
	return False

def isPlaylistFinished(recordFolder):
	playlistFile = os.path.join(recordFolder, "live.m3u8")
	with open(playlistFile, 'r') as f:
		lines = f.read().splitlines()
		last_line = lines[-1]
		if last_line == '#EXT-X-ENDLIST':
			return True
		else:
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
	terminalColumns, terminalRows = shutil.get_terminal_size()
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

def share(fileId, filearr):
	filearr[fileId].status = 'sharing'

	link = filearr[fileId].skylink
	length = filearr[fileId].length
	
	broadcast_stream = push_stream_avalon(avalon_livestream_link,link,length,avalon_user,avalon_privkey)

	if broadcast_stream != True:
		logging.error('Failed to push stream to avalon')
		filearr[fileId].status = 'share failed'
		return False
	else:
		filearr[fileId].status = 'shared'
		return True

def share_thread():
	global filearr
	lastSharedFileId = -1
	# check_share_queue(check_share_queue, filearr)
	while True:
		nextToShare = lastSharedFileId + 1
		if filearr[nextToShare].status == 'share queued' or filearr[nextToShare].status == 'share failed':
			if share(nextToShare, filearr) == True:
				lastSharedFileId += 1
			else:
				time.sleep(10)
		time.sleep(0.2)

def push_stream_avalon(link,hash,len,sender,wif):
	tx = {
		'type': 19,
		'data': {
			'link': link,
			'len': len,
			'hash': {
				'src': hash
			}
		},
		'sender': sender,
		'ts': round(time.time() * 1000)
	}
	stringifiedTxToHash = json.dumps(tx,separators=(',', ':'))
	tx['hash'] = hashlib.sha256(stringifiedTxToHash.encode('UTF-8')).hexdigest()

	pk = secp256k1.PrivateKey(base58.b58decode(wif))
	hexhash = bytes.fromhex(tx['hash'])
	sign = pk.ecdsa_sign(hexhash,raw=True,digest=hashlib.sha256)
	signature = base58.b58encode(pk.ecdsa_serialize_compact(sign)).decode('UTF-8')
	tx['signature'] = signature
	headers = {
		'Accept': 'application/json, text/plain, */*',
		'Content-Type': 'application/json'
	}
	broadcast = requests.post(avalon_api + '/transact',data=json.dumps(tx,separators=(',', ':')),headers=headers)
	if broadcast.status_code == 200:
		return True
	else:
		try:
			err = broadcast.json()
			logging.error(err['error'])
		except Exception as e:
			logging.error('Broadcast error: ' + e)
		return False

class VideoFile:
	def __init__(self, fileId):
		self.fileId = fileId
		self.status = 'waiting for file'
		self.uploadTime = -1
		self.length = -1
		self.skylink = 'skylink'
	def __str__(self):
		return str(self.__dict__)

nextStreamFilename = 0
filearr = [
	# file, status, upload time, length, skylink
	VideoFile(nextStreamFilename)
]

def worker():
	global concurrent_uploads, projectPath, recordFolder, filearr, nextStreamFilename

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
	touchDir(recordFolder)

	cntr = 0
	while True:
		if not check_m3u8(recordFolder):
			if args.record_folder:
				record_folder_name = args.record_folder
			else:
				record_folder_name = 'record_here'
			if not (check_ts(recordFolder)):
				print('Waiting for recording, no .m3u8 or .ts file found in ' + record_folder_name + ' folder (%ds)' %(cntr))
			else:
				print('Starting uploading... Waiting for first chunk and for .m3u8 file in ' + record_folder_name + ' folder (%ds)' %(cntr))
			cntr += 1
			time.sleep(1)
		else:
			break


	Thread(target=share_thread).start()
	while True:
		nextFile = os.path.join(recordFolder, "live" + str(nextStreamFilename) + ".ts")
		nextAfterFile = os.path.join(recordFolder, "live" + str(nextStreamFilename + 1) + ".ts")
		updateDisplay(filearr, symbols)
		if concurrent_uploads < 10 and ( os.path.isfile(nextAfterFile) or ( isPlaylistFinished(recordFolder) and os.path.isfile(nextFile) ) ):
			filearr.append(VideoFile(nextStreamFilename + 1))
			filearr[nextStreamFilename].status = 'upload queued'
			nextLen = get_length(nextFile)
			filearr[nextStreamFilename].length = nextLen
			Thread(target=upload, args=(nextFile, nextStreamFilename, nextLen)).start()
			nextStreamFilename += 1
		else:
			time.sleep(1)
	

concurrent_uploads = 0
projectPath = os.path.dirname(os.path.abspath(__file__))

logFile = os.path.join(projectPath, "error.log")
logging.basicConfig(filename=logFile,
	filemode='a',
	format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
	datefmt='%H:%M:%S',
	level=logging.DEBUG)
logging.info('LOGGING STARTED')

parser = argparse.ArgumentParser('DTube HLS Livestream')
parser.add_argument('-r','--record_folder', help='Record folder, where m3u8 and ts files will be located (default: record_here)')
parser.add_argument('-p','--protocol', help='P2P protocol for HLS streams (valid values: IPFS (default) and Skynet)')
parser.add_argument('-a','--api', help='Avalon API node (default: ' + config.avalon_api + ')')
parser.add_argument('-e','--endpoint', help='IPFS/Skynet upload endpoint')

required_args = parser.add_argument_group('Required arguments')
required_args.add_argument('-u','--user', help='Avalon username', required=True)
required_args.add_argument('-k','--key', help='Avalon key (custom keys must have PUSH_STREAM and END_STREAM permissions)', required=True)
required_args.add_argument('-l','--link', help='Livestream permlink, generated at post creation', required=True)

args = parser.parse_args()


# get recordFolder
if (args.record_folder):
	if (os.path.isabs(args.record_folder)):
		recordFolder = args.record_folder
	else:
		recordFolder = os.path.join(projectPath, args.record_folder)
else:
	recordFolder = os.path.join(projectPath, "record_here")

if not folderIsEmpty(recordFolder):
	print('Record folder is not empty: ' + recordFolder)
	input('Are you sure, you want to continue? Press Enter to continue...')

if args.protocol:
	valid_protocols = ['IPFS','Skynet']
	if args.protocol in valid_protocols:
		upload_protocol = args.protocol
	else:
		print('Invalid P2P protocol')
		sys.exit(1)
else:
	upload_protocol = 'IPFS'

if args.api:
	avalon_api = args.api
else:
	avalon_api = config.avalon_api

# Avalon username
avalon_account = requests.get(avalon_api + '/account/' + args.user)
if avalon_account.status_code != 200:
	print('Avalon username does not exist')
	sys.exit(1)
avalon_user = args.user

# Avalon key
avalon_keyid = None
avalon_privkey = args.key
avalon_pubkey = base58.b58encode(secp256k1.PrivateKey(base58.b58decode(args.key)).pubkey.serialize()).decode('UTF-8')
if avalon_account.json()['pub'] != avalon_pubkey:
	valid_key = False
	for i in range(0,len(avalon_account.json()['keys'])):
		# TODO: Update with the correct op # on livestreaming HF
		if avalon_account.json()['keys'][i]['pub'] == avalon_pubkey and all(x in avalon_account.json()['keys'][i]['types'] for x in [19, 20]):
			avalon_keyid = avalon_account.json()['keys'][i]['id']
			valid_key = True
			break
	if valid_key == False:
		print('Invalid Avalon key')
		sys.exit(1)
	else:
		print('Logged in with custom key')
else:
	print('Logged in with master key')

# Avalon livestream permlink
if len(args.link) < 1 or len(args.link) > 50:
	print('Invalid livestream permlink')
	sys.exit(1)
else:
	avalon_live_post = requests.get(avalon_api + '/content/' + avalon_user + '/' + args.link)
	if avalon_live_post.status_code == 404:
		print('Livestream not found')
		sys.exit(1)
	elif avalon_live_post.status_code != 200:
		print('Error querying livestream with status code ' + avalon_live_post.status_code)
		sys.exit(1)
	else:
		print('Found livestream ' + args.link)
avalon_livestream_link = args.link

# Authenticate with upload endpoint
if args.endpoint:
	upload_endpoint = args.endpoint
else:
	upload_endpoint = config.ipfs_upload_endpoint

access_token = upload_endpoint_auth()

if access_token == False:
	print('Upload endpoint authentication failed')
	sys.exit(1)

worker()