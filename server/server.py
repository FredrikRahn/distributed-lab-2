# coding=utf-8
#------------------------------------------------------------------------------------------------------
# TDA596 Labs - Server Skeleton
# server/server.py
# Input: Node_ID total_number_of_ID
# Student Group: 99
# Student names: Fredrik Rahn & Alexander Branzell
#------------------------------------------------------------------------------------------------------
# We import various libraries
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler # Socket specifically designed to handle HTTP requests
import sys # Retrieve arguments
import os 	#Folder stuff #TODO LÖS
from urlparse import parse_qs # Parse POST data
from httplib import HTTPConnection # Create a HTTP connection, as a client (for POST requests to the other vessels)
from urllib import urlencode # Encode POST content into the HTTP header
from codecs import open # Open a file
from threading import Timer, Thread # Thread Management
from random import randint
import time
import ast
#------------------------------------------------------------------------------------------------------
#Get correct folder path
file_folder = os.path.dirname(os.path.realpath(__file__)) + '/'
# Global variables for HTML templates
board_frontpage_header_template = open(file_folder + 'board_frontpage_header_template.html', 'r').read()
leader_template = open(file_folder + 'leader.html', 'r').read()
boardcontents_template = open(file_folder + 'boardcontents_template.html', 'r').read()
entry_template = open(file_folder + 'entry_template.html', 'r').read()
board_frontpage_footer_template = open(file_folder + 'board_frontpage_footer_template.html', 'r').read()
#------------------------------------------------------------------------------------------------------
# Static variables definitions
PORT_NUMBER = 80
#------------------------------------------------------------------------------------------------------
class BlackboardServer(HTTPServer):
#------------------------------------------------------------------------------------------------------
	def __init__(self, server_address, handler, node_id, vessel_list):
		'''
		Init of Blackboard HTTP server
		@args:	server_address:String, Address to Server
				handler:BaseHTTPRequestHandler, Server handler
				node_id:Number, The ID of the node
				vessel_list:[String], list of vessels
		@return:
		'''
		# We call the super init
		HTTPServer.__init__(self,server_address, handler)
		# we create the dictionary of values
		self.store = {}
		# We keep a variable of the next id to insert
		self.current_key = -1
		# our own ID (IP is 10.1.0.ID)
		self.vessel_id = vessel_id
		# The list of other vessels
		self.vessels = vessel_list
		#init random ID
		self.random_ID = randint(0,1000);
		#init leader List
		self.leader_list = {'creator': vessel_id}
		#init leader
		self.leader = None
		#init leader id
		self.leader_ID = None
		#init leader election
		self.init_leader_election(self.leader_list)
#------------------------------------------------------------------------------------------------------
	# We add a value received to the store
	def add_value_to_store(self, value):
		'''
		Adds a new value to store
		@args: Value:String, Value to be added to store
		@return: [Key:String, Value:String]
		'''
		# We add the value to the store
		#TODO: uuid4
		self.current_key += 1
		key = self.current_key
		if key not in self.store:
			self.store[key]=value
			return [key, value]
		else:
			raise KeyError('Can not add key (Already Exists)')
#------------------------------------------------------------------------------------------------------
	# We add a value received to the store
	def add_value_to_store_from_leader(self, key, value):
		'''
		Adds a new value to store
		@args: Value:String, Value to be added to store
		@return: [Key:String, Value:String]
		'''
		# We add the value to the store
		#TODO: uuid4
		key = int(key)
		if key not in self.store:
			self.store[key]=value
			return [key, value]
		else:
			raise KeyError('Can not add key (Already Exists)')
#------------------------------------------------------------------------------------------------------
	# We modify a value received in the store
	def modify_value_in_store(self, key, value):
		'''
		Modifies value in store
		@args:	Key:Number, 	Key to be modified
				Value:String, 	Value to be added to key
		@return: [Key:Number, Value:String]
		'''
		key = int(key)
		if key in self.store:
			self.store[key] = value
			return [key, value]
		else:
			raise KeyError('Key does not exist in store')
#------------------------------------------------------------------------------------------------------
	# We delete a value received from the store
	def delete_value_in_store(self,key):
		'''
		Deletes value in store
		@args:	Key:Number, Key to be deleted
		@return: [Key:String]
		'''
		key = int(key)
		if key in self.store:
			del self.store[key]
		return [key, None]
#------------------------------------------------------------------------------------------------------
# Contact a specific vessel with a set of variables to transmit to it
	def contact_vessel(self, vessel_ip, path, action, key, value):
		'''
		Handles contact with specific vessel
		@args:	Vessel_ip:String, 	IP to the vessel
				Path:String, 		The path where the request will be sent
				Action:Any, 		Action to be performed
				Key:Number, 		Key for store
				Value:String, 		Value for store
		@return:Entire page:html
		'''
		# the Boolean variable we will return
		success = False
		# The variables must be encoded in the URL format, through urllib.urlencode
		post_content = urlencode({'action': action, 'key': key, 'value': value})
		# the HTTP header must contain the type of data we are transmitting, here URL encoded
		headers = {"Content-type": "application/x-www-form-urlencoded"}
		# We should try to catch errors when contacting the vessel
		try:
			# We contact vessel:PORT_NUMBER since we all use the same port
			# We can set a timeout, after which the connection fails if nothing happened
			connection = HTTPConnection("%s:%d" % (vessel_ip, PORT_NUMBER), timeout = 30)
			# We only use POST to send data (PUT and DELETE not supported)
			action_type = "POST"
			# We send the HTTP request
			connection.request(action_type, path, post_content, headers)
			# We retrieve the response
			response = connection.getresponse()
			# We want to check the status, the body should be empty
			status = response.status
			# If we receive a HTTP 200 - OK
			if status == 200:
				success = True
		# We catch every possible exceptions
		except Exception as e:
			print "Error while contacting %s" % vessel_ip
			# printing the error given by Python
			print(e)

		# we return if we succeeded or not
		return success
#------------------------------------------------------------------------------------------------------
	# We send a received value to all the other vessels of the system
	def propagate_value_to_vessels(self, path, action, key, value):
		'''
		Handles propagation of requests to vessels
		@args:	Path:String,	The path where the request will be sent
				Action:String, 	The action that should be performed by the other vessels
				Key:Number, 	Key that should be used in action
				Value:String, 	Value corresponding to key
		@return:
		'''
		for vessel in self.vessels:
			# We should not send it to our own IP, or we would create an infinite loop of updates
			if vessel != ("10.1.0.%s" % self.vessel_id):
				# A good practice would be to try again if the request failed
				# Here, we do it only once
				self.contact_vessel(vessel, path, action, key, value)
#------------------------------------------------------------------------------------------------------
	def leader_election(self, leader_list):
		'''
        Either creates a leader election and sends it's leader_list to neighbour,
        or updates a recieved leader election message and sends the leader_list to neighbour
		@args: leader_list:Dict, Dict with the vessels and their random ID.
		'''
		#Convert leader_list to dict (from string)
		if isinstance(leader_list, basestring):
			leader_list = ast.literal_eval(leader_list)
		#Check whether node exists in list to check if we're done propagating
		if self.vessel_id in leader_list and leader_list['creator'] == self.vessel_id and len(leader_list) == (len(self.vessels) + 1):
			print("leader list ", leader_list)
			self.leader_list = leader_list
			self.set_leader()
			print(self.leader_list)
			print("leader is: ", self.leader)
		else:
			#print("recieved leader election message")
			#Populate local leader_list with the nodes random_ID
			leader_list[self.vessel_id] = self.random_ID
			#Find next index in vessels
			nextid = (self.vessel_id + 1) % (len(self.vessels) + 1)
			#Check whether nextid point to 0 (non-existant), set 1 if so
			if nextid == 0:
				nextid = 1;
			next_index = self.vessels.index('10.1.0.%d' % nextid)
			next = self.vessels[next_index]
			#Send leader_list to next
			#print("Vessel id = ", self.vessel_id)
			#print('Updated recieved leader_list = ', leader_list)
			path = '/election'
			self.contact_vessel(vessel_ip=next, path=path, action='election', key=None, value=leader_list)
#------------------------------------------------------------------------------------------------------
	def set_leader(self):
		'''
		Sort leader_list after random_ID in reverse (Highest first)
		Then take vessel_id in first tuple and set leader
		'''
		print(self.leader_list)
		self.leader = sorted(self.leader_list.items(), key=lambda tuple: tuple[1], reverse = True)[0][0]
		self.leader_ID = sorted(self.leader_list.items(), key=lambda tuple: tuple[1], reverse = True)[0][1]
#------------------------------------------------------------------------------------------------------
	def display_leader(self):
		'''
		Function used to insert the leader and its random ID into leader.html
		'''
		string = str(self.leader) + ' with random ID: ' + str(self.leader_ID)
		leader = leader_template % string
		return leader
#------------------------------------------------------------------------------------------------------
	def init_leader_election(self, leader_list):
		'''
		Initializes leader election, starts a thread that sleeps
        for 2 seconds and then starts leader election.a
		@args: leader_list:Dict, Dict with the vessels and their random ID.
		'''
		leader_election_thread = Timer(2, self.leader_election, [leader_list])
		print('Created thread for leader election')
		# We kill the process if we kill the server
		leader_election_thread.daemon = True
		# We start the thread
		leader_election_thread.start()
#------------------------------------------------------------------------------------------------------
# This class implements the logic when a server receives a GET or POST
# It can access to the server data through self.server.*
# i.e. the store is accessible through self.server.store
# Attributes of the server are SHARED accross all request hqndling/ threads!
class BlackboardRequestHandler(BaseHTTPRequestHandler):
#------------------------------------------------------------------------------------------------------
	# We fill the HTTP headers
	def set_HTTP_headers(self, status_code = 200):
		'''
		Sets HTTP headers and status code of the response
		@args: Status_code, status code to put in header
		'''
		 # We set the response status code (200 if OK, something else otherwise)
		self.send_response(status_code)
		# We set the content type to HTML
		self.send_header("Content-type","text/html")
		# No more important headers, we can close them
		self.end_headers()
#------------------------------------------------------------------------------------------------------
	# a POST request must be parsed through urlparse.parse_QS, since the content is URL encoded
	def parse_POST_request(self):
		'''
		Parses POST requests
		@args:
		@return: post_data:Dict returns dictionary of URL-encoded data
		'''
		post_data = ""
		# We need to parse the response, so we must know the length of the content
		length = int(self.headers['Content-Length'])
		# we can now parse the content using parse_qs
		post_data = parse_qs(self.rfile.read(length), keep_blank_values=1)
		# we return the data
		return post_data
#------------------------------------------------------------------------------------------------------
# Request handling - GET
#------------------------------------------------------------------------------------------------------
	def do_GET(self):
		'''
		Handles incoming GET requests and routes them accordingly
		'''
		print("Receiving a GET on path %s" % self.path)
		path = self.path[1::].split('/')
		if path[0] == 'board':
			self.do_GET_board()
		elif path[0] == 'entry' and len(path) > 1:
			self.do_GET_entry(path[1])
		else:
			self.do_GET_Index()		#Unknown path, route user to index
#------------------------------------------------------------------------------------------------------
	def do_GET_Index(self):
		'''
		Fetches the Index page and all contents to be displayed
		@return: Entire page:html
		'''
		# We set the response status code to 200 (OK)
		self.set_HTTP_headers(200)

		leader = self.server.display_leader()
		fetch_index_header = board_frontpage_header_template
		fetch_index_contents = self.board_helper()
		fetch_index_footer = board_frontpage_footer_template

		html_response = leader + fetch_index_header + fetch_index_contents + fetch_index_footer

		self.wfile.write(html_response)
#------------------------------------------------------------------------------------------------------
	def board_helper(self):
		'''
		Helper func for fetching board contents
		@return: List of boardcontents
		'''
		fetch_index_entries = ""
		for entryId, entryValue in self.server.store.items():
			fetch_index_entries += entry_template % ("entries/" + str(entryId), int(entryId), str(entryValue))
		boardcontents = boardcontents_template % ("Title", fetch_index_entries)
		return boardcontents
#------------------------------------------------------------------------------------------------------
	def do_GET_board(self):
		'''
		Fetches the board and its contents
		'''
		self.set_HTTP_headers(200)
		html_response = self.board_helper()
		self.wfile.write(html_response)
#------------------------------------------------------------------------------------------------------
	def do_GET_entry(self, entryID):
		'''
		Retrieve an entry from store and inserts it into the entry_template
		@args: entryID:String, ID of entry to be retrieved
		@return: Entry:html
		'''
		#Find the specific value for the entry, if entry does not exist set value to None
		entryValue = self.server.store[entryId] if entryId in self.server.store else None
		#Return found entry if it exists, or return empty string if no such entry was found
		return entry_template %("entries/" + entryId, entryId, entryValue) if entryValue != None else ""
#------------------------------------------------------------------------------------------------------
# Request handling - POST
#------------------------------------------------------------------------------------------------------
	def do_POST(self):
		'''
		Handles incoming POST requests and routes them accordingly
		'''
		print("Receiving a POST on %s" % self.path)
		path = self.path[1::].split('/')
		if path[0] == 'board' and len(path) < 2:
			self.do_POST_board()
		elif path[0] == 'entries' and len(path) > 1:
			self.do_POST_entries(path[1])
		elif path[0] == 'propagate':
			self.do_POST_propagate()
		elif path[0] == 'election':
			self.do_POST_election()
		elif path[0] == 'leader':
			self.do_POST_leader()
#------------------------------------------------------------------------------------------------------
	def do_POST_board(self):
		'''
		Add entries to board
		'''
		post_data = self.parse_POST_request()
		if 'entry' in post_data:
			value = post_data['entry'][0]
			self.propagate_action_to_leader(action='add', value=value)
			self.send_response(200)
		else:
			self.send_error(400, 'Error adding entry to board')
#------------------------------------------------------------------------------------------------------
	def do_POST_entries(self, entryID):
		'''
		Handles deleting and modifying entries to the board
		@args: entryID:String, ID of entry to be modified/deleted
		'''
		post_data = self.parse_POST_request()
		if 'delete' in post_data:
			delete = post_data['delete'][0]
			if delete == '1':
				self.propagate_action_to_leader(action='delete', key=int(entryID))
				self.send_response(200)
			else:
				modified_value = post_data['entry'][0]
				self.propagate_action_to_leader(action='modify', key=int(entryID), value=modified_value)
				self.send_response(200)
		else:
			self.send_error(400, 'Delete flag missing from request')
#------------------------------------------------------------------------------------------------------
	def do_POST_propagate(self):
		'''
		Handles propagation of actions by
		routing them to the correct functions
		'''
		post_data = self.parse_POST_request()
		if 'action' in post_data:
			action = post_data['action'][0]
			value = post_data['value'][0]
			key = post_data['key'][0]
			if action == 'add':
				self.do_POST_add_entry_from_leader(key, value)
			elif action == 'modify':
				self.do_POST_modify_entry(key, value)
			elif action == 'delete':
				self.do_POST_delete_entry(key)
			else:
				self.send_error(400, 'Invalid action')
#------------------------------------------------------------------------------------------------------
	def do_POST_leader(self):
		'''
	    Parses post data, completes the action locally
        and then propagates the action to other vessels.
		'''
		#We only arrive here if we are the leader
		#Do action
		post_data = self.parse_POST_request()
		if 'action' in post_data:
			action = post_data['action'][0]
			key = post_data['key'][0]
			value = post_data['value'][0]
			print('Doing leader_action then propagating (action,key,value) ', action,key,value)
			entry = self.do_leader_action(action=action, key=key, value=value)
			#Then propagate to all other nodes
			self.propagate_action(action=action, key=entry[0], value=entry[1])
			self.send_response(200)
		else:
			self.send_error(400, 'Invalid action for leader')
#------------------------------------------------------------------------------------------------------
	def do_POST_add_entry(self, value):
		'''
		Adds a new entry to store
		@args: value:Value, Value to be added in store
		@return: entry:List, [key, value]
		'''
		entry = self.server.add_value_to_store(value=value)
		if entry:
			self.send_response(200)
			return entry
		else:
			self.send_error(400, "Value was not added.")
#------------------------------------------------------------------------------------------------------
	def do_POST_add_entry_from_leader(self, key, value):
		'''
		Adds a new entry to store
		@args: value:Value, Value to be added in store
		@return: entry:List, [key, value]
		'''
		entry = self.server.add_value_to_store_from_leader(key=key, value=value)
		if entry:
			self.send_response(200)
			return entry
		else:
			self.send_error(400, "Value was not added.")
#------------------------------------------------------------------------------------------------------
	def do_POST_modify_entry(self, entryID, value):
		'''
		Modifies a specific entry in store
		@args: entryID:String, ID of entry to be modified
		@args: value:String, new value to be assigned to entryID
		@return: entry:List, [key, value]
		'''
		entry = self.server.modify_value_in_store(int(entryID), value)
		if entry:
			self.send_response(200)
			return entry
		else:
			 self.send_error(400, 'Entry not modified')
#------------------------------------------------------------------------------------------------------
	def do_POST_delete_entry(self, entryID):
		'''
		Deletes an entry in store
		@args: entryID:String
		@return: entry:List, [key]
		'''
		entry = self.server.delete_value_in_store(int(entryID))
		if entry and entryID != None:
			self.send_response(200)
			return entry
		else:
			 self.send_error(400, 'Entry not deleted')
#------------------------------------------------------------------------------------------------------
	def do_POST_election(self):
		'''
		Parses the post data, then spawns a thread for leader election
		'''
		post_data = self.parse_POST_request()
		action = post_data['action'][0]
		if action == 'election':
			value = post_data['value'][0]
			thread = Thread(target=self.server.leader_election, args=(value,))
			print('Created leader_election thread from POST req')
			# We kill the process if we kill the server
			thread.daemon = True
			# We start the thread
			thread.start()
			self.send_response(200)
		else:
			self.send_error(400, 'Invalid Election Action')
#------------------------------------------------------------------------------------------------------
	def propagate_action(self, action, key, value):
		'''
		Spawns a thread and propagates an action to other vessels
		@args: action:String
		@args: key:String
		@args: value:String
		'''
		propagate_path = '/propagate'
		print('path, action, key, value', propagate_path, action, key, value)
		thread = Thread(target=self.server.propagate_value_to_vessels, args=(propagate_path, action, key, value))
		# We kill the process if we kill the serverx
		thread.daemon = True
		# We start the thread
		thread.start()
#------------------------------------------------------------------------------------------------------
	def propagate_action_to_leader(self, action, key='', value=''):
		'''
	    Spawns a thread that propagates an action to the leader vessel
		@args: action:String
		@args: key:String
		@args: value:String
		'''
		leader_ip = '10.1.0.%d' % self.server.leader

		propagate_path = '/leader'
		#propagate_path = self.path
		if self.server.leader != self.server.vessel_id:
			#Contact leader only if this node is not leader
			thread = Thread(target=self.server.contact_vessel, args=(leader_ip, propagate_path, action, key, value))
			# We kill the process if we kill the server
			thread.daemon = True
			# We start the thread
			thread.start()
		else:
			#This node is leader
			#Do action locally
			entry = self.do_leader_action(action=action, key=key, value=value)
			#Propagate_action (to all other nodes)
			self.propagate_action(action=action, key=entry[0], value=entry[1])
#------------------------------------------------------------------------------------------------------
	def do_leader_action(self, action, key, value):
		'''
		Specific function for leader to do action locally.
		@args: action:String
		@args: key:String
		@args: value:String
		'''
		if action == 'add':
			entry = self.do_POST_add_entry(value)
			return entry
		elif action == 'modify':
			entry = self.do_POST_modify_entry(key, value)
			return entry
		elif action == 'delete':
			entry = self.do_POST_delete_entry(key)
			return entry
		else:
			self.send_error(400, 'Invalid action')
#------------------------------------------------------------------------------------------------------
# Execute the code
if __name__ == '__main__':

	## read the templates from the corresponding html files
	# .....

	vessel_list = []
	vessel_id = 0
	# Checking the arguments
	if len(sys.argv) != 3: # 2 args, the script and the vessel name
		print("Arguments: vessel_ID number_of_vessels")
	else:
		# We need to know the vessel IP
		vessel_id = int(sys.argv[1])
		# We need to write the other vessels IP, based on the knowledge of their number
		for i in range(1, int(sys.argv[2])+1):
			vessel_list.append("10.1.0.%d" % i) # We can add ourselves, we have a test in the propagation

	# We launch a server
	server = BlackboardServer(('', PORT_NUMBER), BlackboardRequestHandler, vessel_id, vessel_list)
	print("Starting the server on port %d" % PORT_NUMBER)

	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.server_close()
		print("Stopping Server")
#------------------------------------------------------------------------------------------------------
