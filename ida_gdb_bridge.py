import idautils
import signal
import idc
import idaapi

import socket
import threading
import time
import Queue

TRACE = False
DEBUG = False
COLOR_CUR = 0x68ff90

# make sure our operations time out so we can actually quit IDA
DEFAULT_TIMEOUT = 3
socket.setdefaulttimeout(DEFAULT_TIMEOUT)

def dprint(s):
	if DEBUG == True:
		print('IDAbridge: ' + s)

# use idaapi.execute_ui_requests to ensure that SetColor and Jump
# are executed in the main thread to ensure thread safety. if we
# ignore that, we will run into btree and other errors.
# thanks for hex-rays for helping with this!
class color_req_t(object):
	def __init__(self, ea, color):
		self.ea = ea
		self.color = color

	def __call__(self):
		SetColor(self.ea, CIC_ITEM, self.color)
		
		return False # Don't reschedule

def safe_setcolor(ea, color):
	idaapi.execute_ui_requests((color_req_t(ea, color),))

class jump_req_t(object):
	def __init__(self, ea):
		self.ea = ea

	def __call__(self):
		Jump(self.ea)
		
		return False # Don't reschedule

def safe_jump(ea):
	idaapi.execute_ui_requests((jump_req_t(ea),))

# TODO: in case of any exceptions it may be nice to have
# a list of all locations where color was changed so that on
# exiting the plugin, we could restore these.
class ColorThread(threading.Thread):
	def __init__(self, ea = -1):
		#print "ColorThread()"
		threading.Thread.__init__(self)
		self.c_queue = Queue.Queue()
		self.ea = ea
		self.running = False
	
	def join(self, timeout = None):
		self.running = False
		threading.Thread.join(self, timeout)

	def run(self):
		self.running = True

		while self.running == True:
			event_ea = self.ea
			try:
				ea = self.c_queue.get(block=True, timeout=DEFAULT_TIMEOUT)
			except:
				continue

			try:
				event_ea = int(struct.unpack("<Q", ea)[0])
			except:
				continue

			dprint("current position: %x" %(event_ea))
			try:
				safe_jump(event_ea)
			except:
				continue

			# TODO: do some sanity checking on received EAs
			# e.g. make sure that the address is within the image space
			if TRACE == False:
				safe_setcolor(self.ea, 0xffffff)

			safe_setcolor(event_ea, COLOR_CUR)
			self.ea = event_ea


class BridgeThread(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.server = None
		self.running = False
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.c_thread = ColorThread()

	def join(self, timeout = None):
		self.running = False
		self.s.close()
		threading.Thread.join(self, timeout)

	def bind(self):
		try:
			self.s.bind(self.server)
		except:
			dprint("bind() failed")
			self.running = False
			return False

		self.running = True
		return True

	def run(self):
		self.s.listen(1)
		dprint("accepting connections")
		if not self.c_thread.running:
			self.c_thread.start()

		# TODO: make it possible to keep a connection or switch to UDP
		while self.running == True:
			try:
				conn, addr = self.s.accept()
			except socket.timeout:
				continue

			try:
				read_ea = conn.recv(8)
			except Exception as e:
				dprint("closing client/%s connection: %s" % (addr, str(e)))
				conn.close()
				continue

			conn.close()
			self.c_thread.c_queue.put(read_ea)

class ida_gdb_debug_bridge_plugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_OK
	comment = ""
	help = ""
	wanted_name = "IDA debug bridge"
	wanted_hotkey = "Alt-f"

	def init(self):
		self.bridge_thread = BridgeThread()
		return idaapi.PLUGIN_OK
	
	def run(self, arg):
		if self.bridge_thread.running == True:
			dprint("server already running: %s:%s\n" % (self.bridge_thread.server[0], self.bridge_thread.server[1]))
			return

		ask_port = idc.AskLong(2305, "Enter port number for incoming events")
		if ask_port < 1 or ask_port <= 1024:
			dprint('invalid port number')
			return

		ask_addr = idc.AskStr('0.0.0.0', "Enter address to bind to")

		self.bridge_thread.server = (ask_addr, ask_port)
		if self.bridge_thread.running == False:
			self.bridge_thread.bind()

		if self.bridge_thread.running == False:
			dprint("there was an issue starting the server")
		else:
			self.bridge_thread.start()

		return

	def term(self):
		if self.bridge_thread.c_thread.ea != -1:
			safe_setcolor(self.bridge_thread.c_thread.ea, 0xffffff)
		self.bridge_thread.running = False
		self.bridge_thread.c_thread.running = False
		self.bridge_thread.s.close()
		pass


def PLUGIN_ENTRY():
	return ida_gdb_debug_bridge_plugin()

