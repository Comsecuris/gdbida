# (C) Copyright 2016 Comsecuris UG
# https://sourceware.org/gdb/onlinedocs/gdb/Events-In-Python.html#Events-In-Python

import os
import socket
import struct
from __future__ import print_function

IDA_BRIGE_IP = '10.0.10.10'
IDA_BRIDGE_PORT = 2305

INIT_BP_WORKAROUND = False
DEBUG = 1

TEXT_START = 'Start of text: '
TEXT_END   = 'End of text: '

socket.setdefaulttimeout(0.1)

class IdaBridge(gdb.Command):
	def __init__(self):
		super (IdaBridge, self).__init__("idabridge", gdb.COMMAND_USER)
		self.ida_ip = IDA_BRIGE_IP
		self.ida_port = IDA_BRIDGE_PORT
		self.init_bps = []
		self.img_base = None
		self.img_reloc = False

	def hdl_stop_event(self, event):
		# in case we want to ignore all breakpoints that were set before the idabridge was launched.
		if isinstance(event, gdb.BreakpointEvent) and event.breakpoint in self.init_bps:
			return

		if self.img_base == None and self.img_reloc == True:
			self.get_relocation()
		pc = self.get_pc()
		# TODO: make sure to adjust pc only if within .text
		if self.img_reloc:
			print("adjusted pc from 0x%x to 0x%x (base: 0x%x)\n" %(pc, pc-self.img_reloc, self.img_base))
			pc = pc - self.img_base

		self.tell_ida(pc)

	def get_relocation(self):
		val = gdb.execute('info proc stat', to_string=True)
		s_text = val.find(TEXT_START)
		e_text = val.find(TEXT_END)
		if s_text == -1:
			print("could not determine image relocation information\n")
			self.img_reloc = False
			return

		reloc = val[s_text + len(TEXT_START) : e_text - 1]
		self.img_base = int(reloc, 16)
		print("using 0x%x as text relocation\n" %(self.img_base))

	def get_pc(self):
		val = gdb.selected_frame().pc()
		return val
	
	# TODO: make this eventually keep the connection
	def tell_ida(self, pc):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.connect((self.ida_ip, self.ida_port))
		except Exception as e:
			print("couldn't connect to IDA bridge", str(e))
			return

		s.send(struct.pack("<Q", pc))
		s.close()

	# TODO: we do minimal to no error checking here, fix that
	def invoke(self, arg, from_tty):
		argv = arg.split(' ')
		if len(argv) < 1:
			print("idabridge <ip:port> [reloc_text]")
			return

		target = argv[0].split(':')

		if not '.' in target[0] or len(target) < 2:
			print("please specify ip:port combination")
			return

		self.ida_ip = target[0]
		self.ida_port = int(target[1])
		print("idabridge: using ip: %s port: %d\n" %(self.ida_ip, self.ida_port))

		if len(argv) >= 2 and argv[1] == 'reloc_text':
			self.img_reloc = True

		if INIT_BP_WORKAROUND:
			self.init_bps = gdb.breakpoints()

		gdb.events.stop.connect(self.hdl_stop_event)
	
IdaBridge()
