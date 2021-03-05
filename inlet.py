#!/usr/bin/env python

# inlet.py - A remote access service
# Copyright (C) 2021 Lloyd Dilley
# http://www.dilley.me/
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from datetime import datetime
import os
from signal import signal, SIGINT
import socket
import subprocess
import sys
from threading import Thread, Lock
import time

VERSION = "1.0.0"          # Inlet version
DEFAULT_ADDR = "0.0.0.0"   # default bind address
DEFAULT_PORT = 14137       # default TCP port
DEFAULT_USER = "user"      # default username
DEFAULT_PASS = "secret"    # default password
DEFAULT_CONF = "inlet.cfg" # default configuration file
DEFAULT_LOG = "inlet.log"  # default log file
BUFFER_SIZE = 2048         # network receive buffer
AUTH_ATTEMPTS = 3          # maximum authentication attempts
DEBUG_MODE = True          # debug mode

work_dir = os.getcwd()     # working directory at startup
server = None              # server socket
mutex = Lock()             # mutex for threading
sessions = []              # array of sessions

# Holds session data for a user
class Session:
  def __init__(self, id, username, client, source_address, source_port, thread, when):
    self.id = id
    self.username = username
    self.client = client
    self.source_address = source_address
    self.source_port = source_port
    self.thread = thread
    self.when = when

# Log entry to file
def log(entry):
  try:
    mutex.acquire()
    log_file = open(work_dir + "/" + DEFAULT_LOG, "a")
    timestamp = time.localtime()
    log_file.write("[%s] %s\n" % (time.asctime(timestamp), entry))
    log_file.close()
  except Exception as reason:
    print("Unable to write to %s: %s" %(DEFAULT_LOG, reason))
  finally:
    mutex.release()

# Catch ctrl+c and exit gracefully
def sigint_handler(sig, frame):
  if server != None:
    server.close()
  print("\nShutting down...")
  log("Shutting down...")
  exit(0)

# Become a background service
def daemonize():
  pid = os.fork()
  if pid != 0:
    print("Going into background...")
    log("Going into background...")
    sys.exit(0)

# Disable echo on remote telnet client (during password request for example)
def disable_echo(client, source):
  if DEBUG_MODE:
    log("Requesting echo disablement for client %s:%d" % (source[0], source[1]))
  client.send(b"\xFF\xFB\x01") # IAC WILL ECHO
  echo_confirmation = client.recv(BUFFER_SIZE) # should be \xFF\xFD\x01 (IAC DO ECHO)
  if DEBUG_MODE:
    log("Echo disable confirmation from client %s:%d: %s" % (source[0], source[1], echo_confirmation))

# Enable echo on remote telnet client (after password request for example)
def enable_echo(client, source):
  if DEBUG_MODE:
    log("Requesting echo enablement for client %s:%d" % (source[0], source[1]))
  client.send(b"\xFF\xFC\x01") # IAC WONT ECHO
  echo_confirmation = client.recv(BUFFER_SIZE) # should be \xFF\xFE\x01 (IAC DONT ECHO)
  if DEBUG_MODE:
    log("Echo enable confirmation from client %s:%d: %s" % (source[0], source[1], echo_confirmation))

# Validate provided username and password
def is_valid_creds(username, password, source):
  if username == DEFAULT_USER and password == DEFAULT_PASS:
    log("Authentication succeeded for %s (%s:%d)." % (username, source[0], source[1]))
    return True
  else:
    log("Authentication failed for %s (%s:%d)." % (username, source[0], source[1]))
    return False

# Display command list
def display_help(session):
  try:
    session.client.send(b"\r\nInlet Commands\r\n")
    session.client.send(b"--------------\r\n")
    session.client.send(b"help:     Display help\r\n")
    session.client.send(b"exit:     Disconnect\r\n")
    session.client.send(b"quit:     Disconnect\r\n")
    session.client.send(b"userlist: Display sessions\r\n\r\n")
  except Exception as reason:
    if DEBUG_MODE:
      log("Error occurred during client help request: %s" % reason)

# Display sessions
def display_sessions(session):
  try:
    mutex.acquire()
    session.client.send(b"\r\nUser Sessions\r\n")
    session.client.send(b"-------------\r\n")
    session.client.send(b"Current sessions: %d\r\n" % len(sessions))
    session.client.send(b"ID\tUser\tSource\t\t\tWhen\r\n")
    for index in range(len(sessions)):
      if sessions[index].id == session.id: # own connection
        session.client.send(b"%d*\t%s\t%s:%d\t%s\r\n" % (index, str.encode(sessions[index].username), str.encode(sessions[index].source_address), sessions[index].source_port, str.encode(sessions[index].when)))
      else:
        session.client.send(b"%d\t%s\t%s:%d\t%s\r\n" % (index, str.encode(sessions[index].username), str.encode(sessions[index].source_address), sessions[index].source_port, str.encode(sessions[index].when)))
    session.client.send(b"\r\n")
  except Exception as reason:
    if DEBUG_MODE:
      log("Error occurred during client userlist request: %s" % reason)
  finally:
    mutex.release()

# Remove a terminated session
def reap_session(session):
  mutex.acquire()
  for connection in sessions:
    if connection.id == session.id:
      sessions.remove(connection)
  mutex.release()

# Terminate a session
def kick_session(session, index):
    mutex.acquire()
    sessions[index].client.close()
    del sessions[index]
    mutex.release()

# Handle command input and output
def command_prompt(session):
  while True:
    try:
      session.client.send(b"> ")
      input = session.client.recv(BUFFER_SIZE)
      input = input.rstrip(b"\r\n")
      if len(input) > 0:
        input = input.decode()
      else:
        continue
      if DEBUG_MODE:
        log("%s (%s:%d) sent command: %s" % (session.username, session.source_address, session.source_port, input))
      if input.lower() == "exit" or input.lower() == "quit":
        session.client.send(b"\r\nGoodbye, %s!\r\n\r\n" % str.encode(session.username))
        return
      if input.lower() == "help":
        display_help(session)
        continue
      if input.lower() == "userlist":
        display_sessions(session)
        continue
      #if input.lstrip().lower()[0:9] == "kickuser":
      #  kick_session(session, index)
      #  continue
      if input.strip() == "cd":
        os.chdir("/")
      if input.strip()[0:3] == "cd ":
        os.chdir("".join(input.split())[2:])
      output = subprocess.run(input, capture_output=True, shell=True, text=True)
      output = output.stdout + output.stderr
      session.client.send(b"\r\n%s\r\n" % output.encode())
    except IOError as ioe:
      session.client.send(b"\r\nError: No such file or directory!\r\n\r\n")
    except Exception as reason:
      if DEBUG_MODE:
        log("Error occurred during client command input/output: %s" % reason)

# Handle client connections
def authenticate_client(client, source, session):
  client.send(b"\r\nInlet v%s\r\n\r\n" % str.encode(VERSION))
  attempts = 0
  account = "unknown"
  while True:
    try:
      client.send(b"Login: ")
      username = client.recv(BUFFER_SIZE)
      username = username.strip()
      if len(username) > 0:
        username = username.decode()
      else:
        continue
      log("Client from %s:%d sent username: %s" % (source[0], source[1], username))
      disable_echo(client, source)
      client.send(b"Password: ")
      password = client.recv(BUFFER_SIZE)
      enable_echo(client, source)
      password = password.strip()
      if len(password) > 0:
        password = password.decode()
      if DEBUG_MODE:
        log("Client from %s:%d sent password: %s" % (source[0], source[1], password))
      if is_valid_creds(username, password, source):
        account = username
        session.username = account
        mutex.acquire()
        sessions.append(session)
        mutex.release()
        client.send(b"\r\n\r\nWelcome, %s!\r\n\r\n" % str.encode(account))
        command_prompt(session)
        log("%s (%s:%d) disconnected." % (account, source[0], source[1]))
        client.close()
        reap_session(session)
        break
      else:
        client.send(b"\r\nInvalid credentials!\r\n\r\n")
        attempts += 1
      if attempts >= AUTH_ATTEMPTS:
        client.send(b"You have exceeded the number of allowed authentication attempts! *click*\r\n\r\n")
        log("%s (%s:%d) was forcibly disconnected due to exceeding the allowed number of authentication attempts." % (account, source[0], source[1]))
        client.close()
    except Exception as reason:
      if DEBUG_MODE:
        log("Error occurred during client authentication: %s" % reason)

# Handle server connections
# ToDo: Add SSL/TLS socket support
def start_network():
  try:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ToDo: check for address and port in config file if it exists
    server.bind((DEFAULT_ADDR, DEFAULT_PORT))
  except socket.error as reason:
    log("Unable to bind socket using %s:%d: %s" % (DEFAULT_ADDR, DEFAULT_PORT, reason))
    sys.exit("Unable to bind socket using %s:%d: %s" % (DEFAULT_ADDR, DEFAULT_PORT, reason))
  server.listen()
  log("Server ready to accept connections on %s:%d." % (DEFAULT_ADDR, DEFAULT_PORT))
  while True:
    try:
      client, source = server.accept()
      log("Client connected from %s:%d." % (source[0], source[1]))
      now = datetime.now()
      session = Session(None, "unknown", client, source[0], source[1], None, now.strftime("%m/%d/%Y %H:%M:%S"))
      client_thread = Thread(target=authenticate_client, args=(client, source, session))
      session.id = hash(client)
      session.thread = client_thread
      client_thread.start()
    except Exception as reason:
      if DEBUG_MODE:
        log("Error occurred during initial client communication: %s" % reason)

signal(SIGINT, sigint_handler)
print("Inlet v%s" % VERSION)
log("Inlet v%s" % VERSION)
daemonize()
# ToDo: parse_config()
start_network()
