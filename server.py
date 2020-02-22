# Python Version: Python 3.6.8
# Author        : Puneeth Kambhampati
# Description   : The multi-threaded server model for chat apps where multiple clients can connect to a single server
#                 and interact with each other

import socket
import sys
import threading
import datetime
from datetime import timedelta


class Server:

    def __init__(self, ip_address, port_no, block_duration, timeout_duration):
        self._ip_address = ip_address
        self._port = port_no
        self._block_duration = block_duration
        self._timeout_duration = timeout_duration
        # server socket
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # socket management for clients that connect to the server
        # for all the dictionaries, {Key: client_socket, Value: User}
        self._active_users = {}
        self._inactive_users = {}
        self._offline_users = {}
        self._blocked_users = {}