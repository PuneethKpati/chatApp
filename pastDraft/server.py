# Python 3
# Usage: 
# Puneeth Kambhampati, z5164647
import sys
import socket
import datetime
from datetime import timedelta
import threading


class server():

    def __init__(self, ip_address, port_no, block_duration, timeout_duration):
        self.ip = ip_address
        self.port = port_no
        self.block_duration = block_duration
        self.timeout_duration = timeout_duration

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Store all user sockets that have connected to the server
        self.user_sockets = []
        # Store all active users in users
        # Key: Socket, Value: [date_time, 'username']
        self.active_users = {}
        self.inactive_users = {}
        self.offline_users = {}
        self.blocked_users = {}
        self.user_block_list = {}

        self.inbox = {}
        # Get all the User names and Passwords from credentials.txt
        self.credentials = self.extract_credentials()

    def run(self):
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen()

        start_commands = False
        print('listening for connections on {} at port {}'.format(self.ip, self.port))
        # Wait for all connections
        while True:
            # Connect to the client and prompt Client to enter details
            client_socket, client_address = self.server_socket.accept()

            # Add client socket to list of all sockets to have connected to server
            self.user_sockets.append(client_socket)

            client_thread = threading.Thread(name="clientHandler", target=self.client_interact,
                                             args=[client_socket, client_address])
            client_thread.daemon = True
            client_thread.start()

    def client_interact(self, client_socket, client_address):
        # Handle the initial login process
        start_commands = self.login_handler(client_socket, client_address)

        # Handle the clients' requests and messages
        if start_commands:
            self.recv_handler(client_socket, client_address)

    # Handle the process for loggin in clients when they connect
    # Also handles blocked users and login trials
    def login_handler(self, client_socket, client_address):

        # Every user gets three tries to log in
        login_trials = 3
        login_finished = False
        # Prompt user to enter login details in the given format
        # login_resp returns the initialised protocol format for login messages
        login_req = self.login_resp(False, False, False, False, False)
        client_socket.send(login_req.encode())

        while True:
            client_req = client_socket.recv(2048)

            # If the connection has been closed by client end the recv loop and function
            if len(client_req) == 0:
                self.deactivate_handler(client_socket, client_address)
                return
            # Break up the message request and call appropriate handler
            else:
                lines = client_req.split(b'\r\n')
                header = lines[0].decode()
                data = lines[1].decode()

                if header == 'Login':
                    username, authenticated = self.login(data, client_socket)

                    if username is None:
                        user_found = False
                    else:
                        user_found = True

                    if not self.blocked_user_handler(username, client_socket):
                        return False

                    if username in self.active_users.keys():
                        self.block_user_login(client_socket, username)
                        return False

                    if authenticated:
                        login_response_message = self.login_resp(True, True, True, False, False)
                        client_socket.send(login_response_message.encode())
                        self.login_success(username, client_socket)
                        return True
                    else:
                        login_trials -= 1

                        if login_trials == 0:
                            self.block_user_login(client_socket, username)
                            return False

                        login_response_message = self.login_resp(authenticated, user_found, authenticated,
                                                                 not authenticated, False)
                        client_socket.send(login_response_message.encode())

                else:
                    client_socket.send(login_req.encode())

    def login_success(self, username, client_socket):
        self.active_users[username] = [client_socket, datetime.datetime.now()]
        if username in self.inactive_users.keys():
            del self.inactive_users[username]
        self.presence_broadcast(username, client_socket, 'in')
        if username in self.inbox.keys():
            print(self.inbox[username])
            for message in self.inbox[username]:
                client_socket.send(message.encode())
            self.inbox[username] = []

    # receive the requests from clients
    # Also address requests by calling appropriate request handlers... i.e login, whoelse
    def recv_handler(self, client_socket, client_address):
        timer = False
        while True:
            try:
                client_socket.settimeout(self.timeout_duration)
                client_req = client_socket.recv(2048)
            except:
                timeoutMessage = 'Timeout\r\nmessage:You Timed out'
                client_socket.send(timeoutMessage.encode())
                self.deactivate_handler(client_socket, client_address)
                return

            # timer.cancel()
            # If the connection has been closed by client end the recv loop and function
            if len(client_req) == 0:
                self.deactivate_handler(client_socket, client_address)
                return
            # Break up the message request and call appropriate handler
            else:
                lines = client_req.split(b'\r\n')
                header = lines[0].decode()

                if header == 'Login':
                    data = lines[1].decode()
                    continue
                if header == 'whoelse':
                    self.whoelse_handler(client_socket)

                if header == 'whoelsesince':
                    timediff = int(lines[1].decode().strip(';'))
                    threshold_time = datetime.datetime.now() - timedelta(seconds=timediff)
                    self.whoelsesince_handler(client_socket, threshold_time)

                if header == 'logout':
                    client_socket.send('Logout\r\nYou have been logged out;'.encode())
                    self.deactivate_handler(client_socket, client_address)
                    client_socket.close()
                    return

                if header == 'message':
                    details = lines[1].decode().split(';')
                    recepient = details[0]
                    message = details[1]
                    self.message_handler(recepient, message, client_socket)

                if header == 'broadcast':
                    message = lines[1].decode().strip(';')
                    self.broadcast_handler(message, client_socket)

                if header == 'block':
                    user = lines[1].decode().strip(';')
                    self.block_handler(user, client_socket)

                if header == 'unblock':
                    user = lines[1].decode().strip(';')
                    self.unblock_handler(user, client_socket)

    def unblock_handler(self, unblock_user, client_socket):
        for user in self.active_users.keys():
            if self.active_users[user][0] == client_socket:
                sender_name = user

        if unblock_user == sender_name:
            error = "Unblock_fail\r\nYou can't unblock yourself;"
            client_socket.send(error.encode())
            return

        if user in self.user_block_list.keys():
            if unblock_user in self.user_block_list[user]:
                self.user_block_list[user].remove(unblock_user)
                unblock_message = "Unblock\r\n{} has been unblocked;".format(unblock_user)
                client_socket.send(unblock_message.encode())
                return
            else:
                error = "Unblock_fail\r\nThis user was not blocked!;"
                client_socket.send(error.encode())
                return

    def block_handler(self, toBlock_user, client_socket):
        for user in self.active_users.keys():
            if self.active_users[user][0] == client_socket:
                sender_name = user

        if toBlock_user == sender_name:
            error = "Block_fail\r\nYou can't block yourself;"
            client_socket.send(error.encode())
            return

        if user in self.user_block_list.keys():
            if toBlock_user in self.user_block_list[user]:
                error = "Block_fail\r\nThis user has already been blocked by you;"
                client_socket.send(error.encode())
                return

        if (toBlock_user in self.active_users.keys()) or (toBlock_user in self.inactive_users.keys()):
            if user in self.user_block_list.keys():
                self.user_block_list[user].append(toBlock_user)
            else:
                self.user_block_list[user] = [toBlock_user]

            print(self.user_block_list[user])
            block_message = "Block\r\nBlocked {}!".format(toBlock_user)
            client_socket.send(block_message.encode())
            return
        else:
            error = "Block_fail\r\nUser doesn't exist;"
            client_socket.send(error.encode())
            return

    def broadcast_handler(self, message, sender_socket):
        for user in self.active_users.keys():
            if self.active_users[user][0] == sender_socket:
                sender_name = user

        for user in self.active_users.keys():
            if user in self.user_block_list.keys():
                print(self.user_block_list[user])
                if sender_name in self.user_block_list[user]:
                    new_message = 'Broadcast_fail\r\nYour broadcast was not shown to some users;'
                    sender_socket.send(new_message.encode())

            elif user != sender_name:
                new_message = 'Broadcast\r\nsender:{};content:{};'.format(sender_name, message)
                self.active_users[user][0].send(new_message.encode())

        sender_socket.send('Broadcast_resp\r\nFinished;'.encode())

    def message_handler(self, recepient_name, message, sender_socket):
        recepient_found = False
        self_message = False
        blocked = False

        for user in self.active_users.keys():
            if self.active_users[user][0] == sender_socket:
                sender_name = user

        if sender_name == recepient_name:
            new_message = 'Message_fail\r\nself_message:{};invalid_user:{};blocked_by_rec:{};'.format(True, False,
                                                                                                      False)
            sender_socket.send(new_message.encode())
            return

        if (recepient_name in self.user_block_list.keys()) and (sender_name in self.user_block_list[recepient_name]):
            new_message = 'Message_fail\r\nself_message:{};invalid_user:{};blocked_by_rec:{};'.format(False, False,
                                                                                                      True)
            sender_socket.send(new_message.encode())
            return

        if recepient_name in self.active_users.keys():
            new_message = 'Message\r\nsender:{};content:{}'.format(sender_name, message)
            self.active_users[recepient_name][0].send(new_message.encode())

        elif recepient_name in self.inactive_users.keys():
            new_message = 'Message\r\nsender:{};content:{}'.format(sender_name, message)
            if recepient_name in self.inbox.keys():
                self.inbox[recepient_name].append(new_message)
            else:
                self.inbox[recepient_name] = [new_message]

        else:
            new_message = 'Message_fail\r\nself_message:{};invalid_user:{};blocked_by_rec:{};'.format(False, True,
                                                                                                      False)
            sender_socket.send(new_message.encode())

        sender_socket.send('Message_resp\r\nMessage Sent!;'.encode())

    def presence_broadcast(self, new_user, client_socket, inout):
        message = 'PSA\r\n{} has just logged {}!'.format(new_user, inout)
        self.broadcast(client_socket, message)

    def whoelse_handler(self, client_socket):
        message = 'whoelse\r\n'
        for user in self.active_users.keys():
            if self.active_users[user][0] == client_socket:
                sender = user

        for user in self.active_users.keys():
            if user != sender:
                message = message + '{};'.format(user)
        client_socket.send(message.encode())

    def whoelsesince_handler(self, client_socket, threshold_time):
        message = 'whoelsesince\r\n'
        for user in self.active_users.keys():
            if self.active_users[user][0] == sender_socket:
                sender = user

        for user in self.active_users.keys():
            if user != sender:
                message = message + '{};'.format(user)

        for user in self.inactive_users.keys():
            if (self.inactive_users[user][2] > threshold_time):
                message = message + '{};'.format(user)

        client_socket.send(message.encode())

    def broadcast(self, aviod_client_socket, message):
        for user in self.active_users.keys():
            if aviod_client_socket != self.active_users[user][0]:
                self.active_users[user][0].send(message.encode())

    # If a client disconnects or logs out, handle that smoothly
    # remove them from active_users
    def deactivate_handler(self, client_socket, client_address):
        deactivate_flag = False
        print('Commands connection closed on : {}!'.format(client_address))
        for user in self.active_users.keys():
            if self.active_users[user][0] == client_socket:
                deactivate_flag = True
                delete_user = user

        if deactivate_flag:
            self.presence_broadcast(delete_user, client_socket, 'out')
            self.inactive_users[delete_user] = [client_socket, self.active_users[delete_user][0],
                                                datetime.datetime.now()]
            del self.active_users[delete_user]

        return

    # Checks username and password
    # Adds user to active users if authenticated
    # returns username and authenticated
    def login(self, data, client_socket):
        authenticated = False

        user_details = data.split(';')
        username = user_details[0].strip()
        password = user_details[1].strip()

        if username in self.credentials.keys():
            if self.credentials[username] == password:
                authenticated = True
            return username, authenticated
        else:
            return None, False

    # If user is blocked and under blocked duration
    # Send Blocked Message
    # Close the connection
    # return False
    def blocked_user_handler(self, username, client_socket):
        if username in self.blocked_users.keys():
            blocked_time = self.blocked_users[username][0]

            if datetime.datetime.now() < (blocked_time + timedelta(seconds=self.block_duration)):
                blocked_message = self.login_resp(False, False, False, False, True)
                client_socket.send(blocked_message.encode())
                client_socket.close()
                return False
            else:
                del self.blocked_users[username]
                return True
        else:
            return True

    # Blocks user from logging in
    # disconnects user
    # sends the blocked message to user
    def block_user_login(self, client_socket, user):

        if user in self.credentials.keys():
            self.blocked_users[user] = [datetime.datetime.now()]
        blocked_message = self.login_resp(False, False, False, False, True)
        client_socket.send(blocked_message.encode())
        client_socket.close()

    # returns the login response string
    def login_resp(self, Logged_in, Username, Password, Failed_try, Blocked):
        return 'Login\r\nLogged_in:{};Username:{};Password:{};Failed_try:{};Blocked:{}'.format(Logged_in, Username,
                                                                                               Password, Failed_try,
                                                                                               Blocked)

    # Extracts all the usernames and passwords from credentials.txt
    # returns dictionary containing all usernames and matchign passwords
    def extract_credentials(self):
        credentials = {}
        creds_file = open("credentials.txt", "r")

        if (creds_file != None):
            creds = creds_file.read().split('\n')
            for cred in creds:
                details = cred.split(' ')
                credentials[details[0]] = details[1]

        return credentials


if (len(sys.argv) != 4):
    print('Error: Wrong usage not enough arguments')
    sys.exit()

port = int(sys.argv[1])
block_duration = int(sys.argv[2])
timeout_duration = int(sys.argv[3])
server = server('127.0.0.1', port, block_duration, timeout_duration)
server.run()
