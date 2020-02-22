# Python 3
# Usage: 
# Puneeth Kambhampati, z5164647

import socket
import sys
import time
import threading
import os

keyT = 0


class client():

    def __init__(self, IpAddress, portno):
        self.ip = IpAddress
        self.port = portno
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logged_in = False
        self.t_lock = threading.Condition()

    def run(self):
        self.client_socket.connect((self.ip, self.port))
        while self.logged_in == False:
            server_message = self.client_socket.recv(2048).decode()

            if len(server_message) == 0:
                print('Server Closed!')
                return

            section = server_message.split('\r\n')
            header = section[0]
            data = section[1]
            if header == 'Login':
                self.login(data)

        while True:
            command_thread = threading.Thread(name="command_handler", target=self.command_handler)
            command_thread.daemon = True
            command_thread.start()

            server_message = self.client_socket.recv(2048).decode()

            if len(server_message) == 0:
                print('Server Closed!')
                sys.exit()

            section = server_message.split('\r\n')
            header = section[0]
            data = section[1]

            if (header == 'Timeout'):
                print(data)
                return
            elif header == 'Login':
                self.login(data)

            elif header == 'Logout':
                print(data.strip(';'))
                sys.exit()

            elif header == 'PSA':
                print(data)

            elif header == 'whoelse' or header == 'whoelsesince':
                users = data.split(';')
                for user in users:
                    if user != '':
                        print('>', user)

            elif header == 'Message':
                message_details = data.split(';')
                user = message_details[0].split(':')
                content = message_details[1].split(':')
                print('\n{}: {}'.format(user[1], content[1]))

            elif header == 'Broadcast':

                message_details = data.split(';')
                user = message_details[0].split(':')
                content = message_details[1].split(':')
                print('\n{}: {}'.format(user[1], content[1]))

            elif header == 'Broadcast_resp':
                pass

            elif header == 'Message_resp':
                pass

            elif header == 'Message_fail':
                message_details = data.split(';')
                self_message = message_details[0].split(':')[1]
                invalid_user = message_details[1].split(':')[1]
                Blocked = message_details[2].split(':')[1]

                if invalid_user == 'True':
                    print('This user does not exist on our server')
                elif Blocked == 'True':
                    print('This user has blocked you. He will not receive your messages')
                elif self_message == 'True':
                    print("You can't send a message to your self")

            elif header == 'Broadcast_fail':
                print(data.strip(';'))

            elif header == 'Logout':
                print(data.strip(';'))
                sys.exit()

            elif header == 'Block':
                print(data.strip(';'))

            elif header == 'Block_fail':
                print(data.strip(';'))

            elif header == 'Unblock':
                print(data.strip(';'))

            elif header == 'Unblock_fail':
                print(data.strip(';'))

            print('Press Enter: To see updates & insert new command')
            stop_threads = True
            command_thread.join()

    def command_handler(self):
        command = input('Command> ')

        inputs = command.split(' ')
        if len(inputs) == 0:
            return

        command = inputs[0]

        if command == '':
            pass
        elif command == 'whoelse':
            if len(inputs) != 1:
                print('Error: Wrong usage of whoelse')
                return
            self.client_socket.send(command.encode())

        elif command == 'whoelsesince':
            if len(inputs) != 2:
                print('Error: Wrong usage of whoelsesince')
                return
            try:
                int(inputs[1])
            except:
                print('Error: Wrong usage of whoelse. Enter integer for time!')
                return

            interval = inputs[1]
            query = 'whoelsesince\r\n{};'.format(interval)
            self.client_socket.send(query.encode())

        elif command == 'logout':
            self.client_socket.send('logout\r\n'.encode())

        elif command == 'message':
            if len(inputs) < 3:
                print('Error: Wrong usage of message')
                return
            message = ''
            for i in range(2, len(inputs)):
                message = message + ' ' + inputs[i]

            query = 'message\r\n{};{};'.format(inputs[1], message)
            self.client_socket.send(query.encode())

        elif command == 'broadcast':
            if len(inputs) < 2:
                print('Error: Wrong usage of broadcast')

            message = ''
            for i in range(1, len(inputs)):
                message = message + ' ' + inputs[i]
            query = 'broadcast\r\n{};'.format(message)
            self.client_socket.send(query.encode())

        elif command == 'block':
            if len(inputs) < 2:
                print('Error: Wrong usage of block')
            user = inputs[1]
            query = 'block\r\n{}'.format(user)
            self.client_socket.send(query.encode())

        elif command == 'unblock':
            if len(inputs) < 2:
                print('Error: Wrong usage of block')
            user = inputs[1]
            query = 'unblock\r\n{}'.format(user)
            self.client_socket.send(query.encode())

        else:
            print("Error: Command doesn't exist")

        return

    def login(self, data):
        login_resp = {}

        lines = data.split(';')

        for line in lines:
            flag = line.split(':')
            if len(flag) == 2:
                login_resp[flag[0]] = flag[1]

        if login_resp['Blocked'] == 'True':
            print('You have been blocked. Please try later.')
            # sys.exit()
            return

        if login_resp['Logged_in'] == 'False':

            if login_resp['Username'] == 'False':
                if login_resp['Failed_try'] == 'True':
                    print('Entered Username does not exist in the Database')
                self.username = input('Username: ')
                self.password = input('Password: ')

            elif login_resp['Password'] == 'False':
                if login_resp['Failed_try'] == 'True':
                    print('Invalid Password. Try Again...')
                self.password = input('Password: ')

            header = 'Login\r\n'

            self.client_socket.send((header + self.username + ';' + self.password + ';').encode())
        else:
            print('Logged in...\nYou may now use the Chat room')
            self.logged_in = True


if (len(sys.argv) != 3):
    print('Error: Wrong usage not enough arguments')
    sys.exit()

ip = sys.argv[1]
port = int(sys.argv[2])
client = client(ip, port)
client.run()
