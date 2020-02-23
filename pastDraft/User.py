

class User:

    def __init__(self, user_id, username, password):
        self._id = user_id
        self._username = username
        self._password = password
        self._blocked_users = []

    def block_user(self, username):
        self._blocked_users.append(username)

    def unblock_user(self, username):
        if username in self._blocked_users:
            self._blocked_users.remove(username)

    def blocked_users(self):
        return self._blocked_users

    def username(self):
        return self._username

    def password(self):
        return self._password

    def set_password(self, new_password):
        if self.check_password_security:
            self._password = new_password

    @staticmethod
    def check_password_security(password):
        if len(password) > 8:
            return True
        else:
            return False

