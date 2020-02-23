

class User():

    def __init__(self, user_id, username, password):
        self._id = user_id
        self._username = username
        self._password = password
        self._blocked_users = {}
