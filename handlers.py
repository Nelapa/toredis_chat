import jwt
import json
import redis
import toredis
import datetime
import dateutil.parser
import uuid
import hashlib

import tornado.gen
import tornado.web
import tornado.websocket

import auth


MIN_USERNAME_LEN = 2
MIN_PASSWORD_LEN = 6

MAX_USERNAME_LEN= 256
MAX_PASSWORD_LEN= 256

JWT_TOKEN_EXPIRE = datetime.timedelta(hours=1)


def _get_redis_client(host, port, password):
    client = toredis.Client()
    client.connect(host, port)
    client.auth(password)
    return client


class InvalidMessageException(Exception):
    pass


class MainHandler(tornado.web.RequestHandler):
    """
    Render chat SPA for authenticated users or redirect to login page
    """
    def get(self):
        self.render('index.html')


class BaseAuthJSONHandler(tornado.web.RequestHandler):
    def _get_redis_client(self):
        return _get_redis_client(
            host=self.settings['redis_host'],
            port=self.settings['redis_port'],
            password=self.settings['redis_password'],
        )


class RegistrationJSONHandler(BaseAuthJSONHandler):
    """
    Register new user with username and password
    """
    @tornado.gen.coroutine
    def post(self):
        try:
            data = json.loads(self.request.body)
        except ValueError:
            self.set_status(400)
            self.finish(json.dumps({'errors': {'-non-field-errors-': 'Invalid JSON'}}))
            return

        valid, errors = self.validate_registration_data(data)
        if not valid:
            self.set_status(400)
            self.finish(json.dumps(errors))
            return

        user_key = u'user:{}'.format(data['username'])
        user_data = self.dump_registration_data(data['password'])

        client = self._get_redis_client()
        user_created = yield tornado.gen.Task(client.setnx, user_key, user_data)
        if not user_created:
            self.set_status(400)
            self.finish(json.dumps({'errors': {'username': 'User already exists'}}))
        else:
            self.finish()

    def validate_registration_data(self, json_data):
        username = json_data.get('username')
        password = json_data.get('password')

        errors = {}

        if not username:
            errors['username'] = 'Username required'
        elif len(username) < MIN_USERNAME_LEN:
            errors['username'] = 'Username shorter than {} symbols is not permitted'.format(
                    MIN_USERNAME_LEN
            )
        elif len(username) > MAX_USERNAME_LEN:
            errors['username'] = 'Username longer than {} symbols is not permitted'.format(
                    MAX_USERNAME_LEN
            )

        if not password or len(password) < MIN_PASSWORD_LEN:
            errors['password'] = 'Password shorter than {} symbols is not permitted'.format(
                    MIN_PASSWORD_LEN
            )
        elif len(username) > MAX_PASSWORD_LEN:
            errors['username'] = 'Password longer than {} symbols is not permitted'.format(
                    MAX_PASSWORD_LEN
            )
        if errors:
            return False, errors
        return True, {}

    def dump_registration_data(self, password):
        salt = uuid.uuid4().hex
        password_hash = hashlib.sha512(password+salt).hexdigest()
        return json.dumps({
            'password_hash': password_hash,
            'salt': salt,
            'registered': datetime.datetime.utcnow().isoformat()
        })



class LoginJSONHandler(BaseAuthJSONHandler):
    """
    Login user and issue jwt token for websocket connection
    """
    @tornado.gen.coroutine
    def post(self):
        try:
            data = json.loads(self.request.body)
        except ValueError:
            self.set_status(400)
            self.finish(json.dumps({'errors': {'-non-field-errors-': 'Invalid JSON'}}))
            return

        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            self.set_status(400)
            self.finish(json.dumps({'errors': {'-non-field-errors-': 'Username and password required'}}))
            return

        client = self._get_redis_client()

        user_key = u'user:{}'.format(data['username'])
        user_data = yield tornado.gen.Task(client.get, user_key)
        if user_data:
            user_data = json.loads(user_data)
            password_hash = user_data['password_hash']
            salt = user_data['salt']
            if password_hash == hashlib.sha512(password+salt).hexdigest():
                self.set_cookie('jwt', self.create_token(username))
                return
        self.set_status(400)
        self.write(json.dumps({'errors': {'-non-field-errors-': 'Invalid username or password'}}))
        return

    def create_token(self, username):
        token = jwt.encode({
                'username': username,
                'expires': (datetime.datetime.utcnow() + JWT_TOKEN_EXPIRE).isoformat(),
            },
            key=self.settings['jwt_secret'],
            algorithm='HS256'
        )
        return token



class LogoutJSONHandler(BaseAuthJSONHandler):
    """
    Log out by clearing cookies

    It prevents from creation of new web sockets but it's still possible
    to use saved web socket
    """
    def post(self):
        self.clear_cookie('jwt')
        self.write(json.dumps({'type': 'info', 'message': 'Logged out'}))


class ChatHandler(tornado.websocket.WebSocketHandler):
    """
    General chat handler for websocket requests

    Gets websocket messages, publishes them to redis channel
    and gives back received from redis channel messages back to client.
    """
    COMMON_CHANNEL = 'chat'
    MAX_MESSAGE_LENGTH = 10000

    def open(self):
        """
        Handle socket opening:
        - check for auth token
        - ? add user to the list of active users
        """
        self.username = self._auth_user()
        if not self.username:
            self.write_json_message('error', 'Not authenticated')
            self.close()
            return
        import random
        self._id = random.randint(0,100)
        direct_channel = 'direct_channel:{}'.format(self.username)
        self.redis_client = self._get_redis_client()
        self.sub_redis_client = self._get_redis_client()
        self.sub_redis_client.subscribe(
            [self.COMMON_CHANNEL, direct_channel],
            callback=self.show_new_message
        )
        self.write_json_message('info', 'Connected')

    @tornado.gen.coroutine
    def on_message(self, message):
        """
        Pipe message to Redis queue
        """
        try:
            message = self._parse_incoming_message(message)
        except InvalidMessageException as e:
            self.write_json_message('error', e.message)
        else:
            message.update({
                'author': self.username,
                'sent': datetime.datetime.utcnow().isoformat()
            })
            yield self.publish_message(message)

    @classmethod
    def _parse_incoming_message(cls, message):
        try:
            message = json.loads(message)
        except ValueError:
            raise InvalidMessageException('Invalid json')
        message_text = message.get('message')
        if not message_text:
            raise InvalidMessageException('Message is empty, no reason to send it to anybody')
        if len(message_text) > cls.MAX_MESSAGE_LENGTH:
            raise InvalidMessageException('Message is too long')
        return message

    @tornado.gen.coroutine
    def show_new_message(self, message):
        if message[0] != 'message':
            return
        _, channel, json_message = message
        direct = channel.startswith('direct_channel:')
        json_message=json.loads(json_message)
        json_message['direct'] = direct
        try:
            yield self.write_message(json.dumps(json_message))
        except tornado.websocket.WebSocketClosedError:
            pass

    def on_close(self):
        """
        - remove user from the list of active users
        - shut down subscription event loop
        """
        if hasattr(self, 'sub_redis_client'):
            self.sub_redis_client.unsubscribe()

    def write_json_message(self, message_type, message, **kwargs):
        result = {
            'type': message_type,
            'message': message
        }
        if kwargs:
            result.update(kwargs)
        self.write_message(json.dumps(result))

    @tornado.gen.coroutine
    def publish_message(self, message_json):
        recipient = message_json.get('to')
        if recipient:
            # skipping recipient check
            channels = [
                u'direct_channel:{}'.format(u)
                for u in (self.username, recipient)
            ]
            message=json.dumps(message_json)
            for channel in channels:
                yield self.redis_client.publish(channel, message)
        else:
            yield self.redis_client.publish(
                self.COMMON_CHANNEL,
                json.dumps(message_json),
            )

    def _get_redis_client(self):
        return _get_redis_client(
            host=self.settings['redis_host'],
            port=self.settings['redis_port'],
            password=self.settings['redis_password'],
        )

    def _auth_user(self):
        token = self.get_cookie('jwt')
        if not token:
            return None
        try:
            user_info = jwt.decode(token, key=self.settings['jwt_secret'], algorithm='HS256')
            assert 'username' in user_info
            assert 'expires' in user_info
        except Exception as e:
            return None
        else:
            expires = user_info['expires']
            expires = dateutil.parser.parse(expires)
            if expires < datetime.datetime.utcnow():
                return None
            return user_info['username']
