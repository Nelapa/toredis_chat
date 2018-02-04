import json
import redis
import toredis
import datetime

import tornado.gen
import tornado.web
import tornado.websocket

import auth


MIN_USERNAME_LEN = 2
MIN_PASSWORD_LEN = 6


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


class RegistrationJSONHandler(tornado.web.RequestHandler):
    """
    Register new user with username and password
    """
    @tornado.web.asynchronous
    def post(self):
        data = json.loads(self.request.body)

        valid, errors = self.validate_registration_data(data)
        if not valid:
            self.set_status(400)
            self.finish(json.dumps(errors))
            return

        user_key = u'user:{}'.format(data['username'])
        user_data = json.dumps({
            'password': data['password'],
            'registered': datetime.datetime.now().isoformat()
        })
        client = self._get_redis_client()
        client.setnx(user_key, user_data, callback=self.on_create)

    def on_create(self, user_created):
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

        if not password or len(password) < MIN_PASSWORD_LEN:
            errors['password'] = 'Password shorter than {} symbols is not permitted'.format(
                    MIN_PASSWORD_LEN
            )
        if errors:
            return False, errors
        return True, {}

    def _get_redis_client(self):
        return _get_redis_client(
            host=self.settings['redis_host'],
            port=self.settings['redis_port'],
            password=self.settings['redis_password'],
        )


class LoginHandler(tornado.web.RequestHandler):
    pass


class LogoutHandler(tornado.web.RequestHandler):
    pass


class ChatHandler(tornado.websocket.WebSocketHandler):
    """
    General chat handler for websocket requests

    Gets websocket messages, publishes them to redis channel
    and gives back received from redis channel messages back to client.
    """
    COMMON_CHANNEL = 'chat'
    max_message_length = 10000

    def open(self):
        """
        Handle socket opening:
        - check for auth token
        - ? add user to the list of active users
        """
        import random
        self._id = random.randint(0,100)
        self.redis_client = toredis.Client()
        self.redis_client.connect(
            host=self.settings['redis_host'],
            port=self.settings['redis_port'],
        )
        self.redis_client.auth(self.settings['redis_password'])
        self.redis_client2 = toredis.Client()
        self.redis_client2.connect(
            host=self.settings['redis_host'],
            port=self.settings['redis_port'],
        )
        self.redis_client2.auth(self.settings['redis_password'])
        self.redis_client2.subscribe(self.COMMON_CHANNEL, callback=self.show_new_message)
        print 'listening...'

    @tornado.gen.coroutine
    def on_message(self, message):
        """
        Pipe message to Redis queue
        """
        # TODO: handle validation
        print self._id, 'sending message: ', message
        self._validate_incoming_message(message)
        yield self.redis_client.publish(
            self.COMMON_CHANNEL,
            message,
        )
        print self._id, 'message sent: ', message

    @classmethod
    def _validate_incoming_message(cls, message):
        # TODO
        if not message:
            raise InvalidMessageException('Message is empty, no reason to send it to anybody')
        if len(message) > cls.max_message_length:
            raise InvalidMessageException('Message is too long')

    @tornado.gen.coroutine
    def show_new_message(self, message):
        # TODO: filter out messages?
        print self._id, 'received message:', message
        try:
            yield self.write_message(u"Somebody's said: " + unicode(message))
        except tornado.websocket.WebSocketClosedError:
            pass

    def on_close(self):
        """
        - remove user from the list of active users
        - shut down subscription event loop
        """
        self.redis_client2.unsubscribe()
