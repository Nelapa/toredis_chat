import jwt
import datetime

import tornado.testing
import tornado.httpserver
import tornado.httpclient
import tornado.gen
import tornado.websocket

from app import Application

APP = Application()
JWT_TOKEN_EXPIRE = datetime.timedelta(seconds=5)

class ChatAuthHandler(tornado.testing.AsyncTestCase):
    def setUp(self):
        super(ChatAuthHandler, self).setUp()
        server = tornado.httpserver.HTTPServer(APP)
        socket, self.port = tornado.testing.bind_unused_port()
        server.add_socket(socket)

    @tornado.testing.gen_test
    def test_auth_no_cookie(self):
        connection = yield self._connect(auth=False)
        response = yield connection.read_message()
        self.assertIn('Not authenticated', response)

    @tornado.testing.gen_test
    def test_auth_invalid_token(self):
        connection = yield self._connect(token='test')
        response = yield connection.read_message()
        self.assertIn('Not authenticated', response)

    @tornado.testing.gen_test
    def test_auth_success(self):
        token = jwt.encode({
                'username': 'tester',
                'expires': (datetime.datetime.utcnow() + JWT_TOKEN_EXPIRE).isoformat(),
            },
            key=APP.settings['jwt_secret'],
            algorithm='HS256'
        )
        connection = yield self._connect(token=token)
        response = yield connection.read_message()
        self.assertIn('Connected', response)


    def _connect(self, auth=True, token=None):
        jwt_cookie = 'jwt={}'.format(token or '')
        request = tornado.httpclient.HTTPRequest(
            url = 'ws://localhost:{}/chat'.format(self.port),
            headers={'Cookie': jwt_cookie} if auth else {}
        )
        return tornado.websocket.websocket_connect(request)
