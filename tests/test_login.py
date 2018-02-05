#coding=utf-8
import json
import mock
import uuid
import hashlib
import toredis
import unittest

import tornado.testing

from app import Application

SALT = uuid.uuid4().hex
PASSWORD = 'test_password'
USER_DATA = json.dumps({
        'password_hash': hashlib.sha512(PASSWORD+SALT).hexdigest(),
        'salt': SALT
})


def get_mock_client(user_exists=1):
    def getter(host, port, password):
        _mock = mock.MagicMock()
        _mock.get = tornado.gen.coroutine(lambda key: USER_DATA if user_exists else None)
        return _mock
    return getter


class LoginHandlerTestCase(tornado.testing.AsyncHTTPTestCase):
    def get_app(self):
        return Application()

    def _login_user(self, username='nelapa', password='password'):
        payload = {}
        if username is not None:
            payload['username'] = username
        if password is not None:
            payload['password'] = password
        payload = json.dumps(payload)
        response = self.fetch(
                '/login',
                method='POST',
                headers={'Content-Type': 'application/json'},
                body=payload
        )
        return response

    @mock.patch('handlers._get_redis_client', side_effect=get_mock_client(1))
    def test_login_success(self, _mock):
        response = self._login_user(password=PASSWORD)
        self.assertEqual(response.code, 200)
        self.assertIn('jwt', response.headers['Set-Cookie'])

    @mock.patch('handlers._get_redis_client', side_effect=get_mock_client(0))
    def test_nonexistent_username(self, _mock):
        response = self._login_user(password=PASSWORD)
        self.assertEqual(response.code, 400)
        self.assertIn('Invalid username or password', response.body)

    @mock.patch('handlers._get_redis_client', side_effect=get_mock_client(1))
    def test_invalid_password(self, _mock):
        response = self._login_user(password='invalid_password')
        self.assertEqual(response.code, 400)
        self.assertIn('Invalid username or password', response.body)
