#coding=utf-8
import json
import mock
import toredis
import unittest

import tornado.testing

from app import Application


def get_mock_client(user_created=1):
    def getter(host, port, password):
        _mock = mock.MagicMock()
        _mock.setnx = tornado.gen.coroutine(lambda key, value: user_created)
        return _mock
    return getter

class RegistrationHandlerTestCase(tornado.testing.AsyncHTTPTestCase):
    def get_app(self):
        return Application()

    def _register_user(self, username='nelapa', password='password'):
        payload = {}
        if username is not None:
            payload['username'] = username
        if password is not None:
            payload['password'] = password
        payload = json.dumps(payload)
        response = self.fetch(
                '/register',
                method='POST',
                headers={'Content-Type': 'application/json'},
                body=payload
        )
        return response

    @mock.patch('handlers._get_redis_client', side_effect=get_mock_client(1))
    def test_register_success(self, _mock):
        response = self._register_user()
        self.assertEqual(response.code, 200)

    @mock.patch('handlers._get_redis_client', side_effect=get_mock_client(0))
    def test_nonunique_username(self, _mock):
        response = self._register_user()
        response = self._register_user()
        self.assertEqual(response.code, 400)
        self.assertIn('User already exists', response.body)

    def test_invalid_username(self):
        response = self._register_user(username='@')
        self.assertEqual(response.code, 400)
        self.assertIn('Username shorter than', response.body)

    def test_invalid_password(self):
        response = self._register_user(password='4')
        self.assertEqual(response.code, 400)
        self.assertIn('Password shorter than', response.body)

    def test_missing_username(self):
        response = self._register_user(username=None)
        self.assertEqual(response.code, 400)
        self.assertIn('Username required', response.body)

    def test_missing_password(self):
        response = self._register_user(password=None)
        self.assertEqual(response.code, 400)
        self.assertIn('Password shorter than', response.body)

    @mock.patch('handlers._get_redis_client', side_effect=get_mock_client(1))
    def test_unicode_username(self, _mock):
        response = self._register_user(username=u'юникод')
        self.assertEqual(response.code, 200)
