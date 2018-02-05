import os

import tornado.ioloop
import tornado.web

import handlers


class Application(tornado.web.Application):
    def __init__(self, *args, **kwargs):
        web_handlers = [
            (r'/', handlers.MainHandler),
            (r'/register', handlers.RegistrationJSONHandler),
            (r'/login', handlers.LoginJSONHandler),
            (r'/logout', handlers.LogoutJSONHandler),
            (r'/chat', handlers.ChatHandler),
        ]

        settings = dict(
            debug = True,  # todo: disable
            jwt_secret='SECRET',
            # gzip=True,
            cookie_secret = 'COOKIE_SECRET',
            # xsrf_cookies = True
            # login_url = '/login',
            # autoescape?
            # db_name?
            # apptitle
            # static_path=os.path.join(os.path.dirname(__file__), 'static'),
            template_path=os.path.join(os.path.dirname(__file__), 'templates'),

            redis_host='localhost',
            redis_port=6379,
            redis_password='password',
        )
        if kwargs:
            settings.update(kwargs)

        super(Application, self).__init__(web_handlers, **settings)

if __name__ == '__main__':
    app = Application()
    app.listen(8000)
    tornado.ioloop.IOLoop.current().start()
