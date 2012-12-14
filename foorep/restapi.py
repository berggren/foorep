# Copyright (C) 2012 Johan Berggren.
# This file is part of foorep
# See the file 'LICENSE.txt' for copying permission.

import cherrypy
from bson import json_util
import foorep

class FileResource:
    def __init__(self, repo):
        self.repo = repo
    exposed = True

    def GET(self, uuid):
        cherrypy.response.headers['Content-Type'] = 'application/json'
        doc = self.repo.get(uuid)
        return json_util.dumps(doc)

class ApiRoot:
    def __init__(self):
        self.repo = foorep.Repository()

def main():
    engine = cherrypy.engine
    root = Root()
    root.file = FileResource(root.repo)
    conf = {
        'global': {
            'server.socket_host': "127.0.0.1",
            'server.socket_port': 4781,
            'server.thread_pool': 200,
            'server.socket_queue_size': 60,
            },
        }
    app_conf = {'/': {
            'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
        }
    }
    cherrypy.config.update(conf)
    cherrypy.tree.mount(root, '/api/v1', config=app_conf)
    engine.start()

if __name__ == "__main__":
    main()
