# Copyright (C) 2012 Johan Berggren.
# This file is part of foorep
# See the file 'LICENSE.txt' for copying permission.

import cherrypy
import jinja2
import foorep
import tempfile
import os
import base64
import re
from foorep.restapi import ApiRoot, FileResource

site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),"site")

def guess_autoescape(template_name):
    if template_name is None or '.' not in template_name:
        return False
    ext = template_name.rsplit('.', 1)[1]
    return ext in ('html', 'htm', 'xml')

env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.join(site_dir, 'templates')),
        autoescape=guess_autoescape,
        extensions=['jinja2.ext.autoescape'])

def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    return value.strftime(format)

env.filters['datetimeformat'] = datetimeformat

def is_picture(file):
    if re.match('JPEG|PNG', file['meta']['filetype']):
        return True
    return False

class App:
    @cherrypy.expose
    def index(self):
        tmpl = env.get_template('index.html')
        return tmpl.render()

class Search:
    def __init__(self, repo):
        self.repo = repo
    @cherrypy.expose
    def index(self, q=None):
        tmpl = env.get_template('result.html')
        if not q or q == '.':
            raise cherrypy.HTTPRedirect("/")
        result = self.repo.search(q)
        return tmpl.render(result=result)

class Annotate:
    def __init__(self, repo):
        self.repo = repo
    @cherrypy.expose
    def default(self, uuid, type, value):
        annotation = {"type": type, "annotation": value}
        self.repo.annotate(uuid, annotation)
        raise cherrypy.HTTPRedirect("/file/%s" % uuid)

class File:
    def __init__(self, repo):
        self.repo = repo
    @cherrypy.expose
    def default(self, uuid):
        tmpl = env.get_template('file.html')
        file = self.repo.get(uuid)
        if is_picture(file):
            img = self.repo.get_file(file['file'])
            b64img = base64.b64encode(img.read())
        else:
            b64img = None
        return tmpl.render(file=file, b64img=b64img)

class Upload:
    def __init__(self, repo):
        self.repo = repo
    @cherrypy.expose
    def default(self, fh):
        _tmpf = tempfile.mkstemp()
        tmpfn = _tmpf[1]
        tmpfh = os.fdopen(_tmpf[0], "wb")
        tmpfh.write(fh.file.read())
        tmpfh.close()
        doc = self.repo.insert(tmpfn, filename=fh.filename)
        os.remove(tmpfn)
        raise cherrypy.HTTPRedirect("/file/%s" % doc['uuid'])

class Download:
    def __init__(self, repo):
        self.repo = repo
    @cherrypy.expose
    def default(self, uuid):
        doc = self.repo.get(uuid)
        fh = self.repo.get_file(doc['file'])
        return cherrypy.lib.static.serve_fileobj(fh, content_type="application/x-download",
                disposition="attachment", name=doc['meta']['hash']['sha1'])

def main():
    repo = foorep.Repository()
    engine = cherrypy.engine
    global_conf = {
        'global': {
            'server.socket_host': '127.0.0.1',
            'server.socket_port': 4780,
            'server.thread_pool': 200,
            'server.socket_queue_size': 60,
            },
    }
    cherrypy.config.update(global_conf)

    # Start WebUI
    webui = App()
    webui.search = Search(repo)
    webui.file = File(repo)
    webui.download = Download(repo)
    webui.upload = Upload(repo)
    webui.annotate = Annotate(repo)
    webui_conf = {
        '/': {
            'tools.login_required.on': False,
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.root': site_dir,
            'tools.staticdir.dir': 'static',
        }
    }
    # Start RESTFul API
    restapi = ApiRoot()
    restapi.file = FileResource(repo)  
    restapi_conf = {
            '/': {
                'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
            }
    }

    cherrypy.tree.mount(webui, '/', config=webui_conf)
    cherrypy.tree.mount(restapi, '/api/v1', config=restapi_conf)
    engine.start()
    
if __name__ == "__main__":
    main()
