# -*- coding: utf-8 -*-

from pytest import mark

from webtest import TestApp
from bottle import Bottle
from moulinette.interfaces.api import filter_csrf


URLENCODED = 'application/x-www-form-urlencoded'
FORMDATA = 'multipart/form-data'
TEXT = 'text/plain'

TYPES = [URLENCODED, FORMDATA, TEXT]
SAFE_METHODS = ["HEAD", "GET", "PUT", "DELETE"]


app = Bottle(autojson=True)
app.install(filter_csrf)


@app.get('/')
def get_hello():
    return "Hello World!\n"


@app.post('/')
def post_hello():
    return "OK\n"


@app.put('/')
def put_hello():
    return "OK\n"


@app.delete('/')
def delete_hello():
    return "OK\n"


test = TestApp(app)


def run(status, method, ctype=None, origin=None, referer=None):
    headers = {}
    headers["host"] = "localhost:8080"
    if origin is not None:
        headers["origin"] = origin
    if referer is not None:
        headers["referer"] = referer
    if ctype is None:
        data = None
    else:
        headers["content-type"] = ctype
        data = "whatever"
    r = test.request("/", method=method, headers=headers, body=data,
                     expect_errors=True)
    assert(r.status[:3] == str(status))


@mark.parametrize("method", SAFE_METHODS)
def test_safe_methods(method):
    """
    No need to do any CSRF check for those methods
    """
    if method == "PUT":
        ctype = TEXT
    else:
        ctype = None
    run(200, method, ctype)


OK_PARAMS = [

             ("POST", URLENCODED, "https://localhost:8080/foo", None),
             ("POST", URLENCODED, "https://localhost:8080", None),
             ("POST", URLENCODED, None, "https://localhost:8080"),

             ("POST", FORMDATA, "https://localhost:8080/foo", None),
             ("POST", FORMDATA, "https://localhost:8080", None),
             ("POST", FORMDATA, None, "https://localhost:8080"),

             ("POST", TEXT, "https://localhost:8080/foo", None),
             ("POST", TEXT, "https://localhost:8080", None),
             ("POST", TEXT, None, "https://localhost:8080"),

             ]


@mark.parametrize("method,ctype,referer,origin", OK_PARAMS)
def test_not_csrf(method, ctype, referer, origin):
    """
    When a suitable Refere or Origin is found, this is not a CSRF
    """
    run(200, method, ctype, referer=referer, origin=origin)


@mark.parametrize("ctype", [(ctype) for ctype in TYPES])
def test_csrf_no_referer_no_origin(ctype):
    """
    There is no Referer and no Origin, this is a CSRF.
    """
    run(403, "POST", ctype)


BAD_REFERERS = ["https://localhost:8081/foo",
                "https://example.com:8080/foo"
                "https://localhost:80801"]


@mark.parametrize("ctype,referer", [(ctype, referer)
                                    for ctype in TYPES
                                    for referer in BAD_REFERERS])
def test_csrf_bad_referer(ctype, referer):
    """
    There is a cross-origin Referer, this is a CSRF.
    """
    run(403, "POST", ctype, referer=referer)


BAD_ORIGINS = ["https://localhost:80801",
               "https://example.com:8080"]


@mark.parametrize("ctype,origin", [(ctype, origin)
                                   for ctype in TYPES
                                   for origin in BAD_ORIGINS])
def test_csrf_bad_origin(ctype, origin):
    """
    There is a cross-origin Referer, this is a CSRF.
    """
    run(403, "POST", ctype, origin=origin)
