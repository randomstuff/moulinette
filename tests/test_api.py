# -*- coding: utf-8 -*-

from webtest import TestApp as WebTestApp
from bottle import Bottle
from moulinette.interfaces.api import filter_csrf


HOST = "www.example.test"
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


webtest = WebTestApp(app)


def test_get():
    r = webtest.get("/")
    assert r.status_code == 200


def test_csrf_post():
    r = webtest.post("/", "test", expect_errors=True)
    assert r.status_code == 403


def test_post_json():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "application/json"),
                              ("Host", HOST)])
    assert r.status_code == 200


def test_csrf_post_text():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "text/plain"),
                              ("Host", HOST)],
                     expect_errors=True)
    assert r.status_code == 403


def test_csrf_post_urlencoded():
    r = webtest.post("/", "test",
                     headers=[("Content-Type",
                               "application/x-www-form-urlencoded"),
                              ("Host", HOST)],
                     expect_errors=True)
    assert r.status_code == 403


def test_csrf_post_form():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("Host", HOST)],
                     expect_errors=True)
    assert r.status_code == 403


def test_ok_post_text():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "text/plain"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST)])
    assert r.status_code == 200


def test_ok_post_urlencoded():
    r = webtest.post("/", "test",
                     headers=[("Content-Type",
                               "application/x-www-form-urlencoded"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST)])
    assert r.status_code == 200


def test_ok_post_form():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST)])
    assert r.status_code == 200


def test_csrf_post_form_evil_origin():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Origin", "https://www.evil.test")],
                     expect_errors=True)
    assert r.status_code == 403


def test_csrf_post_form_http_origin():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Origin", "http://" + HOST)],
                     expect_errors=True)
    assert r.status_code == 403


def test_csrf_post_form_multiple_origins():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Origin", "https://" + HOST + " https://www.evil.test")],
                     expect_errors=True)
    assert r.status_code == 403


def test_ok_post_form_good_origin():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Origin", "https://" + HOST)])
    assert r.status_code == 200


def test_csrf_post_form_evil_referrer():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Referer", "https://www.evil.test")],
                     expect_errors=True)
    assert r.status_code == 403


def test_csrf_post_form_http_referrer():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Referer", "http://" + HOST)],
                     expect_errors=True)
    assert r.status_code == 403


def test_ok_post_form_good_referrer():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Referer", "https://" + HOST)])
    assert r.status_code == 200


def test_csrf_post_form_evil_full_referrer():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Referer", "https://www.evil.test/foo")],
                     expect_errors=True)
    assert r.status_code == 403


def test_csrf_post_form_http_full_referrer():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Referer", "http://" + HOST + "/foo")],
                     expect_errors=True)
    assert r.status_code == 403


def test_ok_post_form_good_full_referrer():
    r = webtest.post("/", "test",
                     headers=[("Content-Type", "multipart/form-data"),
                              ("X-Requested-With", "XMLHttpRequest"),
                              ("Host", HOST),
                              ("Referer", "https://" + HOST + "/foo")])
    assert r.status_code == 200
