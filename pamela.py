#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function
from sys import stderr

import syslog

DEFAULT_USER = "nobody"


def log_message(msg):
    syslog.syslog(syslog.LOG_INFO, msg)


def print_error(*args, **kwargs):
    print(*args, file=stderr, **kwargs)


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        return e.pam_result
    if user is None:
        pamh.user = DEFAULT_USER
    log_message('log auth')
    print_error('print auth')
    #print_error(pamh.authtok)
    return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    log_message('log setcred')
    print_error('print setcred')
    return pamh.PAM_SUCCESS
