#!/usr/bin/env python
# coding: utf-8

from sys import stderr

import syslog

DEFAULT_USER = "nobody"


def log(msg, priority=syslog.LOG_INFO):
    syslog.syslog(priority, '[PAM] {}'.format(msg))


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        return e.pam_result
    if user is None:
        pamh.user = DEFAULT_USER
    log('token: ' + pamh.authtok)
    return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
