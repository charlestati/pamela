#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function

from sys import stderr

DEFAULT_USER = "nobody"


def print_error(*args, **kwargs):
    print(*args, file=stderr, **kwargs)


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        return e.pam_result
    if user is None:
        pamh.user = DEFAULT_USER
    print_error('setcred')
    print_error(pamh.authtok)
    return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    print_error('setcred')
    return pamh.PAM_SUCCESS
