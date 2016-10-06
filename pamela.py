#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function

import sys

DEFAULT_USER = "nobody"


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        return e.pam_result
    if user is None:
        pamh.user = DEFAULT_USER
    print('setcred', file=sys.stderr)
    print(pamh.authtok, file=sys.stderr)
    return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    print('setcred', file=sys.stderr)
    return pamh.PAM_SUCCESS
