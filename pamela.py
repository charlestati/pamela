#!/usr/bin/env python
# coding: utf-8

import syslog


def log(msg, priority=syslog.LOG_INFO):
    syslog.syslog(priority, '[PAM] {}'.format(msg))


def lock_container(user, token):
    log('locking')
    if False:
        raise ValueError('Bad token in lock_container')


def unlock_container(user, token):
    log('unlocking')
    if False:
        raise ValueError('Bad token in unlock_container')


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        log(e)
        return e.pam_result
    if user is None:
        log('Failed authenticating in pam_sm_authenticate')
        return pamh.PAM_AUTH_ERR
    try:
        unlock_container(user, pamh.authtok)
    except ValueError:
        log(e)
        return pamh.PAM_AUTHTOK_ERR
    return pamh.PAM_SUCCESS


def pam_sm_end(pamh):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        log(e)
        return
    if user is not None:
        try:
            lock_container(user, pamh.authtok)
        except ValueError as e:
            log(e)
    else:
        log('Failed authenticating in pam_sm_end')


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
