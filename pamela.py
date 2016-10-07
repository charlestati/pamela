#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function
import sys
import os
import ConfigParser

import syslog


def log(msg):
    syslog.syslog('[PAM] {}'.format(msg))
    #print('[PAM] {}'.format(msg), file=sys.stderr)


def lock_container(user):
    log('locking')
    if False:
        raise ValueError('Bad token in lock_container')


def unlock_container(container, mount_point, token):
    log('unlocking')
    if False:
        raise ValueError('Bad token in unlock_container')


def get_abs_path(directory, path):
    if os.path.isabs(path):
        return os.path.expanduser(path)


def get_config(user):
    config = ConfigParser.ConfigParser()
    home_dir = os.path.expanduser('~{}'.format(user))
    config_file = os.path.join(home_dir, '.pamela')
    config.read(config_file)
    return config


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        log(e)
        return e.pam_result
    if user is None:
        log('Failed authenticating in pam_sm_authenticate')
        return pamh.PAM_AUTH_ERR

    log(os.path.expanduser('~{}'.format(user)))

    return pamh.PAM_SUCCESS

    try:
        config = get_config(user)
        for section in config.sections():
            options = config.options(section)
            unlock_container(options['container'], options['mountPoint'], pamh.authtok)
    except ValueError as e:
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
            lock_container(user)
        except ValueError as e:
            log(e)
    else:
        log('Failed authenticating in pam_sm_end')


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
