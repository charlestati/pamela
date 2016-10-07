#!/usr/bin/env python
# coding: utf-8

import syslog
import os
import ConfigParser


def log(msg):
    syslog.syslog('[PAM] {}'.format(msg))


def lock_container(user):
    log('locking {}'.format(user))
    if False:
        raise ValueError('Bad token in lock_container')


def unlock_container(container, mount_point, token):
    log('unlocking {} to {}'.format(container, mount_point))
    if False:
        raise ValueError('Bad token in unlock_container')


def custom_expanduser(path, user):
    path = os.path.normpath(path)
    path_parts = path.split(os.sep)
    for i, part in enumerate(path_parts):
        if part == '~':
            path_parts[i] = '~{}'.format(user)
    expanded_path = os.path.expanduser(os.path.join(*path_parts))
    return os.path.abspath(expanded_path)


def get_section(section, config):
    containers = {}
    options = config.options(section)
    for option in options:
        containers[option] = config.get(section, option)
    return containers


def get_config(user):
    config = ConfigParser.ConfigParser()
    home_dir = os.path.expanduser('~{}'.format(user))
    config_file = os.path.join(home_dir, '.pamela.d', 'config.ini')
    config.read(config_file)
    return config


def unlock_user(user, token):
    config = get_config(user)
    for section in config.sections():
        options = get_section(section, config)
        container = custom_expanduser(options['container'], user)
        mount_point = custom_expanduser(options['mountpoint'], user)
        unlock_container(container, mount_point, token)


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        return e.pam_result
    if user is None:
        return pamh.PAM_AUTH_ERR
    unlock_user(user, pamh.authtok)
    return pamh.PAM_SUCCESS


def pam_sm_end(pamh):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        return
    if user is not None:
        try:
            lock_container(user)
        except ValueError as e:
            log(e)


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
