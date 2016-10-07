#!/usr/bin/env python
# coding: utf-8

import ConfigParser
import os
import syslog


def log(msg, priority=syslog.LOG_INFO):
    syslog.syslog(priority, '[PAM] {}'.format(msg))


def lock_container():
    log('locking')
    if False:
        raise ValueError('Bad token in lock_container')


def unlock_container(container, mount_point, token):
    log('unlocking')
    if False:
        raise ValueError('Bad token in unlock_container')


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

    log(os.path.expanduser('~'))

    return pamh.PAM_SUCCESS


def get_abs_path(directory, path):
    if os.path.isabs(path):
        return os.path.expanduser(path)


# todo Debug
def main():
    config = ConfigParser.ConfigParser()
    config.read('pamela.ini')
    for section in config.sections():
        options = config.options(section)
        container = get_abs_path(config_file, options['container'])
        #unlock_container(options['container'], options['mountPoint'], 'azerty')


if __name__ == '__main__':
    main()
