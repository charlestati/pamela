#!/usr/bin/env python
# coding: utf-8

from __future__ import unicode_literals

import subprocess
import syslog
import os

import ConfigParser

import pexpect as pexpect


def log(msg):
    syslog.syslog('[PAM] {}'.format(msg))


def lock_container(mount_point):
    subprocess.call('umount {}'.format(mount_point))


def unlock_container(container, mount_point, token):
    log('Mounting {} to {}'.format(container, mount_point))
    child = pexpect.spawnu(
        'mount -t ecryptfs -o ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_passthrough=no,ecryptfs_enable_filename_crypto=no {} {}'.format(
            container, mount_point))
    child.expect('Selection: ')
    child.sendline('1')
    child.expect('Passphrase: ')
    child.sendline(token)
    child.close()


def custom_expanduser(path, user):
    path = os.path.normpath(path)
    path_parts = path.split(os.sep)
    for i, part in enumerate(path_parts):
        if part == '~':
            path_parts[i] = '~{}'.format(user)
    expanded_path = os.path.expanduser(os.path.join(*path_parts))
    return expanded_path


def get_path(path, user):
    if os.path.isabs(path):
        return path
    config_file = get_config_file(user)
    config_file_location = os.path.dirname(config_file)
    expanded_path = custom_expanduser(path, user)
    return os.path.join(config_file_location, expanded_path)


def get_section(section, config):
    containers = {}
    options = config.options(section)
    for option in options:
        containers[option] = config.get(section, option)
    return containers


def get_config_file(user):
    home_dir = os.path.expanduser('~{}'.format(user))
    return os.path.join(home_dir, '.pamela.d', 'config.ini')


def get_config(config_file):
    config = ConfigParser.ConfigParser()
    config.read(config_file)
    return config


def lock_user(user):
    config_file = get_config_file(user)
    if not os.path.isfile(config_file):
        return
    config = get_config(config_file)
    for section in config.sections():
        options = get_section(section, config)
        mount_point = get_path(options['mountpoint'], user)
        lock_container(mount_point)


def unlock_user(user, token):
    config_file = get_config_file(user)
    if not os.path.isfile(config_file):
        return
    config = get_config(config_file)
    for section in config.sections():
        options = get_section(section, config)
        container = get_path(options['container'], user)
        mount_point = get_path(options['mountpoint'], user)
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
    except pamh.exception:
        return
    if user is not None:
        lock_user(user)


# todo Check if config file exists and if contaienr and mountpoints exist
def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
