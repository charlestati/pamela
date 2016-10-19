#!/usr/bin/env python
# coding: utf-8

import base64
import ConfigParser
import os
import pipes
import subprocess

EXIT_SUCCESS = 0


class Container:
    def __init__(self, container, mount_point):
        self.container = container
        self.mount_point = mount_point
        self.fuuid = base64.b64encode(self.container)
        self.map = os.path.join('/dev/mapper', self.fuuid)

    # todo Remettre shell=True si besoin
    def open(self, passphrase):
        if os.path.ismount(self.mount_point):
            raise IOError('Mount point is already mounted')

        cryptsetup = subprocess.Popen('cryptsetup luksOpen {} {}'.format(pipes.quote(self.container), self.fuuid),
                                      stdin=subprocess.PIPE)
        cryptsetup.communicate('{}\n'.format(passphrase))
        cryptsetup.wait()

        if cryptsetup.returncode != EXIT_SUCCESS:
            raise IOError('luksOpen failed')

        if subprocess.call('mount {} {}'.format(self.map, pipes.quote(self.mount_point))) != EXIT_SUCCESS:
            subprocess.call('cryptsetup luksClose {}'.format(self.fuuid))
            raise IOError('mount failed')

    def close(self):
        if subprocess.call('umount {}'.format(pipes.quote(self.mount_point))) != EXIT_SUCCESS:
            self.kill()
        subprocess.call('cryptsetup luksClose {}'.format(self.fuuid))

    def kill(self):
        subprocess.call('fuser -k {}'.format(pipes.quote(self.mount_point)))
        subprocess.call('umount {}'.format(pipes.quote(self.mount_point)))


class User:
    def __init__(self, username, token=None):
        self.username = username
        self.auth_token = token
        self.config_file = self.get_config_file()
        self.config = self.get_config()
        self.containers = []
        if self.config:
            self.set_containers()

    def get_config_file(self):
        home_dir = os.path.expanduser('~{}'.format(self.username))
        return os.path.join(home_dir, '.pamela.d', 'config.ini')

    def get_config(self):
        if not os.path.isfile(self.config_file):
            return None
        config = ConfigParser.ConfigParser()
        config.read(self.config_file)
        return config

    def set_containers(self):
        for section in self.config.sections():
            options = self.get_section(section)
            if 'container' in options and 'mountpoint' in options:
                container = self.get_path(options['container'])
                mount_point = self.get_path(options['mountpoint'])
                if os.path.exists(container) and os.path.isdir(mount_point):
                    self.containers.append(Container(container, mount_point))

    def expanduser(self, path):
        path_parts = path.split(os.sep)
        for i, part in enumerate(path_parts):
            if part == '~':
                path_parts[i] = '~{}'.format(self.username)
        expanded_path = os.path.expanduser(os.path.join(*path_parts))
        return expanded_path

    def get_path(self, path):
        if os.path.isabs(path):
            return path
        expanded_path = self.expanduser(path)
        if os.path.isabs(expanded_path):
            return os.path.normpath(expanded_path)
        config_file_location = os.path.dirname(self.config_file)
        return os.path.normpath(os.path.join(config_file_location, expanded_path))

    def get_section(self, section):
        containers = {}
        options = self.config.options(section)
        for option in options:
            containers[option] = self.config.get(section, option)
        return containers

    def unlock(self):
        for container in self.containers:
            container.open(self.auth_token)

    def lock(self):
        for container in self.containers:
            container.close()


def pam_sm_authenticate(pamh, flags, argv):
    try:
        username = pamh.get_user(None)
    except pamh.exception as e:
        return e.pam_result
    if username is None:
        return pamh.PAM_AUTH_ERR
    user = User(username, pamh.authtok)
    user.unlock()
    return pamh.PAM_SUCCESS


def pam_sm_end(pamh):
    try:
        username = pamh.get_user(None)
    except pamh.exception:
        return
    if username is not None:
        user = User(username)
        user.lock()


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
