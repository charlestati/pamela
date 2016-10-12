#!/usr/bin/env python
# coding: utf-8

import ConfigParser
import argparse
import base64
import getpass
import os
import pwd
import subprocess

import syslog


class Container:
    def __init__(self, container, mount_point):
        self.container = container
        self.mount_point = mount_point
        self.fuuid = base64.b64encode(container)
        self.map = os.path.join('/dev/mapper', self.fuuid)

    def open(self, passphrase, owner):
        if os.path.ismount(self.mount_point):
            raise IOError('Mount point is already mounted')

        cryptsetup = subprocess.Popen(['cryptsetup', 'luksOpen', self.container, self.fuuid], stdin=subprocess.PIPE)
        cryptsetup.communicate('{}\n'.format(passphrase))
        cryptsetup.wait()

        if cryptsetup.returncode != 0:
            raise IOError('open failed')

        if subprocess.call(['mount', self.map, self.mount_point]) != 0:
            subprocess.call(['cryptsetup', 'luksClose', self.fuuid])
            raise IOError('mount failed')

        if owner and owner != 'root':
            syslog.syslog('PAM: {}'.format(owner))
            subprocess.call(['chown', '-R', '{}:{}'.format(owner, owner), self.mount_point])
            subprocess.call(['chmod', '-R', '700', self.mount_point])

    def close(self):
        if subprocess.call(['umount', self.mount_point]) != 0:
            self.kill()
        else:
            subprocess.call(['cryptsetup', 'luksClose', self.fuuid])

    def kill(self):
        subprocess.call(['fuser', '-k', self.mount_point])
        subprocess.call(['cryptsetup', 'luksClose', self.fuuid])


class User:
    def __init__(self, username, token):
        self.username = username
        self.auth_token = token
        self.config_file = self.get_config_file()
        self.config = self.get_config()
        self.containers = []
        if self.config:
            self.set_containers()

    def set_containers(self):
        for section in self.config.sections():
            options = self.get_section(section)
            if 'container' in options and 'mountpoint' in options:
                container = self.get_path(options['container'])
                mount_point = self.get_path(options['mountpoint'])
                if os.path.exists(container) and os.path.isdir(mount_point):
                    self.containers.append(Container(container, mount_point))

    def get_config_file(self):
        home_dir = os.path.expanduser('~{}'.format(self.username))
        return os.path.join(home_dir, '.pamela.d', 'config.ini')

    def get_config(self):
        if not os.path.isfile(self.config_file):
            return None
        config = ConfigParser.ConfigParser()
        config.read(self.config_file)
        return config

    def expanduser(self, path):
        path = os.path.normpath(path)
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
            return expanded_path
        config_file_location = os.path.dirname(self.config_file)
        return os.path.join(config_file_location, expanded_path)

    def get_section(self, section):
        containers = {}
        options = self.config.options(section)
        for option in options:
            containers[option] = self.config.get(section, option)
        return containers

    def unlock(self):
        for container in self.containers:
            container.open(self.auth_token, self.username)

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
        user = User(username, None)
        user.lock()


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def create_vault(container, mount_point, size, owner):
    if os.path.exists(container):
        raise IOError('File "{}" already exists'.format(container))

    if subprocess.call(['fallocate', '-l', '{}M'.format(str(size)), container]) != 0:
        raise IOError('Failed to create file "{}"'.format(container))

    if not os.path.exists(mount_point):
        os.makedirs(mount_point)
    elif os.listdir(mount_point):
        os.remove(container)
        raise IOError('Mount point "{}" is not empty'.format(mount_point))

    passphrase = getpass.getpass('Passphrase: ')

    csetup = subprocess.Popen(['cryptsetup', 'luksFormat', container], stdin=subprocess.PIPE)
    csetup.communicate('{}\n'.format(passphrase))
    csetup.wait()
    if csetup.returncode != 0:
        os.remove(container)
        os.rmdir(mount_point)
        raise IOError('cryptSetup luksFormat failed')

    fuuid = base64.b64encode(container)

    csetup = subprocess.Popen(['cryptsetup', 'luksOpen', container, fuuid], stdin=subprocess.PIPE)
    csetup.communicate('{}\n'.format(passphrase))
    csetup.wait()
    if csetup.returncode != 0:
        os.remove(container)
        os.rmdir(mount_point)
        raise IOError('cryptSetup luksOpen failed')

    map_location = os.path.join('/dev/mapper', fuuid)

    if subprocess.call(['mkfs.ext4', '-j', map_location]) != 0:
        subprocess.call(['cryptsetup', 'luksClose', fuuid])
        os.remove(container)
        os.rmdir(mount_point)
        raise IOError('mkfs.ext4 failed')

    if subprocess.call(['mount', map_location, mount_point]) != 0:
        subprocess.call(['cryptsetup', 'luksClose', fuuid])
        os.remove(container)
        os.rmdir(mount_point)
        raise IOError('mount failed')

    if owner != 'root':
        subprocess.call(['chown', '{}:{}'.format(owner, owner), mount_point])
        subprocess.call(['chown', '{}:{}'.format(owner, owner), container])

    subprocess.call(['chmod', '700', mount_point])


def main():
    parser = argparse.ArgumentParser(description='Set up a LUKS container')
    parser.add_argument('container', help='The container to hold encrypted data in')
    parser.add_argument('mountpoint', help='The mount point of the container')
    parser.add_argument('-l', '--length', default=100, type=int, help='The size of the container in megabytes [100M]')
    parser.add_argument('-u', '--user', default=pwd.getpwuid(os.getuid())[0],
                        help='The owner of the container [' + pwd.getpwuid(os.getuid())[0] + ']')

    args = parser.parse_args()

    create_vault(args.container, args.mountpoint, args.length, args.user)


if __name__ == '__main__':
    main()
