#!/usr/bin/env python
# coding: utf-8

import argparse
import base64
import getpass
import os
import pwd
import subprocess

from User import User


def pam_sm_authenticate(pamh):
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


def pam_sm_setcred(pamh):
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
