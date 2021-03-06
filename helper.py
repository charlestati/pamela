#!/usr/bin/env python
# coding: utf-8

import argparse
import base64
import getpass
import os
import pwd
import subprocess

EXIT_SUCCESS = 0


def create_vault(container, mount_point, size, owner):
    if os.path.exists(container):
        raise IOError('File "{}" already exists'.format(container))

    if subprocess.call('fallocate -l {}M {}'.format(str(size), container), shell=True) != EXIT_SUCCESS:
        raise IOError('Failed to create file "{}"'.format(container))

    if not os.path.exists(mount_point):
        os.makedirs(mount_point)
    elif os.listdir(mount_point):
        os.remove(container)
        raise IOError('Mount point "{}" is not empty'.format(mount_point))

    passphrase1 = getpass.getpass('Passphrase: ')
    passphrase2 = getpass.getpass('Confirmation: ')

    if passphrase1 != passphrase2:
        os.remove(container)
        os.rmdir(mount_point)
        raise ValueError('Passphrases do not match')

    passphrase = passphrase1

    csetup = subprocess.Popen('cryptsetup luksFormat {}'.format(container), stdin=subprocess.PIPE, shell=True)
    csetup.communicate('{}\n'.format(passphrase))
    csetup.wait()

    if csetup.returncode != EXIT_SUCCESS:
        os.remove(container)
        os.rmdir(mount_point)
        raise IOError('luksFormat failed')

    fuuid = base64.b64encode(container)

    csetup = subprocess.Popen('cryptsetup luksOpen {} {}'.format(container, fuuid), stdin=subprocess.PIPE, shell=True)
    csetup.communicate('{}\n'.format(passphrase))
    csetup.wait()

    if csetup.returncode != EXIT_SUCCESS:
        os.remove(container)
        os.rmdir(mount_point)
        raise IOError('luksOpen failed')

    map_location = os.path.join('/dev/mapper', fuuid)

    if subprocess.call('mkfs.ext4 -j {}'.format(map_location), shell=True) != EXIT_SUCCESS:
        subprocess.call('cryptsetup luksClose {}'.format(fuuid), shell=True)
        os.remove(container)
        os.rmdir(mount_point)
        raise IOError('mkfs.ext4 failed')

    if subprocess.call('mount {} {}'.format(map_location, mount_point), shell=True) != EXIT_SUCCESS:
        subprocess.call('cryptsetup luksClose {}'.format(fuuid), shell=True)
        os.remove(container)
        os.rmdir(mount_point)
        raise IOError('mount failed')

    if owner != 'root':
        subprocess.call('chown {}:{} {}'.format(owner, owner, mount_point), shell=True)
        subprocess.call('chown {}:{} {}'.format(owner, owner, container), shell=True)

    subprocess.call('chmod 700 {}'.format(mount_point), shell=True)


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
