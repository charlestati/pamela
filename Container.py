import base64
import os

import subprocess


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

        return

        if owner and owner != 'root':
            subprocess.call(['chown', '-R', '{}:{}'.format(owner, owner), self.mount_point])
            subprocess.call(['chmod', '-R', '700', self.mount_point])

    def close(self):
        if subprocess.call(['umount', self.mount_point]) != 0:
            self.kill()
        else:
            subprocess.call(['cryptsetup', 'luksClose', self.fuuid])

    def kill(self):
        subprocess.call(['fuser', '-k', self.mount_point])
        self.close()
