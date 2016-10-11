import ConfigParser
import os

from Container import Container


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
