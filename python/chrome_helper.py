import os, sys, subprocess
import glob
import argparse
from datetime import datetime
from uuid import uuid4
import json
from typing import Generator
from winreg import *
import shutil


def log(data):
    print("[+] %s" % (data))


def sub_log(id, data):
    print("    [{id}] {data}".format(id=id, data=data))


def warn(data):
    print("[!] %s" % (data))


class DirDoesNotExist(Exception):
    pass


class FileDoesNotExist(FileNotFoundError):
    pass


class Extension(object):
    def __init__(self, id, name, version, path):
        self.id = id
        self.name = name
        self.version = version
        self.path = path

    def __eq__(self, other):
        return self.id == other.id

    def __str__(self):
        return "{name} ({version}) [{id}]".format(name=self.name, version=self.version, id=self.id)

    def __repr__(self):
        return self.__str__()

    def to_dict(self):
        return self.__dict__


class Utils:
    def exist_or_exit(func):
        def wrapper(file_path: str):
            is_exist = func(file_path)
            if not is_exist:
                warn('Specified path [{}] doesnt exist, exiting'.format(file_path))
                sys.exit(0)
            return is_exist

        return wrapper

    @exist_or_exit
    def file_exist(file_path: str) -> bool:
        return os.path.isdir(file_path) ^ os.path.exists(file_path)

    @exist_or_exit
    def folder_exist(folder_path: str) -> bool:
        return os.path.isdir(folder_path)

    def dir_exist(dir_path: str) -> bool:
        return Utils.folder_exist(dir_path)

    def __find_files(directory: str, pattern) -> Generator:
        for root, dirs, files in os.walk(directory):
            for basename in files:
                filename = Utils.join_dir(root, basename).replace('\\', '/')
                yield filename

    def find_files(directory: str, pattern: str) -> Generator:
        glob_path = "{dir}/{pattern}".format(dir=directory, pattern=pattern).replace('\\', '/').replace('//', '/')

        # should raise error if the base dir itself doesn't exist
        if not Utils.dir_exist(directory):
            raise DirDoesNotExist

        for file in glob.glob(glob_path, recursive=True):
            yield file

    def join_dir(base_dir: str, child_dir: str):
        return os.path.join(base_dir, child_dir).replace('\\', '/')

    def find_extensions(extensions_path: str, pattern: str = None) -> Generator:
        if pattern is None:
            pattern = '/*/Extensions/*/*/manifest.json'
        for ext_file in Utils.find_files(extensions_path, pattern):
            path = ext_file.replace('\\', '/')
            manifest = json.loads(open(path, 'r').read())
            extension_name = None
            extension_id = path.split('/')[-3]
            extension_version = manifest['version']
            extension_path = "/".join(path.split('/')[:-1])

            if not manifest['name'].startswith('__MSG_'):
                extension_name = manifest['name']
            else:
                key = manifest['name'].split('__MSG_')[1].replace('__', '')
                npath = Utils.join_dir("/".join(path.split('/')[:-1]), "_locales/en/messages.json")
                if not os.path.isdir(npath) ^ os.path.exists(npath):
                    npath = Utils.join_dir("/".join(path.split('/')[:-1]), "_locales/en_US/messages.json")
                try:
                    extension_name = json.loads(open(npath, 'r').read())[key]['message']
                except KeyError:
                    pass

            if extension_name:
                extension = Extension(extension_id, extension_name, extension_version, extension_path)
                yield extension

    def print_extensions(extensions_data: list):
        for e in extensions_data:
            sub_log(extensions_data.index(e), e)

    def selected_ext_to_obj(selected_extensions: list):
        exts = []
        for i in config.selected_extensions:
            exts.append(config.available_extensions[i])
        return exts


class Config(object):
    def __init__(self):
        self.current_user = os.getlogin()
        self._extensions_path = "C:/Users/{current_user}/AppData/Local/Google/Chrome/User Data".format(
            current_user=self.current_user)
        self.description = None
        self.session_cmd_line = None
        self._base_dir = "C:/Users/{current_user}/Documents/Chrome".format(current_user=self.current_user)
        self.session_id = "{random_id}".format(random_id=str(uuid4()).replace('-', '')[0:16])
        self.session_path = Utils.join_dir(self.base_dir + '/Sessions', self.session_id)
        self._config_path = Utils.join_dir(self.base_dir, "config.json")
        self.available_extensions = []
        self.selected_extensions = []

    def load_extensions(self, force_reload: bool = False, pattern: str = None):
        self.available_extensions = []
        # If user wants to refresh the available extensions or config file doesn't exist then rebuild the info
        if force_reload or not os.path.exists(self.config_path):
            for extension in Utils.find_extensions(self.extensions_path, pattern):
                # Add only unique extensions to avoid duplicates
                if extension not in self.available_extensions:
                    self.available_extensions.append(extension)
        else:
            for extension in json.loads(open(self.config_path, 'r').read())['available_extensions']:
                self.available_extensions.append(Extension(**extension))

    def save(self):
        try:
            existing_config = json.loads(open(self.config_path, 'r').read())
        except FileNotFoundError:
            config_structure = {
                'user': '',
                'base_dir': '',
                'available_extensions': [],
                'sessions_history': [],
            }
            with open(self.config_path, 'w') as f:
                json.dump(config_structure, f, indent=4)

            existing_config = json.loads(open(self.config_path, 'r').read())

        existing_config['user'] = self.current_user
        existing_config['base_dir'] = self.base_dir
        existing_config['available_extensions'] = [e.to_dict() for e in self.available_extensions]
        existing_config['sessions_history'].append(
            {
                'id': self.session_id,
                'description': self.description,
                'session_path': self.session_path,
                'cmd': self.session_cmd_line,
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'extensions':  self.selected_extensions
            }
        )

        with open(self.config_path, 'w') as f:
            json.dump(existing_config, f, indent=4)

    def load(self):
        print("loading config from [{}]".format(self.config_path))
        # self.__dict__ = json.loads(open(self.config, 'r').read())

    @property
    def base_dir(self):
        return self._base_dir.replace('\\', '/')

    @base_dir.setter
    def base_dir(self, path: str = None):
        if os.path.isdir(path):
            log('Using specified base directory [{}]'.format(path))
        else:
            os.mkdir(path)
        self._base_dir = path
        self._config_path = Utils.join_dir(self.base_dir, "config.json")

    @property
    def extensions_path(self):
        return self._extensions_path.replace('\\', '/')

    @extensions_path.setter
    def extensions_path(self, path: str = None):
        self._extensions_path = path

    @property
    def config_path(self):
        return self._config_path.replace('\\', '/')

    @config_path.setter
    def config_path(self, file: str = None):
        if Utils.file_exist(file):
            log('Using config from path [{}]'.format(file))
            self._config_path = file

    def list_sessions(self):
        sessions = json.loads(open(self.config_path, 'r').read())['sessions_history']
        if sessions:
            print("     _______________________________________________________________")
            header = "     |    SESSION ID    |      START TIME     |     DESCRIPTION    |"
            print(header)
            print("     ---------------------------------------------------------------")
            for session in sessions:
                print('     | {} | {} | {} '.format(session['id'], session['time'], session['description']))

    def restore_session(self, session_id: str):
        sessions = json.loads(open(self.config_path, 'r').read())['sessions_history']
        for session in sessions:
            if session_id == session['id']:
                log("Restoring session with id : [{}]".format(session_id))
                log("Selected Extensions")
                self.selected_extensions = session['extensions']
                Utils.print_extensions(Utils.selected_ext_to_obj(self.selected_extensions))
                log("Starting chrome with command line : [{}]".format(session['cmd']))
                subprocess.Popen(session['cmd'], shell=False)
                return
        warn("Session with ID [{}] doesn't exist".format(session_id))


class Chrome(object):
    def __init__(self, base_path: str = None, config: Config = None):
        self.config = config
        self.proxy = None
        if base_path:
            self.base_path = base_path
        else:
            self.base_path = self.__find_executable()

    def __find_executable(self):
        try:
            aKey = OpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe")
            val = QueryValueEx(aKey, None)
            return val[0]
        except FileDoesNotExist:
            raise FileDoesNotExist

    def start_arguments(self):
        cmd_args = []
        cmd_args.append('"{}"'.format(self.base_path))
        cmd_args.append('--bwsi')
        cmd_args.append('--user-data-dir="{}"'.format(self.config.base_dir + '/Sessions'))
        cmd_args.append('--profile-directory="{}"'.format(self.config.session_id))
        if self.proxy:
            cmd_args.append('--proxy-server="{}"'.format(self.proxy))
        # chrome needs comma separated list of extension paths
        exts_path = [",".join(e.path for e in Utils.selected_ext_to_obj(self.config.selected_extensions))]
        if exts_path[0] != '':
            cmd_args.append('--load-extension="{}"'.format(",".join(exts_path)))
        cmd_args.append('--start-maximized')
        return " ".join(cmd_args)

    def set_proxy(self, proxy: str):
        self.proxy = proxy
        return self.proxy

    def start(self):
        subprocess.Popen(self.start_arguments(), shell=False)


parser = argparse.ArgumentParser(description="Simple script to run Chrome browser some specified cli arguments")
parser.add_argument("-b", "--base-dir", help="Base directory to store different session states etc", type=str)
parser.add_argument("-e", "--extensions", nargs="+", help="List of extensions to load with chrome", type=int)
parser.add_argument("-ep", "--extensions-path", help="Load extensions from custom path")
parser.add_argument("-le", "--list-extensions", action='store_true', help="Show the list of available extensions")
parser.add_argument("-re", "--refresh-extensions", action='store_true',
                    help="Refresh the list of extensions from provided path or default path")
parser.add_argument("-c", "--clear-all", action='store_true', help="Clear all sessions")
parser.add_argument("-sc", "--save-config", action='store_false',
                    help="Save current configuration. Default is set to true")
parser.add_argument("-lc", "--load-config", nargs="?", help="Load supplied configuration", type=str)
parser.add_argument("-d", "--description", nargs="?", help="Description for current session", type=str)
parser.add_argument("-pr", "--proxy", nargs="?", help="Proxy address schema, e.g. http://127.0.0.1:8080")
parser.add_argument("-ls", "--list-sessions", action='store_true', help="Show sessions history")
parser.add_argument("-rs", "--restore-session", nargs="?", help="Restore a session using session id")
args = parser.parse_args()

config = Config()
config.load_extensions()

chrome = Chrome(config=config)

if args.base_dir:
    config.base_dir = args.base_dir

if args.list_sessions:
    log("Available sessions")
    config.list_sessions()
    sys.exit(1)

if args.restore_session:
    config.restore_session(args.restore_session)
    sys.exit(1)

if args.clear_all:
    log("Please wait, clearing all sessions...")
    shutil.rmtree(config.base_dir)

if args.extensions_path and Utils.dir_exist(args.extensions_path):
    log("Reload extensions from custom extension directory [{}]".format(args.extensions_path))
    config.extensions_path = args.extensions_path
    config.load_extensions(force_reload=True,  pattern='**/manifest.json')

if args.refresh_extensions:
    log("Reloading extensions")
    config.load_extensions(force_reload=True)

if args.load_config:
    if Utils.file_exist(args.load_config):
        config.load()

if args.list_extensions:
    log("Available extensions")
    Utils.print_extensions(config.available_extensions)
    sys.exit(1)

if args.extensions:
    config.selected_extensions = args.extensions
    log("Starting with following extensions")
    Utils.print_extensions(Utils.selected_ext_to_obj(config.selected_extensions))

if args.description:
    config.description = args.description

if args.proxy:
    chrome.set_proxy(args.proxy)

if args.save_config:
    config.session_cmd_line = chrome.start_arguments()
    config.save()
    log("Config file saved to : [{}]".format(config.config_path))

log("Using base directory : [{}]".format(config.base_dir))
log("Loading extensions from : [{}]".format(config.extensions_path))
log("Current session is at : [{}]".format(config.session_path))
log("Starting chrome using command line : [{}]".format(chrome.start_arguments()))
chrome.start()
