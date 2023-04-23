import os
import subprocess

import magic
import yaml
import argparse

CONFIG_PATH = 'config.yaml'


class ConfigError(Exception):
    pass


class Config:
    @staticmethod
    class SanitizerPrefixes:
        asan: list = None
        tsan: list = None
        msan: list = None

    mime_types: list = None

    def __init__(self, path='config.yaml', reset=False):
        self.config_path = path

        if reset:
            print(f'Resetting config at {path} as asked...')
            self.fix_config()
            return

        try:
            self.read_config()
        except FileNotFoundError:
            print(f'Config file is not found. Creating {path}...')
            self.fix_config()
        except yaml.YAMLError:
            raise ConfigError(f'Config file {path} couldn\'t be parsed')
        except KeyError:
            raise ConfigError(f'Config file {path} is incorrect. Use \'--reset\' flag to reset config.')

    def read_config(self):
        with open(self.config_path, 'r') as file:
            cfg = yaml.safe_load(file)

        self.SanitizerPrefixes.asan = cfg['sanitizer_prefixes']['asan']
        self.SanitizerPrefixes.tsan = cfg['sanitizer_prefixes']['tsan']
        self.SanitizerPrefixes.msan = cfg['sanitizer_prefixes']['msan']

        self.mime_types = cfg['mime-types']

    def fix_config(self):
        cfg = {
            'sanitizer_prefixes': {
                'asan': ['__asan_', '___asan_'],
                'tsan': ['__tsan_', '___tsan_'],
                'msan': ['__msan_', '___msan_']
            },
            'mime-types': [
                'application/x-executable',
                'application/x-sharedlib'
            ]
        }

        with open(self.config_path, 'w') as file:
            yaml.dump(cfg, file)

        self.read_config()


def fix_path(path):
    path = os.path.expanduser(path)
    path = os.path.abspath(path)
    return path


def check_bin(path):
    force_mention = 'Use \'--force\' flag if you are sure that\'s a bug or you know what you\'re doing.'

    # Mime type check
    mime_type = magic.from_file(path, mime=True)
    # print(f'[DEBUG] File\'s mime type: {mime_type}')
    if not any(mime_type.startswith(t) for t in config.mime_types):
        raise ValueError(f'File {path} have unacceptable mime type. '
                         f'Change config file or use \'--force\' if you know what you are doing.')

    # ELF binary or shared library check
    file_output = subprocess.check_output(['file', '-b', path])
    if not any(s in file_output.decode('utf-8') for s in ['ELF', 'shared object']):
        raise ValueError(f'File {path} is not an ELF binary or shared library. {force_mention}')

    # clang (version 14+) check
    try:
        objdump_output = subprocess.check_output(['readelf', '-p', '.comment', path])
    except subprocess.CalledProcessError:
        raise ValueError(f'Could not read version information from file {path}. {force_mention}')
    objdump_output_lines = objdump_output.decode('utf-8').splitlines()
    clang_version = None
    for line in objdump_output_lines:
        if 'clang version' in line:
            clang_version_string = line.strip().split('clang version ')[-1]
            clang_version_string = ''.join(c for c in clang_version_string if c.isdigit() or c == '.')
            clang_version = int(clang_version_string.split('.')[0])
            break
    if clang_version is None or clang_version < 14:
        raise ValueError(f'File {path} was not built with clang version 14 or higher. {force_mention}')


def check_path(path):
    if not os.path.isfile(path):
        raise ValueError(f'File {path} does not exist or not a file')

    if not os.access(path, os.X_OK):
        raise ValueError(f'File {path} is not an executable')


def get_sanitizer_type(path):
    readelf_output = subprocess.check_output(['readelf', '-s', path])
    res = set()
    for line in readelf_output.decode('utf-8').split('\n'):
        if any(pref in line for pref in config.SanitizerPrefixes.asan):
            res.add('AddressSanitizer')
        elif any(pref in line for pref in config.SanitizerPrefixes.tsan):
            res.add('ThreadSanitizer')
        elif any(pref in line for pref in config.SanitizerPrefixes.msan):
            res.add('MemorySanitizer')

    return res


def parse_args():
    parser = argparse.ArgumentParser(
        description='binaryAnalyzer is a simple script that checks for used sanitizers in a binary file.',
        usage='%(prog)s [--help (-h)] [--force (-r)] [--reset (-r)] file_path',
        add_help=True)

    parser.add_argument('file_path', help='Path to the file')

    parser.add_argument('-f', '--force', action='store_true', help='Force check of file (skip checking)')

    parser.add_argument('-r', '--reset', action='store_true', help='Reset config file')

    parser.add_argument('-c', '--config', default='config.yaml', help='Path to config file')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    config = Config(args.config, args.reset)

    # file_path = '~/CLionProjects/algo/cmake-build-asan/main'
    file_path = args.file_path
    file_path = fix_path(file_path)

    check_path(file_path)
    if not args.force:
        check_bin(file_path)

    res = get_sanitizer_type(file_path)
    if len(res) == 0:
        print(f'No sanitizers found in {file_path}')
    else:
        print(f'{len(res)} {"sanitizers" if len(res) > 1 else "sanitizer"} found in {file_path}:')
        for san in res:
            print(' -', san)
