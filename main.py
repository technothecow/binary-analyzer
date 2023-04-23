import os
import subprocess
import yaml
import argparse

CONFIG_PATH='config.yaml'

try:
    with open(CONFIG_PATH, 'r') as file:
        config = yaml.safe_load(file)
except FileNotFoundError:
    config = {
        'asan': ['__asan_', '___asan_'],
        'tsan': ['__tsan', '___tsan'],
        'msan': ['__msan', '___msan']
    }
    with open(CONFIG_PATH, 'w') as file:
        yaml.dump(config, file)

asan_prefixes = config['asan']
tsan_prefixes = config['tsan']
msan_prefixes = config['msan']


def get_sanitizer_type(file_path):
    file_path = os.path.expanduser(file_path)
    print(file_path)
    readelf_output = subprocess.check_output(['readelf', '-s', file_path])
    res = set()
    for line in readelf_output.decode('utf-8').split('\n'):
        if '__asan_' in line or '___asan_' in line:
            res.add('AddressSanitizer')
        elif '__tsan_' in line or '___tsan_' in line:
            res.add('ThreadSanitizer')
        elif '__msan_' in line or '___msan_' in line:
            res.add('MemorySanitizer')

    return res if len(res) > 0 else 'No sanitizer found'


if __name__ == '__main__':
    # sanitizer_type = get_sanitizer_type('~/CLionProjects/algo/cmake-build-asan/main')
    # print(sanitizer_type)
    print(asan_prefixes)
