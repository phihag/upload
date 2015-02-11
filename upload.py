#!/usr/bin/env python3

import argparse
import base64
import errno
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import sys

try:
    import urllib.parse as urllib_parse
except ImportError:
    import urllib2 as urllib_parse
try:
    import urllib.request as urllib_request
except ImportError:
    import urllib2 as urllib_request


import paramiko  # If this fails:  sudo apt-get install -y python3-paramiko


class AbstractFs(object):
    def sha512(self, fn):
        with self.open(fn, 'rb') as f:
            return _file_sha512(f)

    def sha512_or_false(self, fn):
        try:
            return self.sha512(fn)
        except IOError as ioe:
            if ioe.errno == errno.ENOENT:
                return False
            raise

    def bulk_sha512(self, files, prefix=''):
        return {
            fn: self.sha512_or_false(os.path.join(prefix, fn))
            for fn in files}

    def exists(self, path):
        try:
            self.stat(path)
        except IOError:
            return False
        return True

    def ensure_mkdir(self, dn, prefix=''):
        path = ''
        made = False
        for p in dn.split('/'):
            path = os.path.join(path, p)
            full_path = os.path.join(prefix, path)
            if not self.exists(full_path):
                self.mkdir(full_path)
                made = True
        return made


class LocalFs(AbstractFs):
    open = io.open
    stat = os.stat
    unlink = os.unlink
    mkdir = os.mkdir


class SFTPFs(AbstractFs):
    def __init__(self, client):
        self.client = client
        self.sftp = client.open_sftp()

    def open(self, fn, mode):
        return self.sftp.open(fn, mode)

    def stat(self, fn):
        return self.sftp.stat(fn)

    def unlink(self, fn):
        return self.sftp.unlink(fn)

    def mkdir(self, path):
        return self.sftp.mkdir(path)


def _encode_php(s):
    assert isinstance(s, type('')), 'Expected a string, but got %r' % s
    return "'%s'" % re.sub(r"\\|'", lambda m: '\\' + m.group(0), s)


class PHPSFTPFs(SFTPFs):
    def __init__(self, client, php_basepath, php_baseurl):
        super(PHPSFTPFs, self).__init__(client)
        self.php_basepath = php_basepath
        self.php_baseurl = php_baseurl

    def bulk_sha512(self, files, prefix=''):
        key = hashlib.sha512(os.urandom(64)).hexdigest()
        php_code = '''<?php
if ($_POST['key'] !== '%s') {
    header('HTTP/1.1 403 Forbidden');
    header('Content-Type: text/plain');
    echo 'Invalid key';
    exit(1);
}

header('Content-Type: application/json; charset=utf-8');
$files = json_decode(%s);
$res = array();
foreach ($files as $f) {
    $path = %s . $f;
    $content = @file_get_contents($path);
    if ($content === false) {
        $res[$f] = false;
    } else {
        $res[$f] = hash('sha512', $content);
    }
}
echo json_encode($res);
''' % (key, _encode_php(json.dumps(files)), _encode_php(prefix))

        php_fn = '.upload_checksums-%s.php' % (
            hashlib.sha512(os.urandom(64)).hexdigest())
        php_path = os.path.join(self.php_basepath, php_fn)
        try:
            with self.open(php_path, 'wb') as phpf:
                phpf.write(php_code.encode('utf-8'))

            php_url = '%s%s' % (self.php_baseurl, php_fn)
            data = urllib_parse.urlencode({
                'key': key,
            }).encode('utf-8')
            php_req = urllib_request.Request(php_url, data)
            json_res = urllib_request.urlopen(php_req).read().decode('utf-8')
            return json.loads(json_res)
        finally:
            self.unlink(php_path)


def _ssh_setup_host_keys(client, hostname, port):
    full_hostname, hostkeys = _ssh_get_host_keys(hostname, port)
    client._host_keys = {full_hostname: hostkeys}


def _ssh_match_hostname(hn_line, hostname):
    _HASH_MAGIC = '|1|'
    if hn_line.startswith(_HASH_MAGIC):
        salt_b64, hash_b64 = hn_line[len(_HASH_MAGIC):].split('|')
        salt_raw = base64.b64decode(salt_b64)
        assert len(salt_raw) == 20
        hash_raw = base64.b64decode(hash_b64)
        hmac_str = hmac.new(
            salt_raw, hostname.encode('ascii'),
            digestmod=hashlib.sha1).digest()
        return hmac_str == hash_raw
    else:
        hn, _, _ = hn_line.partition(',')
        return hn == hostname


def _ssh_get_host_keys(hostname, port):
    hostkeys_fn = os.path.expanduser('~/.ssh/known_hosts')
    if port != 22:
        hostname = '[%s]:%d' % (hostname, port)
    hostkeys = {}

    def _add_key(keytype, keydata):
        keybytes = paramiko.py3compat.decodebytes(keydata.encode('ascii'))
        if keytype == 'ssh-rsa':
            key = paramiko.rsakey.RSAKey(data=keybytes)
        elif keytype == 'ssh-dss':
            key = paramiko.DSSKey(data=keybytes)
        elif keytype == 'ecdsa-sha2-nistp256':
            key = paramiko.ECDSAKey(data=keybytes)
        else:
            raise NotImplementedError('Unknown keytype %s' % keytype)

        hostkeys[keytype] = key

    with io.open(hostkeys_fn, encoding='ascii') as hkf:
        for line in hkf:
            hn, _, data = line.partition(' ')
            if _ssh_match_hostname(hn, hostname):
                keytype, keydata = data.split()[:2]
                _add_key(keytype, keydata)

    if not hostkeys:
        raise KeyError(
            'Could not find key for %s in %s' % (hostname, hostkeys_fn))

    return hostname, hostkeys


def _file_sha512(f):
    with f:
        content = f.read()
        return hashlib.sha512(content).hexdigest()


def read_config(root_dir):
    config_fn = os.path.join(root_dir, '.upload_config.json')
    with io.open(config_fn, 'r', encoding='utf-8') as configf:
        return json.load(configf)


def gather_local_files(root_dir):
    root_dir = os.path.normpath(root_dir)
    public_fn = os.path.join(root_dir, '.public')
    res = set()
    never = set()
    with io.open(public_fn, encoding='utf-8') as publicf:
        for line in publicf:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('!'):
                line = line[len('!'):]
                to_add = never
            else:
                to_add = res

            # TODO line should be relative to root_dir
            if os.path.isfile(line):
                to_add.add(line)
            else:
                for cwd, _dirs, files in os.walk(line):
                    for f in files:
                        to_add.add(os.path.normpath(os.path.join(cwd, f)))

    if res & never:
        raise Exception(
            'Invalid configuration: blacklisted files (%s) in upload list' %
            ', '.join(sorted(res & never)))

    return sorted(res)


def search_root(starting_point):
    d = os.path.normpath(starting_point)
    while True:
        if os.path.exists(os.path.join(d, '.upload_config.json')):
            return d
        new_d = os.path.dirname(d)
        if d == new_d:
            raise ValueError(
                'Could not find root directory (started from %s)' %
                os.path.normpath(starting_point))
        d = new_d


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-L', '--list-local',
        action='store_true', help='List all local files to upload')
    parser.add_argument(
        '-r', '--root-dir', metavar='DIRECTORY',
        help='Root directory to sync')
    parser.add_argument(
        '-d', '--dry-run',
        action='store_true',
        help=(
            'Do not actually change anything; just print out '
            'what would be changed.'))
    args = parser.parse_args()

    root_dir = (
        args.root_dir if args.root_dir is not None
        else search_root(os.getcwd()))
    config = read_config(root_dir)
    local_fs = LocalFs()
    local_files = gather_local_files(root_dir)
    local_hashes = LocalFs().bulk_sha512(local_files)

    if args.list_local:
        for l in local_files:
            print(l)
        return 0

    for r in config['remotes']:
        port = r.get('port', 22)
        client = paramiko.SSHClient()
        _ssh_setup_host_keys(client, r['host'], port)
        client.connect(
            r['host'], port=port, username=r.get('username'))

        if r.get('php_baseurl'):
            remote_fs = PHPSFTPFs(client, r['dir'], r['php_baseurl'])
        else:
            remote_fs = SFTPFs(client)
        remote_hashes = remote_fs.bulk_sha512(local_files, r['dir'])
        created = set()
        for path, h in sorted(local_hashes.items()):
            assert path in remote_hashes
            if remote_hashes[path] == h:
                continue

            if not remote_hashes[path]:
                dirpath = os.path.dirname(path)
                if dirpath not in created:
                    created.add(dirpath)
                    made = remote_fs.ensure_mkdir(dirpath, prefix=r['dir'])
                    if made:
                        print('mkdir %s' % dirpath)

            print('Writing %s' % path)
            out_fn = os.path.join(r['dir'], path)
            with local_fs.open(path, 'rb') as readf, \
                    remote_fs.open(out_fn, 'wb') as writef:
                shutil.copyfileobj(readf, writef)

    return 0

if __name__ == '__main__':
    sys.exit(main())
