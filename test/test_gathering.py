#!/usr/bin/env python

from __future__ import unicode_literals

import io
import os
import shutil
import sys
import tempfile
import textwrap
import unittest

TEST_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(TEST_ROOT))


def _makedirs(d):
    if not os.path.isdir(d):
        os.makedirs(d)


class GatheringTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix='upload_test_')

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def _test_gathering(self, files, public_files):
        import upload
        test_tmp_dir = tempfile.mkdtemp(dir=self.tmp_dir)

        for f in files:
            path = os.path.join(test_tmp_dir, f.lstrip('!'))
            _makedirs(os.path.dirname(path))
            with open(path, 'ab') as f:
                pass  # Just open it

        for pf_dir, pf_contents_raw in public_files.items():
            pf_contents = textwrap.dedent(pf_contents_raw)
            path = os.path.join(test_tmp_dir, pf_dir, '.public')
            _makedirs(os.path.dirname(path))
            with io.open(path, 'w', encoding='utf-8') as publicf:
                publicf.write(pf_contents)

        gathered = upload.gather_local_files(test_tmp_dir)
        for f in files:
            relpath = f.lstrip('!')
            if f.startswith('!'):
                self.assertNotIn(relpath, gathered)
            else:
                self.assertIn(relpath, gathered)

    def test_basic(self):
        files = [
            'afile',
            '!bfile',
            '!cfile',
        ]
        public_files = {
            '.': '''
            afile
            cfile
            !cfile
        '''}
        self._test_gathering(files, public_files)

    def test_double_include(self):
        files = [
            'foo/afile',
            'foo/!bfile',
            '!i/a',
            '!i/b',
        ]
        public_files = {
            '.': '''
            foo
            !i
        ''', 'foo': '''
            afile
        ''', 'i': '''
            b
        '''}
        self._test_gathering(files, public_files)

    def test_extended(self):
        files = [
            'afile',
            '!comment',
            '!unmentioned',
            'adir/x',
            'adir/y',
            '!adir/z',
            'adir/subdir/subfile',
            '!adir/subdir2/subfile',
            'adir/subdir3/subsubdir/subfile',
            '!unrelateddir/ufile',
            '!unrelateddir/udir/usubfile',

            'anotherpub/f1',
            '!anotherpub/f2',
            'anotherpub/dir/f1',
            '!anotherpub/dir/f2',
            'anotherpub/dirall/f1',
            'anotherpub/dirall/f2',
            '!anotherpub/dirall/notthis',

            '!both/x',

            '!notatall/f1',
            '!notatall/f2',
            '!notatall/sub/x',
        ]
        public_files = {
            '.': '''
                afile
                #comment
                adir
                !adir/z
                !adir/subdir2
                does_not_exist
                !does_also_not_exist
                both
                !both
                !notatall
                ''',
            'anotherpub': '''
                f1
                dir/f1
                dirall
            ''',
            'anotherpub/dirall': '''
                !notthis

                # the following is redundant
                f1
            ''',
            'notatall': '''
                f1
            '''
        }
        self._test_gathering(files, public_files)

    def test_selfpub(self):
        files = [
            '!root',
            'sub/a',
            'sub/b',
            '!sub/c',
            '!forbidden/a',
        ]
        public_files = {
            '.': '''
            !forbidden
            ''',
            'sub': '''
            .
            !c
            ''',
            'forbidden': '''
            .
            '''
        }
        self._test_gathering(files, public_files)

    def test_selfpub2(self):
        files = [
            'sub/a',
            '!sub/b',
            '!sub/c',
        ]
        public_files = {
            'sub': '''
            a
            c
            !c
            '''
        }
        self._test_gathering(files, public_files)

    def test_selfpub3(self):
        files = [
            '!sub/subsub/a',
            '!sub/x',
        ]
        public_files = {
            'sub': '''
            !.
            ''',
            'sub/subsub': '''
            a
            '''
        }
        self._test_gathering(files, public_files)

    def test_dot_root(self):
        files = [
            'foo',
            '!bar',
            'sub/a/b',
            'sub/x',
        ]
        public_files = {
            '.': '''
            .
            baz
            !bar
            ''',
        }
        self._test_gathering(files, public_files)

    def test_dot_root_negative(self):
        files = [
            '!foo',
            '!sub/a/b',
            '!sub/x',
        ]
        public_files = {
            '.': '''
            .
            foo
            !.
            ''',
        }
        self._test_gathering(files, public_files)

    def test_selfunpub(self):
        files = [
            '!sub/a/b',
            '!sub/x',
        ]
        public_files = {
            '.': '''
            sub
            ''',
            'sub': '''
            !.
            '''
        }
        self._test_gathering(files, public_files)


if __name__ == '__main__':
    unittest.main()
