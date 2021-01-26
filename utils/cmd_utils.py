# cmd_utils.py
#
# This module is part of linux_commands/commands module and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import binascii
import os
import mmap
import sys
import time
import errno

from io import BytesIO

from smmap import (
    StaticWindowMapManager,
    SlidingWindowMapManager,
    SlidingWindowMapBuffer
)

defenc = sys.getfilesystemencoding()
qsort = lambda L: [] if L==[] else qsort([x for x in L[1:] if x< L[0]]) + L[0:1] + qsort([x for x in L[1:] if x>=L[0]])

def expand_path(p, expand_vars=True):
    try:
        p = osp.expanduser(p)
        if expand_vars:
            p = osp.expandvars(p)
        return osp.normpath(osp.abspath(p))
    except Exception:
        return None

def handle_process_output(process, stdout_handler, stderr_handler,
                          finalizer=None, decode_streams=True):
    """Registers for notifications to learn that process output is ready to read, and dispatches lines to
    the respective line handlers.
    This function returns once the finalizer returns

    :return: result of finalizer
    :param process: subprocess.Popen instance
    :param stdout_handler: f(stdout_line_string), or None
    :param stderr_handler: f(stderr_line_string), or None
    :param finalizer: f(proc) - wait for proc to finish
    :param decode_streams:
        Assume stdout/stderr streams are binary and decode them before pushing \
        their contents to handlers.
        Set it to False if `universal_newline == True` (then streams are in text-mode)
        or if decoding must happen later (i.e. for Diffs).
    """
    # Use 2 "pump" threads and wait for both to finish.
    def pump_stream(cmdline, name, stream, is_decode, handler):
        try:
            for line in stream:
                if handler:
                    if is_decode:
                        line = line.decode(defenc)
                    handler(line)
        except Exception as ex:
            log.error(f"Pumping {name} of cmd({cmdline}) failed due to: {ex}")
            raise CommandError([f'<{name}-pump>'] + cmdline, ex) from ex
        finally:
            stream.close()

    cmdline = getattr(process, 'args', '')  # PY3+ only
    if not isinstance(cmdline, (tuple, list)):
        cmdline = cmdline.split()

    pumps = []
    if process.stdout:
        pumps.append(('stdout', process.stdout, stdout_handler))
    if process.stderr:
        pumps.append(('stderr', process.stderr, stderr_handler))

    threads = []

    for name, stream, handler in pumps:
        t = threading.Thread(target=pump_stream,
                             args=(cmdline, name, stream, decode_streams, handler))
        t.setDaemon(True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if finalizer:
        return finalizer(process)

def dashify(string):
    if '___' in string:
        return string.replace('___', '--')
    return string.replace('_', '-')


def to_dict(self, exclude=()):
    return {s: getattr(self, s) for s in self.__slots__ if s not in exclude}


def to_slots(self, d, excluded=()):
    for k, v in d.items():
        setattr(self, k, v)
    for k in excluded:
        setattr(self, k, None)


class AutoInterrupt(object):
    """Kill/Interrupt the stored process instance once this instance goes out of scope. It is
    used to prevent processes piling up in case iterators stop reading.
    Besides all attributes are wired through to the contained process object.
    The wait method was overridden to perform automatic status code checking
    and possibly raise.
    """

    __slots__ = ("proc", "args")

    def __init__(self, proc, args):
        self.proc = proc
        self.args = args

    def __del__(self):
        if self.proc is None:
            return

        proc = self.proc
        self.proc = None
        if proc.stdin:
            proc.stdin.close()
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

        # did the process finish already so we have a return code ?
        try:
            if proc.poll() is not None:
                return
        except OSError as ex:
            log.info("Ignored error after process had died: %r", ex)

        # can be that nothing really exists anymore ...
        if os is None or getattr(os, 'kill', None) is None:
            return

        # try to kill it
        try:
            proc.terminate()
            proc.wait()    # ensure process goes away
        except OSError as ex:
            log.info("Ignored error after process had died: %r", ex)
        except AttributeError:
            # try windows
            # for some reason, providing None for stdout/stderr still prints something. This is why
            # we simply use the shell and redirect to nul. Its slower than CreateProcess, question
            # is whether we really want to see all these messages. Its annoying no matter what.
            if is_win:
                call(("TASKKILL /F /T /PID %s 2>nul 1>nul" % str(proc.pid)), shell=True)
        # END exception handling

    def __getattr__(self, attr):
        return getattr(self.proc, attr)

    def wait(self, stderr=b''):  # TODO: Bad choice to mimic `proc.wait()` but with different args.
        """
        Wait for the process and return its status code.
        :param stderr: Previously read value of stderr, in case stderr is already closed.
        :warn: may deadlock if output or error pipes are used and not handled separately.
        :raise GitCommandError: if the return status is not 0
        """
        if stderr is None:
            stderr = b''
        stderr = force_bytes(data=stderr, encoding='utf-8')

        status = self.proc.wait()

        def read_all_from_possibly_closed_stream(stream):
            try:
                return stderr + force_bytes(stream.read())
            except ValueError:
                return stderr or b''

        if status != 0:
            errstr = read_all_from_possibly_closed_stream(self.proc.stderr)
            log.debug('AutoInterrupt wait stderr: %r' % (errstr,))
            raise GitCommandError(self.args, status, errstr)
        # END status handling
        return status

def safe_decode(s):
    """Safely decodes a binary string to unicode"""
    if isinstance(s, str):
        return s
    elif isinstance(s, bytes):
        return s.decode(defenc, 'surrogateescape')
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))


def safe_encode(s):
    """Safely decodes a binary string to unicode"""
    if isinstance(s, str):
        return s.encode(defenc)
    elif isinstance(s, bytes):
        return s
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))
