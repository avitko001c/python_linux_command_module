# exceptions.py
#
# This module is part of linux_commands/commands module and is released under
# the GNU Public License: https://en.wikipedia.org/wiki/GNU_General_Public_License

""" Module containing all exceptions thrown throughout the cmd package, """

from commands.utils.cmd_utils import safe_decode

class QuietError():
    """ Error class that will just be Quiet """
    pass

class CmdError(Exception):
    """ Base class for all package exceptions """

class NoSuchPathError(CmdError, OSError):
    """ Thrown if a path could not be access by the system. """

class MultipleCommandError(CmdError):
    """ Thrown if there are Multiple paths for a command """
    def __init__(self, command, paths, status=None, stderr=None, stdout=None):
        if not isinstance(path, (tuple, list)):
            path = path.split()
        self.path = path

    def __str__(self):
        return (self.msg + f"\n cmdline {self._cmd}")

class CommandError(CmdError):
    """
    Base class for exceptions thrown at every stage of `Popen()` execution.

    :param command:
        A non-empty list of argv comprising the command-line.
    """

    #: A unicode print-format with 2 `%s for `<cmdline>` and the rest,
    #:  e.g.
    #:     "'%s' failed%s"
    _msg = "Cmd('%s') failed%s"

    def __init__(self, command, status=None, stderr=None, stdout=None):
        if not isinstance(command, (tuple, list)):
            command = command.split()
        self.command = command
        self.status = status
        if status:
            if isinstance(status, Exception):
                status = "%s('%s')" % (type(status).__name__, safe_decode(str(status)))
            else:
                try:
                    status = 'exit code(%s)' % int(status)
                except (ValueError, TypeError):
                    s = safe_decode(str(status))
                    status = "'%s'" % s if isinstance(status, str) else s

        self._cmd = safe_decode(command[0])
        self._cmdline = ' '.join(safe_decode(i) for i in command)
        self._cause = status and " due to: %s" % status or "!"
        self.stdout = stdout and "\n  stdout: '%s'" % safe_decode(stdout) or ''
        self.stderr = stderr and "\n  stderr: '%s'" % safe_decode(stderr) or ''

    def __str__(self):
        return (self._msg + "\n  cmdline: %s%s%s") % (
            self._cmd, self._cause, self._cmdline, self.stdout, self.stderr)


class CommandNotFound(CommandError):
    """Thrown if we cannot find the `cmd` executable in the PATH or at the path given by
    the GIT_PYTHON_GIT_EXECUTABLE environment variable"""
    def __init__(self, command, cause):
        super(CmdCommandNotFound, self).__init__(command, cause)
        self._msg = "Cmd('%s') not found%s"

class CmdCommandError(CommandError):
    """ Thrown if execution of the cmd command fails with non-zero status code. """

    def __init__(self, command, status, stderr=None, stdout=None):
        super(CmdCommandError, self).__init__(command, status, stderr, stdout)


class CacheError(CmdError):

    """Base for all errors related to the cmd index, which is called cache internally"""
