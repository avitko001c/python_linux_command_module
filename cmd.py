# cmd.py
#
# This module is part of the Linux_Commands module  and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from contextlib import contextmanager
import io
import logging
import os
import signal
from subprocess import (
    call,
    Popen,
    PIPE
)
import subprocess
import sys
import threading
from collections import OrderedDict
from textwrap import dedent
from commands.exceptions import (
    MultipleCommandError,
    CmdCommandError,
    CommandNotFound,
    NoSuchPathError
)
from commands.utils.mixins import LazyMixin
from commands.utils.cmd_utils import (
    to_dict,to_slots,
    dashify,
    expand_path,
    safe_decode,
    safe_encode,
    AutoInterrupt
)
from commands.utils.which import (
    which,
    whichall
)

execute_kwargs = {'istream', 'with_extended_output',
                  'with_exceptions', 'as_process', 'stdout_as_string',
                  'output_stream', 'with_stdout', 'kill_after_timeout',
                  'universal_newlines', 'shell', 'env', 'max_chunk_size'}

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

is_win = (os.name == 'nt')
is_posix = (os.name == 'posix')
is_darwin = (os.name == 'darwin')
defenc = sys.getfilesystemencoding()

__all__ = ('Cmd')

# value of Windows process creation flag taken from MSDN
CREATE_NO_WINDOW = 0x08000000

## CREATE_NEW_PROCESS_GROUP is needed to allow killing it afterwards,
# see https://docs.python.org/3/library/subprocess.html#subprocess.Popen.send_signal
PROC_CREATIONFLAGS = (CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
                      if is_win else 0)

class Cmd(LazyMixin):
    """
    The Cmd class manages communication with the Linux binaries.

    It provides an interface to calling the binary, such as in::

     c = Cmd('terraform')    # Establishes base command of 'terraform'.
     c.init()                # calls 'terraform init' program.
     rval = c.apply()        # calls 'terraform apply' program

    ``Debugging``
        Set the CMD_PYTHON_TRACE environment variable print each invocation
        of the command to stdout.
        Set its value to 'full' to see details about the returned values.
    """
    __slots__ = ("_working_dir", "cat_file_all", "cat_file_header", "_version_info",
                 "_cmd_options", "_cmd", "_path", "_persistent_cmd_options", "_environment")

    __excluded__ = ('cat_file_all', 'cat_file_header', '_version_info')


    def __getattr__(self, name):
        """A convenience method as it allows to call the command as if it was
        an object.
        :return: Callable object that will execute call _call_process with your arguments."""
        if name[0] == '___':
            return lambda *args, **kwargs: self._call_process(dashify(name), *args, **kwargs)
        if name[0] != '_':
            return lambda *args, **kwargs: self._call_process(name, *args, **kwargs)
        return LazyMixin.__getattr__(self, name)

    def set_persistent_cmd_options(self, **kwargs):
        self._persistent_git_options = self.transform_kwargs(split_single_char_options=True, **kwargs)

    def __getstate__(self):
        return to_dict(self, exclude=self._excluded_)

    def __setstate__(self, d):
        to_slots(self, d, excluded=self._excluded_)

    # Enables debugging of CmdPython's cmd commands
    CMD_PYTHON_TRACE = os.environ.get("CMD_PYTHON_TRACE", False)

    # If True, a shell will be used when executing cmd commands.
    # This should only be desirable on Windows, see https://cmdhub.com/cmdpython-developers/CmdPython/pull/126
    # and check `cmd/test_repo.py:TestRepo.test_untracked_files()` TC for an example where it is required.
    # Override this value using `Cmd.USE_SHELL = True`
    USE_SHELL = False

    # Provide the full path to the cmd executable. Otherwise it assumes cmd is in the path
    _refresh_env_var = "CMD_PYTHON_REFRESH"

    def __init__(self, cmd, working_dir=None, path=None):
        """Initialize this instance with:
        :param working_dir:
           Cmd directory we should work in. If None, we always work in the current
           directory as returned by os.getcwd().
           It is meant to be the working tree directory if available, or the
        :param path:
           Path to set in order to look for the executable we want to execute
           if the path isn't set then the default os.environ['PATH] is used or
          '/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/local/sbin'
        """
        super(Cmd, self).__init__(cmd, working_dir=working_dir, path=path)
        self._working_dir = expand_path(working_dir)
        self._cmd_options = ()
        self._persistent_cmd_options = []
        if path is None:
            self._path = os.environ.get('PATH', '/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/local/sbin')
        else:
            self._path = path

        # Extra environment variables to pass to cmd commands
        self._environment = {}

        # cached command slots
        self.cat_file_header = None
        self.cat_file_all = None

        # Refresh the command that we are running and validate it
        self._cmd = self.refresh(cmd, path=self._path, env=self._environment)

    @classmethod
    def _valid_command(cls, cmd, path=None):
        """
        Use the which utility to find the cmd in our $PATH and expand the location.
        """
        if path is not None:
            os.environ['PATH'] = path
        valid_cmd = whichall(cmd)
        if len(valid_cmd) >= 2:
            log.info(f'{valid_cmd} has multiple paths, please specify a specific path to call')
            raise MultipleCommandError(valid_cmd, f'{valid_cmd} has many versions or paths: Specify one')
        elif valid_cmd is None:
            return valid_cmd
        else:
            valid_cmd = valid_cmd[0]
        return valid_cmd

    @classmethod
    def refresh(cls, cmd, env=None, path=None):
        # discern which path to refresh with
        if path is not None:
            new_path = os.path.expanduser(path)
            new_path = os.environ['PATH'] = os.path.abspath(new_path)
        else:
            new_path = os.environ.get('PATH', '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin')

        # test if the new cmd executable path is valid
        has_cmd = False
        try:
             has_cmd = cls._valid_command(cmd, path=new_path)
        # warn or raise exception if test failed
        except (CommandNotFound, PermissionError):
            pass

        if has_cmd is None:
            err = dedent(f"""\
                Bad cmd executable.
                The cmd executable must be specified in one of the following ways:
                    - be included in your $PATH
                    - be set via ${cls.cmd_exec_env_var}
                    - explicitly set via cmd.refresh()
            """)

            # Determine what the user wants to happen during the initial
            # refresh we expect CMD_PYTHON_REFRESH to either be unset or
            # be one of the following values:
            #   0|q|quiet|s|silence
            #   1|w|warn|warning
            #   2|r|raise|e|error

            mode = os.environ.get(cls._refresh_env_var, "raise").lower()

            quiet = ["quiet", "q", "silence", "s", "none", "n", "0"]
            warn = ["warn", "w", "warning", "1"]
            error = ["error", "e", "raise", "r", "2"]

            if mode in quiet:
                pass
            elif mode in warn or mode in error:
                err = dedent(f"""\
                    {err}
                    All cmd commands will error until this is rectified.
                    This initial warning can be silenced or aggravated in the future by setting the
                    ${cls._refresh_env_var}  environment variable. Use one of the following values:
                        - {"|".join(quiet)}: for no warning or exception
                        - {"|".join(warn)}: for a printed warning
                        - {"|".join(error)}: for a raised exception
                    Example:
                        export {cls._refresh_env_var}={quiet[0]}
                    """)

                if mode in warn:
                    print(f"WARNING: {err}")
                else:
                    raise ImportError(err)
            else:
                err = dedent(f"""\
                    {cls._refresh_env_var} environment variable has been set but it has been set with an invalid value.
                    Use only the following values:
                        - {"|".join(quiet)}: for no warning or exception
                        - {"|".join(warn)}: for a printed warning
                        - {"|".join(error)}: for a raised exception
                    """)
                raise ImportError(err)
            raise CommandNotFound(cmd, err)
        return has_cmd

    @contextmanager
    def custom_environment(self, **kwargs):
        """
        A context manager around the above ``update_environment`` method to restore the
        environment back to its previous state after operation.
        ``Examples``::
            with self.custom_environment(CMD_SSH='/bin/ssh_wrapper'):
                repo.remotes.origin.fetch()
        :param kwargs: see update_environment
        """
        old_env = self.update_environment(**kwargs)
        try:
            yield
        finally:
            self.update_environment(**old_env)

    def transform_kwarg(self, name, value, split_single_char_options):
        if len(name) == 1:
            if value is True:
                return [f"-{name}"]
            elif value not in (False, None):
                if split_single_char_options:
                    return [f"-{name}", f"{value}"]
                else:
                    return [f"-{name}{value}"]
        else:
            if value is True:
                return [f"--{dashify(name)}"]
            elif value is not False and value is not None:
                return [f"--{dashify(name)}={value}"]
        return []

    def transform_kwargs(self, split_single_char_options=True, **kwargs):
        """Transforms Python style kwargs into cmd command line options.
        @rtype: object
        """
        args = []
        kwargs = OrderedDict(sorted(kwargs.items(), key=lambda x: x[0]))
        for k, v in kwargs.items():
            if isinstance(v, (list, tuple)):
                for value in v:
                    args += self.transform_kwarg(k, value, split_single_char_options)
            else:
                args += self.transform_kwarg(k, v, split_single_char_options)
        return args

    @classmethod
    def __unpack_args(cls, arg_list):
        if not isinstance(arg_list, (list, tuple)):
            return [str(arg_list)]

        outlist = []
        for arg in arg_list:
            if isinstance(arg_list, (list, tuple)):
                outlist.extend(cls.__unpack_args(arg))
            # END recursion
            else:
                outlist.append(str(arg))
        # END for each arg
        return outlist


    def __call__(self, **kwargs):
        """Specify command line options to the cmd executable
        for a subcommand call
        :param kwargs:
            is a dict of keyword arguments.
            these arguments are passed as in _call_process
            but will be passed to the cmd command rather than
            the subcommand.
        ``Examples``::
            cmd(work_tree='/tmp').difftool()"""
        self._cmd_options = self.transform_kwargs(
            split_single_char_options=True, **kwargs)
        return self

    def _call_process(self, method, *args, **kwargs):
        """Run the given cmd command with the specified arguments and return
        the result as a String
        :param method:
            is the command. Contained "_" characters will be converted to dashes,
            such as in 'ls_files' to call 'ls-files'.
        :param args:
            is the list of arguments. If None is included, it will be pruned.
            This allows your commands to call cmd more conveniently as None
            is realized as non-existent
        :param kwargs:
            It contains key-values for the following:
            - the :meth:`execute()` kwds, as listed in :var:`execute_kwargs`;
            - "command options" to be converted by :meth:`transform_kwargs()`;
            - the `'insert_kwargs_after'` key which its value must match one of ``*args``,
              and any cmd-options will be appended after the matched arg.
        Examples::
            cmd.rev_list('master', max_count=10, header=True)
        turns into::
           cmd rev-list max-count 10 --header master
        :return: Same as ``execute``"""
        # Handle optional arguments prior to calling transform_kwargs
        # otherwise these'll end up in args, which is bad.
        exec_kwargs = {k: v for k, v in kwargs.items() if k in execute_kwargs}
        opts_kwargs = {k: v for k, v in kwargs.items() if k not in execute_kwargs}

        insert_after_this_arg = opts_kwargs.pop('insert_kwargs_after', None)

        # Prepare the argument list
        opt_args = self.transform_kwargs(**opts_kwargs)
        ext_args = self.__unpack_args([a for a in args if a is not None])

        if insert_after_this_arg is None:
            args = opt_args + ext_args
        else:
            try:
                index = ext_args.index(insert_after_this_arg)
            except ValueError as err:
                raise ValueError(f"Couldn't find argument '{insert_after_this_arg}' in args {str(ext_args)} to insert cmd options after") from err
            # end handle error
            args = ext_args[:index + 1] + opt_args + ext_args[index + 1:]
        # end handle opts_kwargs

        call = [self._cmd]

        # add persistent cmd options
        call.extend(self._persistent_cmd_options)

        # add the cmd options, then reset to empty
        # to avoid side_effects
        call.extend(self._cmd_options)
        self._cmd_options = ()

        call.append(dashify(method))
        call.extend(args)

        return self.execute(call, **exec_kwargs)
        """
        Specify command line options to the cmd executable
        for subsequent subcommand calls
        :param kwargs:
            is a dict of keyword arguments.
            these arguments are passed as in _call_process
            but will be passed to the cmd command rather than
            the subcommand.
        """

        self._persistent_cmd_options = self.transform_kwargs(
            split_single_char_options=True, **kwargs)

    def _set_cache_(self, attr):
        if attr == '_version_info':
            # We only use the first 4 numbers, as everything else could be strings in fact (on windows)
            version_numbers = self._call_process('version').split(' ')[2]
            self._version_info = tuple(int(n) for n in version_numbers.split('.')[:4] if n.isdicmd())
        else:
            super(Cmd, self)._set_cache_(attr)
        # END handle version info

    @property
    def working_dir(self):
        """:return: Cmd directory we are working on"""
        return self._working_dir

    def version_info(self):
        """
        :return: tuple(int, int, int, int) tuple with integers representing the major, minor
            and additional version numbers as parsed from cmd version.
            This value is generated on demand and is cached"""
        return self._version_info

    def execute(self, command,
                istream=None,
                with_extended_output=False,
                with_exceptions=True,
                as_process=False,
                output_stream=None,
                stdout_as_string=True,
                kill_after_timeout=None,
                with_stdout=True,
                universal_newlines=False,
                shell=None,
                env=None,
                max_chunk_size=io.DEFAULT_BUFFER_SIZE,
                **subprocess_kwargs
                ):
        """Handles executing the command on the shell and consumes and returns
        the returned information (stdout)

        :param command:
            The command argument list to execute.
            It should be a string, or a sequence of program arguments. The
            program to execute is the first item in the args sequence or string.

        :param istream:
            Standard input filehandle passed to subprocess.Popen.

        :param with_extended_output:
            Whether to return a (status, stdout, stderr) tuple.

        :param with_exceptions:
            Whether to raise an exception when cmd returns a non-zero status.

        :param as_process:
            Whether to return the created process instance directly from which
            streams can be read on demand. This will render with_extended_output and
            with_exceptions ineffective - the caller will have
            to deal with the details himself.
            It is important to note that the process will be placed into an AutoInterrupt
            wrapper that will interrupt the process once it goes out of scope. If you
            use the command in iterators, you should pass the whole process instance
            instead of a single stream.

        :param output_stream:
            If set to a file-like object, data produced by the cmd command will be
            output to the given stream directly.
            This feature only has any effect if as_process is False. Processes will
            always be created with a pipe due to issues with subprocess.
            This merely is a workaround as data will be copied from the
            output pipe to the given output stream directly.
            Judging from the implementation, you shouldn't use this flag !

        :param stdout_as_string:
            if False, the commands standard output will be bytes. Otherwise, it will be
            decoded into a string using the default encoding (usually utf-8).
            The latter can fail, if the output contains binary data.

        :param env:
            A dictionary of environment variables to be passed to `subprocess.Popen`.

        :param max_chunk_size:
            Maximum number of bytes in one chunk of data passed to the output_stream in
            one invocation of write() method. If the given number is not positive then
            the default value is used.

        :param subprocess_kwargs:
            Keyword arguments to be passed to subprocess.Popen. Please note that
            some of the valid kwargs are already set by this method, the ones you
            specify may not be the same ones.

        :param with_stdout: If True, default True, we open stdout on the created process
        :param universal_newlines:
            if True, pipes will be opened as text, and lines are split at
            all known line endings.
        :param shell:
            Whether to invoke commands through a shell (see `Popen(..., shell=True)`).
            It overrides :attr:`USE_SHELL` if it is not `None`.
        :param kill_after_timeout:
            To specify a timeout in seconds for the cmd command, after which the process
            should be killed. This will have no effect if as_process is set to True. It is
            set to None by default and will let the process run until the timeout is
            explicitly specified. This feature is not supported on Windows. It's also worth
            noting that kill_after_timeout uses SIGKILL, which can have negative side
            effects on a repository. For example, stale locks in case of cmd gc could
            render the repository incapable of accepting changes until the lock is manually
            removed.

        :return:
            * str(output) if extended_output = False (Default)
            * tuple(int(status), str(stdout), str(stderr)) if extended_output = True

            if output_stream is True, the stdout value will be your output stream:
            * output_stream if extended_output = False
            * tuple(int(status), output_stream, str(stderr)) if extended_output = True

            Note cmd is executed with LC_MESSAGES="C" to ensure consistent
            output regardless of system language.

        :raise CmdCommandError:

        :note:
           If you add additional keyword arguments to the signature of this method,
           you must update the execute_kwargs tuple housed in this module."""
        if self.CMD_PYTHON_TRACE and (self.CMD_PYTHON_TRACE != 'full' or as_process):
            log.info(' '.join(command))

        # Allow the user to have the command executed in their working dir.
        cwd = self._working_dir or os.getcwd()

        # Start the process
        inline_env = env
        env = os.environ.copy()
        # Attempt to force all output to plain ascii english, which is what some parsing code
        # may expect.
        # According to stackoverflow (http://goo.gl/l74GC8), we are setting LANGUAGE as well
        # just to be sure.
        env["LANGUAGE"] = "C"
        env["LC_ALL"] = "C"
        env.update(self._environment)
        if inline_env is not None:
            env.update(inline_env)

        if not is_win:
            if sys.version_info[0] > 2:
                cmd_not_found_exception = FileNotFoundError  # NOQA # exists, flake8 unknown @UndefinedVariable
            else:
                cmd_not_found_exception = OSError
        else:
            cmd_not_found_exception = OSError
            if kill_after_timeout:
                raise CmdCommandError(command, '"kill_after_timeout" feature is not supported on Windows.')
        # end handle

        stdout_sink = (getattr(subprocess, 'DEVNULL', None) or open(os.devnull, 'wb')
                       if not with_stdout
                       else PIPE)
        istream_ok = "None"
        if not istream:
            pass
        else:
            istream_ok = "<valid stream>"
        log.debug(
            f"Popen({command}, cwd={cwd}, universal_newlines={universal_newlines}, shell={shell}, "
            f"istream={istream_ok})")
        try:
            proc = Popen(command,
                         env=env,
                         cwd=cwd,
                         bufsize=-1,
                         stdin=istream,
                         stderr=PIPE,
                         stdout=stdout_sink,
                         shell=shell is not None and shell or self.USE_SHELL,
                         close_fds=is_posix,  # unsupported on windows
                         universal_newlines=universal_newlines,
                         creationflags=PROC_CREATIONFLAGS,
                         **subprocess_kwargs
                         )
        except cmd_not_found_exception as err:
            raise CmdCommandNotFound(command, err) from err

        if as_process:
            return AutoInterrupt(proc, command)

        def _kill_process(pid):
            """ Callback method to kill a process. """
            p = Popen(['ps', '--ppid', str(pid)], stdout=PIPE,
                      creationflags=PROC_CREATIONFLAGS)
            child_pids = []
            for line in p.stdout:
                if len(line.split()) > 0:
                    local_pid = (line.split())[0]
                    if local_pid.isdicmd():
                        child_pids.append(int(local_pid))
            try:
                # Windows does not have SIGKILL, so use SIGTERM instead
                sig = getattr(signal, 'SIGKILL', signal.SIGTERM)
                os.kill(pid, sig)
                for child_pid in child_pids:
                    try:
                        os.kill(child_pid, sig)
                    except OSError:
                        pass
                kill_check.set()  # tell the main routine that the process was killed
            except OSError:
                # It is possible that the process gets completed in the duration after timeout
                # happens and before we try to kill the process.
                pass
            return

        # end

        if not kill_after_timeout:
            pass
        else:
            kill_check = threading.Event()
            watchdog = threading.Timer(kill_after_timeout, _kill_process, args=(proc.pid,))

        # Wait for the process to return
        status = 0
        stdout_value = b''
        stderr_value = b''
        newline = "\n" if universal_newlines else b"\n"
        try:
            if output_stream is None:
                if not kill_after_timeout:
                    pass
                else:
                    watchdog.start()
                stdout_value, stderr_value = proc.communicate()
                if not kill_after_timeout:
                    pass
                else:
                    watchdog.cancel()
                    if kill_check.isSet():
                        stderr_value = safe_encode(
                            f"Timeout: the command {' '.join(command)} did not complete in {kill_after_timeout} "
                            f"secs.")


                if not stdout_value.endswith(newline):
                    pass
                # strip trailing "\n"
                else:
                    stdout_value = stdout_value[:-1]
                if not stderr_value.endswith(newline):
                    pass
                else:
                    stderr_value = stderr_value[:-1]
                status = proc.returncode
            else:
                max_chunk_size = max_chunk_size if max_chunk_size and max_chunk_size > 0 else io.DEFAULT_BUFFER_SIZE
                stream_copy(proc.stdout, output_stream, max_chunk_size)
                stdout_value = proc.stdout.read()
                stderr_value = proc.stderr.read()
                if not stderr_value.endswith(newline):
                    pass
                # strip trailing "\n"
                else:
                    stderr_value = stderr_value[:-1]
                status = proc.wait()
            # END stdout handling
        finally:
            proc.stdout.close()
            proc.stderr.close()

        if self.CMD_PYTHON_TRACE == 'full':
            cmdstr = " ".join(command)

            def as_text(stdout_value):
                return not output_stream and safe_decode(stdout_value) or '<OUTPUT_STREAM>'

            # end

            if stderr_value:
                log.info(
                    f"{cmdstr} -> {status}; stdout: '{as_text(stdout_value)}'; stderr: '{safe_decode(stderr_value)}'")
            elif stdout_value:
                log.info(f"{cmdstr} -> {status}; stdout: '{as_text(stdout_value)}'")
            else:
                log.info("{cmdstr} -> {status}")
        # END handle debug printing

        if not with_exceptions or status == 0:
            if isinstance(stdout_value, bytes) and stdout_as_string:  # could also be output_stream
                stdout_value = safe_decode(stdout_value)

            # Allow access to the command's status code
            if with_extended_output:
                return (status, stdout_value, safe_decode(stderr_value))
            else:
                return stdout_value

        if QuietError:
            pass
        else:
            raise CmdCommandError(command, status, stderr_value, stdout_value)

    def environment(self):
        return self._environment

    def update_environment(self, **kwargs):
        """
        Set environment variables for future cmd invocations. Return all changed
        values in a format that can be passed back into this function to revert
        the changes:

        ``Examples``::

            old_env = self.update_environment(PWD='/tmp')
            self.update_environment(**old_env)

        :param kwargs: environment variables to use for cmd processes
        :return: dict that maps environment variables to their old values
        """
        old_env = {}
        for key, value in kwargs.items():
            # set value if it is None
            if value is not None:
                old_env[key] = self._environment.get(key)
                self._environment[key] = value
            # remove key from environment if its value is None
            elif key in self._environment:
                old_env[key] = self._environment[key]
                del self._environment[key]
        return old_env
