# Copyright (c) 2002-2007 ActiveState Software Inc.

# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Author:
#   Trent Mick (TrentM@ActiveState.com)
# Home:
#   http://trentm.com/projects/which/
import os
import sys
import stat
import getopt
import builtins
import collections.abc as cabc

"""Find the full path to commands.

which(command, path=None, verbose=0, exts=None)
    Return the full path to the first match of the given command on the
    path.

whichall(command, path=None, verbose=0, exts=None)
    Return a list of full paths to all matches of the given command on
    the path.

whichgen(command, path=None, verbose=0, exts=None)
    Return a generator which will yield full paths to all matches of the
    given command on the path.

By default the PATH environment variable is searched (as well as, on
Windows, the AppPaths key in the registry), but a specific 'path' list
to search may be specified as well.  On Windows, the PATHEXT environment
variable is applied as appropriate.

If "verbose" is true then a tuple of the form
    (<fullpath>, <matched-where-description>)
is returned for each match. The latter element is a textual description
of where the match was found. For example:
    from PATH element 0
    from HKLM\SOFTWARE\...\perl.exe
"""

__version_info__ = (1, 2, 0)
__version__ = ".".join(map(str, __version_info__))
__all__ = ["which", "whichall", "whichgen", "WhichError"]


class WhichError(Exception):
    pass


# internal support stuff


def _getRegisteredExecutable(exeName):
    """Windows allow application paths to be registered in the registry."""
    registered = None
    if sys.platform.startswith("win"):
        if os.path.splitext(exeName)[1].lower() != ".exe":
            exeName += ".exe"
        try:
            import winreg as _winreg
        except ImportError:
            import _winreg
        try:
            key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exeName
            value = _winreg.QueryValue(_winreg.HKEY_LOCAL_MACHINE, key)
            registered = (value, "from HKLM\\" + key)
        except _winreg.error:
            pass
        if registered and not os.path.exists(registered[0]):
            registered = None
    return registered


def _samefile(fname1, fname2):
    if sys.platform.startswith("win"):
        return os.path.normpath(os.path.normcase(fname1)) == os.path.normpath(
            os.path.normcase(fname2)
        )
    else:
        return os.path.samefile(fname1, fname2)


def _cull(potential, matches, verbose=0):
    """Cull inappropriate matches. Possible reasons:
        - a duplicate of a previous match
        - not a disk file
        - not executable (non-Windows)
    If 'potential' is approved it is returned and added to 'matches'.
    Otherwise, None is returned.
    """
    for match in matches:  # don't yield duplicates
        if _samefile(potential[0], match[0]):
            if verbose:
                sys.stderr.write("duplicate: %s (%s)\n" % potential)
            return None
    else:
        if not stat.S_ISREG(os.stat(potential[0]).st_mode):
            if verbose:
                sys.stderr.write("not a regular file: %s (%s)\n" % potential)
        elif sys.platform != "win32" and not os.access(potential[0], os.X_OK):
            if verbose:
                sys.stderr.write("no executable access: %s (%s)\n" % potential)
        else:
            matches.append(potential)
            return potential


# module API


def whichgen(command, path=None, verbose=0, exts=None):
    """Return a generator of full paths to the given command.

    "command" is a the name of the executable to search for.
    "path" is an optional alternate path list to search. The default it
        to use the PATH environment variable.
    "verbose", if true, will cause a 2-tuple to be returned for each
        match. The second element is a textual description of where the
        match was found.
    "exts" optionally allows one to specify a list of extensions to use
        instead of the standard list for this system. This can
        effectively be used as an optimization to, for example, avoid
        stat's of "foo.vbs" when searching for "foo" and you know it is
        not a VisualBasic script but ".vbs" is on PATHEXT. This option
        is only supported on Windows.

    This method returns a generator which yields tuples of the form (<path to
    command>, <where path found>).
    """
    matches = []
    if path is None:
        usingGivenPath = 0
        path = os.environ.get("PATH", "").split(os.pathsep)
        if sys.platform.startswith("win"):
            path.insert(0, os.curdir)  # implied by Windows shell
    else:
        usingGivenPath = 1

    # Windows has the concept of a list of extensions (PATHEXT env var).
    if sys.platform.startswith("win"):
        if exts is None:
            exts = builtins.__xonsh__.env["PATHEXT"]
            # If '.exe' is not in exts then obviously this is Win9x and
            # or a bogus PATHEXT, then use a reasonable default.
            for ext in exts:
                if ext.lower() == ".exe":
                    break
            else:
                exts = [".COM", ".EXE", ".BAT", ".CMD"]
        elif not isinstance(exts, cabc.Sequence):
            raise TypeError("'exts' argument must be a sequence or None")
    else:
        if exts is not None:
            raise WhichError(
                "'exts' argument is not supported on " "platform '%s'" % sys.platform
            )
        exts = []

    # File name cannot have path separators because PATH lookup does not
    # work that way.
    if os.sep in command or os.altsep and os.altsep in command:
        if os.path.exists(command):
            match = _cull((command, "explicit path given"), matches, verbose)
            yield match
    else:
        for i in range(len(path)):
            dirName = path[i]
            # On windows the dirName *could* be quoted, drop the quotes
            if (
                sys.platform.startswith("win")
                and len(dirName) >= 2
                and dirName[0] == '"'
                and dirName[-1] == '"'
            ):
                dirName = dirName[1:-1]
            for ext in [""] + exts:
                absName = os.path.abspath(
                    os.path.normpath(os.path.join(dirName, command + ext))
                )
                if os.path.isfile(absName):
                    if usingGivenPath:
                        fromWhere = "from given path element %d" % i
                    elif not sys.platform.startswith("win"):
                        fromWhere = "from PATH element %d" % i
                    elif i == 0:
                        fromWhere = "from current directory"
                    else:
                        fromWhere = "from PATH element %d" % (i - 1)
                    match = _cull((absName, fromWhere), matches, verbose)
                    if match:
                        yield match
        match = _getRegisteredExecutable(command)
        if match is not None:
            match = _cull(match, matches, verbose)
            if match:
                yield match


def which(command, path=None, verbose=0, exts=None):
    """Return the full path to the first match of the given command on
    the path.

    "command" is a the name of the executable to search for.
    "path" is an optional alternate path list to search. The default it
        to use the PATH environment variable.
    "verbose", if true, will cause a 2-tuple to be returned. The second
        element is a textual description of where the match was found.
    "exts" optionally allows one to specify a list of extensions to use
        instead of the standard list for this system. This can
        effectively be used as an optimization to, for example, avoid
        stat's of "foo.vbs" when searching for "foo" and you know it is
        not a VisualBasic script but ".vbs" is on PATHEXT. This option
        is only supported on Windows.

    If no match is found for the command, a WhichError is raised.
    """
    try:
        absName, fromWhere = next(whichgen(command, path, verbose, exts))
    except StopIteration:
        raise WhichError("Could not find '%s' on the path." % command)
    if verbose:
        return absName, fromWhere
    else:
        return absName


def whichall(command, path=None, verbose=0, exts=None):
    """Return a list of full paths to all matches of the given command
    on the path.

    "command" is a the name of the executable to search for.
    "path" is an optional alternate path list to search. The default it
        to use the PATH environment variable.
    "verbose", if true, will cause a 2-tuple to be returned for each
        match. The second element is a textual description of where the
        match was found.
    "exts" optionally allows one to specify a list of extensions to use
        instead of the standard list for this system. This can
        effectively be used as an optimization to, for example, avoid
        stat's of "foo.vbs" when searching for "foo" and you know it is
        not a VisualBasic script but ".vbs" is on PATHEXT. This option
        is only supported on Windows.
    """
    if verbose:
        cmd = list(whichgen(command, path, verbose, exts))
    else:
        cmd = list(absName for absName, _ in whichgen(command, path, verbose, exts))
    if len(cmd) == 0:
        return None
    else:
        return cmd
