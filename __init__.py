# __init__.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
# flake8: noqa
#@PydevCodeAnalysisIgnore
import inspect
import os
import sys

import os.path as osp


__version__ = '1.0'

ENV = os.environ

def _init():
    """Initialize external projects by putting them into the path"""
    if __version__ == '1.0' and 'PYOXIDIZER' not in os.environ:
        sys.path.insert(1, osp.join(osp.dirname(__file__), 'ext', 'gitdb'))

#################
_init()
#################

from commands.exceptions import (
    CacheError,
    MultipleCommandError,
    CommandNotFound,
    CmdCommandError,
    CmdError,
    CommandError,
    NoSuchPathError
)
try:
    from commands.cmd import Cmd

    from commands.utils.mixins import LazyMixin
    from commands.utils.cmd_utils import (
        to_dict,
        to_slots,
        dashify,
        handle_process_output,
        expand_path,
        AutoInterrupt
    )
    from commands.utils.which import (
        which,
        whichall,
        whichgen
    )
except CmdError as exc:
    raise ImportError(f'{exc.__class__.__name__}: {exc}') from exc

__all__ = [name for name, obj in locals().items()
           if not (name.startswith('_') or inspect.ismodule(obj))]

QuietError = True