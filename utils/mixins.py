# mixins.py
#
# This module is part of linux_commands/commands module and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

class LazyMixin(object):

    """
    Base class providing an interface to lazily retrieve attribute values upon
    first access. If slots are used, memory will only be reserved once the attribute
    is actually accessed and retrieved the first time. All future accesses will
    return the cached value as stored in the Instance's dict or slot.
    """

    __slots__ = tuple()

    def __init__(self):
        """
        This method should be overridden in the derived class. It should set self, do nothing,
        do everything, or call your subclasses.
        """
        pass

    def __getattr__(self, attr):
        """
        Whenever an attribute is requested that we do not know, we allow it
        to be created and set. Next time the same attribute is reqeusted, it is simply
        returned from our dict/slots. 
        """
        self._set_cache_(attr)
        # will raise in case the cache was not created
        return object.__getattribute__(self, attr)

    def _set_cache_(self, attr):
        """
        This method should be overridden in the derived class.
        It should check whether the attribute named by attr can be created
        and cached. Do nothing if you do not know the attribute or call your subclass

        The derived class may create as many additional attributes as it deems
        necessary in case a command returns more information than represented
        in the single attribute.
        """
        pass
