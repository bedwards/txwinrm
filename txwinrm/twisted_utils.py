##############################################################################
#
# Copyright (C) Zenoss, Inc. 2016, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

from twisted.internet import defer, error, reactor
from twisted.python import failure
from twisted.web._newclient import ResponseNeverReceived


def with_timeout(fn,
                 args=None,
                 kwargs=None,
                 seconds=None,
                 exception_class=error.TimeoutError):
    """Execute asynchronous function fn(*args, **kwargs) with a timeout."""
    return add_timeout(
        deferred=fn(*args, **kwargs),
        seconds=seconds,
        exception_class=exception_class)


def add_timeout(deferred, seconds, exception_class=error.TimeoutError):
    """Return new Deferred that will errback exception_class after seconds."""
    deferred_with_timeout = defer.Deferred()

    def fire_timeout():
        deferred.cancel()

        if not deferred_with_timeout.called:
            deferred_with_timeout.errback(exception_class())

    delayed_timeout = reactor.callLater(seconds, fire_timeout)

    def handle_result(result):
        is_failure = isinstance(result, failure.Failure)
        is_cancelled = is_failure and isinstance(result.value,
                                                 defer.CancelledError)

        # With twisted.web._newclient, errors may be wrapped in a
        # 'ResponseNeverReceived', including CancelledError.  If it is,
        # set is_cancelled.
        if is_failure and isinstance(result.value, ResponseNeverReceived):
            if any([isinstance(x, failure.Failure) and
                    isinstance(x.value, defer.CancelledError)
                    for x in result.value.reasons]):
                is_cancelled = True

        if delayed_timeout.active():
            # Cancel the timeout since a result came before it fired.
            delayed_timeout.cancel()
        elif is_cancelled:
            # Don't propagate cancellations that we caused.
            return

        # Propagate remaining results.
        if is_failure:
            deferred_with_timeout.errback(result)
        else:
            deferred_with_timeout.callback(result)

    deferred.addBoth(handle_result)

    return deferred_with_timeout
