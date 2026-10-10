"""Optional progress events for saved-result report renderers."""


def report_progress(callback, phase, message, completed=None, total=None, unit=None):
    if callback is not None:
        callback(dict(phase=phase, message=message, completed=completed, total=total, unit=unit))
