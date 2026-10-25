"""Shared display preferences; serialized timestamps remain ISO 8601."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DATE_FORMATS = {"MM-DD-YYYY": "%m-%d-%Y", "DD-MM-YYYY": "%d-%m-%Y", "YYYY-MM-DD": "%Y-%m-%d"}
TIME_FORMATS = {"24h": "%H:%M:%S", "12h": "%I:%M:%S %p"}
_snapshot = None


def validate_display(value):
    result = {"date_format": value.get("date_format", "MM-DD-YYYY"),
              "time_format": value.get("time_format", "24h"),
              "timezone": value.get("timezone") or "UTC"}
    if result["date_format"] not in DATE_FORMATS:
        raise ValueError("Unsupported date format")
    if result["time_format"] not in TIME_FORMATS:
        raise ValueError("Unsupported time format")
    try:
        ZoneInfo(result["timezone"])
    except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
        raise ValueError("Use a valid IANA time zone, for example Pacific/Auckland") from exc
    return result


def configure_display(value):
    global _snapshot
    _snapshot = validate_display(value)
    return dict(_snapshot)


def display_preferences():
    if _snapshot is not None:
        return dict(_snapshot)
    from utils.config_utils import get_display_config
    return get_display_config()


def format_datetime(value=None, *, date_only=False, preferences=None):
    prefs = validate_display(preferences) if preferences is not None else display_preferences()
    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    # Historical naive timestamps were recorded in server local time.
    if value.tzinfo is None:
        value = value.astimezone()
    value = value.astimezone(ZoneInfo(prefs["timezone"]))
    pattern = DATE_FORMATS[prefs["date_format"]]
    if not date_only:
        pattern += " " + TIME_FORMATS[prefs["time_format"]] + " %Z"
    return value.strftime(pattern)


def save_display_preferences(value):
    from ruamel.yaml import YAML
    import state.runtime_state as runtime
    yaml = YAML()
    yaml.preserve_quotes = True
    with open(runtime.toolConfig) as stream:
        config = yaml.load(stream)
    prefs = validate_display(value)
    config["display"] = prefs
    with open(runtime.toolConfig, "w") as stream:
        yaml.dump(config, stream)
    return prefs


def presentation_dates(value):
    """Copy a display context, formatting only known timestamp fields."""
    timestamp_keys = {'created_at', 'generated_at', 'modified_at', 'updated_at', 'started_at', 'completed_at', 'start_timestamp', 'end_timestamp', 'scan_start_time', 'scan_end_time', 'recon_start_time', 'recon_end_time'}
    if isinstance(value, dict):
        return {key: format_datetime(item) if key in timestamp_keys and isinstance(item, (str, datetime)) and item else presentation_dates(item) for key, item in value.items()}
    if isinstance(value, list):
        return [presentation_dates(item) for item in value]
    return value
