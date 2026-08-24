# Standard libraries
import json
from pathlib import Path

# Third-party libraries
import yaml
from jinja2 import Template

# Local application imports
import state.runtime_state as state
import utils.file_utils as futils


# Assumed number of hours to review one file
# hours_per_file = 0.25



# Preferred display order; any category recon ever adds beyond these is
# still estimated (via the fallback in get_category_effort_days) and just
# gets appended after this list instead of silently contributing nothing.
_CATEGORY_DISPLAY_ORDER = [
    "Backend", "Frontend", "Mobile Platforms", "Database",
    "Shell Scripts", "Infrastructure", "System Programs",
]


def effort_estimator(json_file_path):
    """
    Estimates the effort in days for every recon-detected technology
    category (Backend, Frontend, Mobile Platforms, Database, Shell
    Scripts, Infrastructure, System Programs) based on file counts, and
    outputs an HTML report.

    Parameters:
        json_file_path (str): Path to the JSON file containing recon
                              category/file-count data.

    Returns:
        None: The function writes an HTML report summarizing the effort estimation.
    """

    # Load data from JSON file
    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)

    # recon_summary.json wraps categories under a "categories" key;
    # fall back to top-level for backward compatibility.
    categories = data.get("categories", data)

    ordered_categories = [c for c in _CATEGORY_DISPLAY_ORDER if c in categories]
    ordered_categories += [c for c in categories if c not in _CATEGORY_DISPLAY_ORDER]

    total_days_min = 0.0
    total_days_max = 0.0
    category_sections = []

    for category in ordered_categories:
        category_data = categories.get(category) or {}
        info = []
        cat_min = 0.0
        cat_max = 0.0

        for language, language_data in category_data.items():
            total_files = language_data.get("totalFiles", 0)
            if category.lower() in ('backend', 'frontend'):
                effort_days = get_effort_days(total_files, category.lower())
            else:
                effort_days = get_category_effort_days(total_files, category)

            cat_min += effort_days[0]
            cat_max += effort_days[1]
            info.append({
                'language': language,
                'total_files': total_files,
                'effort_days_min': effort_days[0],
                'effort_days_max': effort_days[1],
            })

        total_days_min += cat_min
        total_days_max += cat_max
        category_sections.append({
            'title': category,
            'info': info,
            'total_min': round(cat_min, 2),
            'total_max': round(cat_max, 2),
        })

    raw_days_min = total_days_min
    raw_days_max = total_days_max

    efficiency_factor, buffer_days = _load_estimation_adjustments()
    # efficiency_factor is a percentage reduction applied to the raw
    # estimate (reviewer tooling/experience makes review faster than the
    # calibrated baseline); buffer_days is a flat contingency added to the
    # upper bound only, to account for unknowns the file-count model can't see.
    adjusted_days_min = round(total_days_min * (1 - efficiency_factor / 100), 2)
    adjusted_days_max = round(total_days_max * (1 - efficiency_factor / 100) + buffer_days, 2)

    # Backward-compatible aliases for the two categories the template/report
    # consumers originally keyed on directly.
    backend_info = next((s['info'] for s in category_sections if s['title'] == 'Backend'), [])
    frontend_info = next((s['info'] for s in category_sections if s['title'] == 'Frontend'), [])

    # A dictionary to encapsulate the report data
    report_data = {
        'backend_data': backend_info,
        'frontend_data': frontend_info,
        'category_sections': category_sections,
        'total_days_min': adjusted_days_min,
        'total_days_max': adjusted_days_max,
        'raw_days_min': round(raw_days_min, 2),
        'raw_days_max': round(raw_days_max, 2),
        'efficiency_factor': efficiency_factor,
        'buffer_days': buffer_days,
    }

    # Generate HTML report
    generate_report(report_data)



def generate_report(report_data):
    """
    Generates an HTML report for effort estimation by populating a Jinja2 template.

    Parameters:
        report_data (dict): Contains effort data for frontend, backend, 
                            and total days estimate (min and max).

    Returns:
        None: Writes the rendered HTML report to a predefined file path.
    """

    # Load the template HTML content from the file
    with open(state.estimation_template, 'r') as template_file:
        template_html = template_file.read()

    # Render the Jinja2 template with the data
    template = Template(template_html)
    rendered_html = template.render(**report_data)

    # Save the rendered HTML report to the current per-project/run path.
    # Read state.estimation_Fpath at call time (not at import time) so a
    # prior state.configure_project_paths() call is respected.
    estimation_Fpath = state.estimation_Fpath
    Path(estimation_Fpath).parent.mkdir(parents=True, exist_ok=True)
    with open(estimation_Fpath, 'w') as report_file:
        report_file.write(rendered_html)

    print("     [-] Effort estimation report: " + str(futils.get_reports_root_path(estimation_Fpath)))



def get_effort_days(file_count, tech):
    """
    Estimates effort days based on the file count and technology type.

    Parameters:
        file_count (int): Number of files to estimate effort for.
        tech (str): Technology type ('backend' or 'frontend').

    Returns:
        tuple: Effort range (min, max days) for the given file count.

    Raises:
        ValueError: If 'file_count' is not an integer or 'tech' is invalid.
    """

    try:
        file_count = int(file_count)
    except (TypeError, ValueError):
        raise ValueError("Invalid value for 'file_count'. It must be an integer.")

    if not isinstance(tech, str) or tech.lower() not in ['backend', 'frontend']:
        raise ValueError("Invalid value for 'tech'. It must be either 'backend' or 'frontend'.")

    if file_count <= 0:
        return (0, 0)

    # Load data from the config file
    with open(state.estimateConfig, 'r') as config_file:
        config_data = yaml.safe_load(config_file)

    # Determine the corresponding data for the specified tech (backend or frontend)
    tech_data = config_data['estimation_days_ranges'][f'{tech}_data']

    for data in tech_data:
        lower_bound, upper_bound = data['files_range']
        
        if lower_bound <= file_count <= (upper_bound if upper_bound != 999999 else 999999):
            if upper_bound == 999999:
                print("Maximum range exceeded!")
            return data['effort_range']
        
    raise ValueError(f"No effort range found for file count {file_count} and tech {tech}.")


def get_category_effort_days(file_count, category):
    """
    Estimates effort days for a recon category that isn't Backend/Frontend
    (Mobile Platforms, Database, Shell Scripts, Infrastructure, System
    Programs), by scaling one of the two calibrated backend/frontend
    curves via config/estimate.yaml's category_effort_multipliers.

    Falls back to the backend curve at 1.0x for any category with no
    configured multiplier, rather than raising or silently returning 0 -
    a future 8th recon category should still get *some* estimate.
    """
    try:
        file_count = int(file_count)
    except (TypeError, ValueError):
        raise ValueError("Invalid value for 'file_count'. It must be an integer.")

    if file_count <= 0:
        return (0, 0)

    with open(state.estimateConfig, 'r') as config_file:
        config_data = yaml.safe_load(config_file)

    multipliers = config_data.get('category_effort_multipliers', {}) or {}
    settings = multipliers.get(category) or {"base": "backend_data", "multiplier": 1.0}
    base_key = settings.get("base", "backend_data")
    multiplier = float(settings.get("multiplier", 1.0))

    base_tech = "frontend" if base_key == "frontend_data" else "backend"
    base_min, base_max = get_effort_days(file_count, base_tech)
    return (round(base_min * multiplier, 2), round(base_max * multiplier, 2))


def _load_estimation_adjustments():
    """Read efficiency_factor (%) and buffer (days) from config/estimate.yaml.
    Previously declared in config and exposed via the Settings API/UI but
    never actually applied to the computed estimate - defaults preserve
    the original unadjusted behavior if the keys are missing."""
    try:
        with open(state.estimateConfig, 'r') as config_file:
            config_data = yaml.safe_load(config_file) or {}
    except OSError:
        return 0.0, 0.0
    efficiency_factor = float(config_data.get('efficiency_factor', 0) or 0)
    buffer_days = float(config_data.get('buffer', 0) or 0)
    return efficiency_factor, buffer_days


# Backward-compatible alias for legacy callers.
effortEstimator = effort_estimator

