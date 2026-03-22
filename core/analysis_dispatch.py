from pathlib import Path


def project_language_hints(source_root):
    root = Path(source_root)
    counts = {
        "java": 0,
        "kotlin": 0,
        "javascript": 0,
        "dotnet": 0,
    }
    if not root.exists():
        return counts

    patterns = {
        "java": ("*.java",),
        "kotlin": ("*.kt",),
        "javascript": ("*.js", "*.jsx", "*.ts", "*.tsx"),
        "dotnet": ("*.cs", "*.vb", "*.aspx", "*.cshtml"),
    }
    for lang, globs in patterns.items():
        total = 0
        for glob in globs:
            try:
                total += sum(1 for _ in root.rglob(glob))
            except OSError:
                continue
        counts[lang] = total
    return counts


def resolve_analysis_target(platform, alias_map, analyzers, language_hints):
    platform_key = str(platform or "").strip().lower()
    canonical = alias_map.get(platform_key, platform_key)
    runner = analyzers.get(canonical)
    if runner:
        return canonical, runner

    mobile_to_language = {
        "reactnative": "javascript",
        "ionic": "javascript",
        "cordova": "javascript",
        "nativescript": "javascript",
        "xamarin": "dotnet",
    }
    fallback = mobile_to_language.get(platform_key)
    if fallback and analyzers.get(fallback):
        return fallback, analyzers.get(fallback)

    if platform_key == "android":
        kotlin_count = int(language_hints.get("kotlin", 0) or 0)
        java_count = int(language_hints.get("java", 0) or 0)
        if kotlin_count and kotlin_count >= java_count and analyzers.get("kotlin"):
            return "kotlin", analyzers.get("kotlin")
        if java_count and analyzers.get("java"):
            return "java", analyzers.get("java")
        if kotlin_count and analyzers.get("kotlin"):
            return "kotlin", analyzers.get("kotlin")

    return canonical, None
