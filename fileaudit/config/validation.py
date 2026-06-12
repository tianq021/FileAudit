from __future__ import annotations


def validate_detection_skip_conflicts(
    *,
    detect_suspicious_extensions: bool = False,
    detect_double_extensions: bool = False,
    detect_hidden_files: bool,
    skip_hidden_files: bool,
    detect_big_files: bool,
    big_file_threshold_mb: int,
    skip_large_files_mb: int,
    suspicious_extensions: tuple[str, ...] | list[str] = (),
    whitelisted_extensions: tuple[str, ...] | list[str] = (),
    skip_extensions: tuple[str, ...] | list[str] = (),
    ignored_dirs: tuple[str, ...] | list[str] = (),
    skip_dirs: tuple[str, ...] | list[str] = (),
    skip_path_keywords: tuple[str, ...] | list[str] = (),
    include_only_matched: bool = False,
    include_extensions: tuple[str, ...] | list[str] = (),
    include_name_keywords: tuple[str, ...] | list[str] = (),
    include_path_keywords: tuple[str, ...] | list[str] = (),
    include_file_types: tuple[str, ...] | list[str] = (),
) -> None:
    conflicts = []
    suspicious = _normalized_set(suspicious_extensions)
    whitelisted = _normalized_set(whitelisted_extensions)
    skipped_extensions = _normalized_set(skip_extensions)
    skipped_dir_names = _normalized_set(ignored_dirs) | _normalized_set(skip_dirs)
    skipped_path_keywords = _normalized_set(skip_path_keywords)
    included_path_keywords = _normalized_set(include_path_keywords)

    if include_only_matched and not any(
        (include_extensions, include_name_keywords, include_path_keywords, include_file_types)
    ):
        conflicts.append("开启“只扫描匹配规则”时，至少要填写一种只扫描规则，否则所有文件都会被过滤。")

    extension_detection_enabled = detect_suspicious_extensions or detect_double_extensions
    whitelisted_suspicious = suspicious & whitelisted
    if extension_detection_enabled and whitelisted_suspicious:
        conflicts.append(
            "白名单扩展名会覆盖可疑/双扩展名检测，请不要同时放在可疑扩展名和白名单扩展名中："
            f"{_format_items(whitelisted_suspicious)}。"
        )

    skipped_suspicious = suspicious & skipped_extensions
    if extension_detection_enabled and skipped_suspicious:
        conflicts.append(
            "跳过扩展名会让对应文件不进入风险检测，请不要同时放在可疑扩展名和跳过扩展名中："
            f"{_format_items(skipped_suspicious)}。"
        )

    if detect_hidden_files and skip_hidden_files:
        conflicts.append("不能同时开启“检测隐藏文件”和“跳过隐藏文件”，否则隐藏文件会先被跳过，无法被标记为风险。")
    if detect_big_files and skip_large_files_mb > 0 and skip_large_files_mb <= big_file_threshold_mb:
        conflicts.append(
            "“跳过大文件阈值”不能小于或等于“大文件阈值”，否则达到大文件阈值的文件会先被跳过，无法被标记为风险。"
        )

    if include_only_matched and included_path_keywords:
        blocked_dir_keywords = _matching_keywords(included_path_keywords, skipped_dir_names)
        if blocked_dir_keywords:
            conflicts.append(
                "目录跳过规则会早于只扫描规则生效，请不要同时把只扫描路径关键词指向已忽略/跳过的目录："
                f"{_format_items(blocked_dir_keywords)}。"
            )

        blocked_path_keywords = _matching_keywords(included_path_keywords, skipped_path_keywords)
        if blocked_path_keywords:
            conflicts.append(
                "跳过路径关键词会早于只扫描路径关键词生效，请不要在两处填写相同或互相包含的关键词："
                f"{_format_items(blocked_path_keywords)}。"
            )

    if conflicts:
        raise ValueError("\n".join(conflicts))


def _normalized_set(items: tuple[str, ...] | list[str]) -> set[str]:
    return {str(item).strip().lower() for item in items if str(item).strip()}


def _matching_keywords(left_items: set[str], right_items: set[str]) -> set[str]:
    matches = set()
    for left in left_items:
        for right in right_items:
            if left in right or right in left:
                matches.add(left)
    return matches


def _format_items(items: set[str]) -> str:
    return "、".join(sorted(items))
