from datetime import datetime

RISK_LEVEL_NAMES = {
    "high": "高风险",
    "medium": "中风险",
    "low": "低风险",
    "normal": "正常",
}

RISK_REASON_NAMES = {
    "suspicious extension": "可疑扩展名",
    "script file": "脚本文件",
    "double extension": "双扩展名伪装",
    "hidden file": "隐藏文件",
    "empty file": "空文件",
    "big file": "大文件",
    "large file without extension": "无扩展名大文件",
    "temporary file": "临时/备份文件",
    "time anomaly": "时间异常",
    "long path": "路径过长",
}

RISK_REASON_EXPLANATIONS = {
    "suspicious extension": "文件扩展名属于高风险或不常见类型，可能包含可执行代码或自动化脚本。",
    "script file": "脚本文件可以批量执行命令，来源不明时可能修改系统或读取敏感数据。",
    "double extension": "文件名包含双扩展名，常见于把可执行文件伪装成文档、图片或压缩包。",
    "hidden file": "隐藏文件通常不在普通文件管理视图中显示，可能是系统文件，也可能用于规避注意。",
    "empty file": "文件大小为 0，可能是占位文件、异常生成文件或未完成写入的文件。",
    "big file": "文件超过配置的大文件阈值，可能占用较多空间或拖慢 Hash、导出等处理。",
    "large file without extension": "大文件没有扩展名，无法直观看出类型，可能需要确认来源和用途。",
    "temporary file": "临时、缓存或备份文件通常可以清理，但应先确认是否仍被应用使用。",
    "time anomaly": "文件修改时间晚于当前时间，可能来自系统时间错误、同步异常或人为修改。",
    "long path": "完整路径超过配置阈值，可能导致部分工具、压缩或迁移流程处理失败。",
}

RISK_REASON_ACTIONS = {
    "suspicious extension": "确认文件来源；不认识的可执行或脚本文件建议先隔离，不要直接运行。",
    "script file": "查看脚本内容和来源；确认用途前不要双击执行。",
    "double extension": "重点核对真实扩展名；如果伪装成文档或图片，建议隔离并进一步检查。",
    "hidden file": "确认是否为系统或应用正常文件；来源不明时检查所在目录和创建时间。",
    "empty file": "确认是否为合法占位文件；无用途时可加入清理候选。",
    "big file": "确认是否需要保留；可结合重复文件结果判断是否可归档或清理。",
    "large file without extension": "尝试确认文件类型和来源；必要时补充扩展名或移动到明确目录。",
    "temporary file": "确认应用未使用后再清理；重要目录中的备份文件先保留或归档。",
    "time anomaly": "检查系统时间、同步工具和文件来源；必要时重新生成或修正时间戳。",
    "long path": "考虑缩短目录层级或文件名，降低迁移、备份和压缩失败风险。",
}

SKIP_REASON_NAMES = {
    "skip dir name": "目录名",
    "skip dir path keyword": "目录路径关键词",
    "skip file name": "文件名",
    "skip path keyword": "路径关键词",
    "skip extension": "扩展名",
    "skip hidden file": "隐藏文件",
    "skip large file": "大文件",
    "skip include unmatched": "未匹配只扫描规则",
    "skip slow file": "慢文件",
    "skip slow hash": "慢 Hash",
}

RISK_LEVEL_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
    "normal": 3,
}


def format_size(size: int) -> str:
    value = float(size)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def format_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def format_risk_level(level: str) -> str:
    return RISK_LEVEL_NAMES.get(level, level)


def format_risk_reasons(reasons: list[str]) -> str:
    return "，".join(RISK_REASON_NAMES.get(reason, reason) for reason in reasons)


def format_risk_explanations(reasons: list[str]) -> str:
    return "；".join(RISK_REASON_EXPLANATIONS.get(reason, reason) for reason in reasons)


def format_risk_actions(reasons: list[str]) -> str:
    return "；".join(RISK_REASON_ACTIONS.get(reason, reason) for reason in reasons)


def format_skip_reason(reason: str) -> str:
    return SKIP_REASON_NAMES.get(reason, reason)


def format_skip_reasons(reasons: dict[str, int]) -> str:
    if not reasons:
        return "无"
    return "，".join(f"{format_skip_reason(reason)} {count}" for reason, count in reasons.items())


def risk_sort_key(level: str) -> int:
    return RISK_LEVEL_ORDER.get(level, 9)
