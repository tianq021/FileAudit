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


def format_skip_reason(reason: str) -> str:
    return SKIP_REASON_NAMES.get(reason, reason)


def format_skip_reasons(reasons: dict[str, int]) -> str:
    if not reasons:
        return "无"
    return "，".join(f"{format_skip_reason(reason)} {count}" for reason, count in reasons.items())


def risk_sort_key(level: str) -> int:
    return RISK_LEVEL_ORDER.get(level, 9)
