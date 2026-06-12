FILE_TYPE_GROUPS = {
    "文档": {
        ".csv",
        ".doc",
        ".docx",
        ".md",
        ".pdf",
        ".ppt",
        ".pptx",
        ".rtf",
        ".txt",
        ".xls",
        ".xlsx",
    },
    "图片": {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".svg", ".tif", ".tiff", ".webp"},
    "音视频": {".aac", ".avi", ".flac", ".m4a", ".mkv", ".mov", ".mp3", ".mp4", ".wav", ".webm", ".wmv"},
    "压缩包": {".7z", ".gz", ".rar", ".tar", ".tgz", ".zip"},
    "代码": {
        ".bat",
        ".cmd",
        ".css",
        ".go",
        ".html",
        ".java",
        ".js",
        ".json",
        ".py",
        ".rs",
        ".sh",
        ".ts",
        ".xml",
        ".yaml",
        ".yml",
    },
    "可执行": {".com", ".dll", ".exe", ".msi", ".scr"},
}


def classify_file_type(extension: str) -> str:
    extension = extension.lower()
    for name, extensions in FILE_TYPE_GROUPS.items():
        if extension in extensions:
            return name
    return "其他"
