# FileAudit 文件体检分析器

FileAudit 是一个基于 PySide6 的桌面文件审计工具，用于扫描文件夹并分析文件基础信息、重复文件、可疑文件、大文件、空文件、隐藏文件和异常路径，并支持导出 CSV 数据包和 HTML 图表报告。

## 当前功能

- 选择目录并递归扫描文件。
- 后台扫描，不阻塞界面。
- 可取消扫描，取消后保留已经扫描到的结果。
- 记录文件名、完整路径、扩展名、大小、创建时间、修改时间、Hash、隐藏状态和空文件状态。
- 按“大小相同 + Hash 相同”识别重复文件。
- 检测可疑扩展名、双扩展名伪装、隐藏文件、空文件、大文件、时间异常和路径过长。
- 文件明细支持关键字搜索、风险等级筛选、文件类型筛选和表头排序。
- 扫描概览显示统计卡片和图表：文件类型分布、风险等级分布、目录占用 Top 10。
- 重复文件页和可疑文件页显示完整路径，支持横向滚动查看长路径。
- 报告导出支持 `summary.csv`、`files.csv`、`duplicates.csv`、`risks.csv`、`errors.csv` 和 `report.html`。
- 设置页支持保存默认扫描目录、默认报告目录、阈值、检测开关、忽略目录、可疑扩展名和白名单扩展名。

## 运行方式

当前已确认 `C:\Python312\python.exe` 安装了 PySide6，可以直接运行：

```powershell
C:\Python312\python.exe main.py
```

如果要使用项目内虚拟环境，需要先安装依赖：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

注意：当前 `F:\Python\FileAudit\.venv` 里未安装 PySide6，直接用它运行会报 `ModuleNotFoundError: No module named 'PySide6'`。

## 使用流程

1. 打开程序。
2. 在“扫描配置”页选择扫描目录。
3. 按需调整扫描选项、忽略目录、可疑扩展名和白名单扩展名。
4. 点击“开始扫描”。
5. 扫描完成后查看“扫描概览”“文件明细”“重复文件”“可疑文件”。
6. 在“报告导出”页点击“生成报告”，选择输出目录。
7. 在“设置”页保存常用默认值。

## 重复文件判断

重复文件不是只看文件名，而是：

1. 先按文件大小分组。
2. 只有同样大小的文件才计算 Hash。
3. 大小相同且 Hash 相同，才判定为重复文件。

这样可以避免给所有文件无差别计算 Hash，扫描大目录时更快。

## 风险规则

默认风险规则包括：

- 可疑扩展名，例如 `.exe`、`.bat`、`.ps1`、`.vbs` 等。
- 双扩展名伪装，例如 `invoice.pdf.exe`。
- 隐藏文件。
- 空文件。
- 大文件。
- 修改时间异常。
- 路径过长。

`.js` 默认不再作为可疑扩展名，但仍归类为代码文件。可疑扩展名和白名单扩展名都可以在设置页修改。

## 报告导出

报告导出会生成一个带时间戳的目录，包含：

```text
summary.csv      # 扫描概览
files.csv        # 文件明细
duplicates.csv   # 重复文件
risks.csv        # 可疑文件
errors.csv       # 扫描错误
report.html      # 带图表的 HTML 报告
```

CSV 使用 `utf-8-sig` 编码，方便用 Excel 打开中文内容。

## 设置文件

设置保存到用户目录：

```text
%USERPROFILE%\.fileaudit\settings.json
```

如果设置文件损坏，程序会自动回退到默认设置。

## 主要目录

```text
main.py                  # 程序入口
fileaudit/app.py         # 主窗口和跨页面交互
fileaudit/core/          # 扫描、风险检测、重复检测
fileaudit/models/        # 扫描数据模型
fileaudit/services/      # 后台扫描线程
fileaudit/reports/       # CSV/HTML 报告导出
fileaudit/config/        # 设置读写
fileaudit/ui/            # 页面、组件和样式
```
