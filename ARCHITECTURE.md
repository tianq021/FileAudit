# 项目结构说明

FileAudit 当前已经从界面骨架推进到可用的桌面文件审计工具。代码按“界面、后台任务、扫描核心、数据模型、报告导出、配置持久化”分层，避免把文件扫描和界面控件混在一起。

## 当前目录

```text
FileAudit/
├─ main.py                    # 程序入口，只负责启动 QApplication
├─ fileaudit/
│  ├─ app.py                  # 主窗口，负责页面组装、扫描流程、导出流程和设置同步
│  ├─ config/
│  │  └─ settings.py          # AppSettings、默认设置、JSON 读写
│  ├─ core/
│  │  └─ scanner.py           # 目录扫描、风险规则、Hash、重复文件检测
│  ├─ models/
│  │  └─ scan.py              # ScanOptions、FileRecord、ScanResult 等数据结构
│  ├─ reports/
│  │  └─ exporter.py          # CSV 数据包和 HTML 图表报告导出
│  ├─ services/
│  │  └─ scan_worker.py       # QThread 后台扫描任务
│  └─ ui/
│     ├─ components.py        # 顶部栏、侧边栏、底部栏、统计卡片、图表控件
│     ├─ pages.py             # 扫描配置、概览、明细、重复、风险、导出、设置页面
│     └─ styles.py            # 全局 QSS 样式
├─ docs/
│  └─ 官方文档.md             # PySide6/Qt 官方文档入口
├─ 草图.txt                   # 产品草图和页面规划
├─ README.md                  # 项目说明
├─ CHANGELOG.md               # 更新记录
└─ 修改指南.md                # 二次修改入口说明
```

## 模块职责

### `main.py`

保持最薄，只创建 `QApplication`、创建 `MainWindow` 并启动事件循环。

### `fileaudit/app.py`

主窗口层，负责：

- 创建页面和导航。
- 启动后台扫描线程。
- 接收扫描进度、完成、失败和取消状态。
- 把扫描结果分发给概览、明细、重复文件和可疑文件页面。
- 调用报告导出。
- 加载和保存设置，并同步到扫描配置页。

### `fileaudit/core/scanner.py`

纯业务逻辑，不依赖 UI 控件。负责：

- 遍历目录。
- 应用忽略目录。
- 构造文件记录。
- 判断风险规则。
- 先按大小分组，再计算 Hash，识别重复文件。
- 支持取消扫描并返回部分结果。

### `fileaudit/models/scan.py`

集中定义扫描相关数据结构：

- `ScanOptions`
- `FileRecord`
- `DuplicateGroup`
- `ScanError`
- `ScanSummary`
- `ScanResult`

### `fileaudit/services/scan_worker.py`

连接 UI 和扫描核心。用 `QThread` 在后台执行扫描，通过 Signal 通知：

- 扫描进度。
- 扫描完成。
- 扫描失败。

### `fileaudit/reports/exporter.py`

负责生成报告文件：

- `summary.csv`
- `files.csv`
- `duplicates.csv`
- `risks.csv`
- `errors.csv`
- `report.html`

报告导出只使用 Python 标准库，不依赖 `openpyxl` 或 `pandas`。

### `fileaudit/config/settings.py`

负责应用设置：

- 默认扫描目录。
- 默认报告目录。
- 阈值和 Hash 算法。
- 检测开关。
- 忽略目录。
- 可疑扩展名。
- 白名单扩展名。

设置保存到 `%USERPROFILE%\.fileaudit\settings.json`。

## 关键流程

### 扫描流程

```text
ScanConfigPage
  -> MainWindow.on_scan_requested
  -> ScanWorker
  -> core.scan_directory
  -> ScanResult
  -> OverviewPage/FileDetailPage/DuplicatePage/RiskPage
```

### 取消流程

```text
ScanConfigPage 取消按钮
  -> MainWindow.on_cancel_requested
  -> ScanWorker.cancel
  -> scan_directory 检查 should_cancel
  -> 返回 canceled=True 的部分 ScanResult
```

### 导出流程

```text
ExportPage
  -> MainWindow.on_export_requested
  -> reports.export_report_bundle
  -> CSV + HTML
```

### 设置流程

```text
程序启动
  -> load_settings
  -> ScanConfigPage.apply_settings
  -> SettingsPage.apply_settings

设置页保存
  -> save_settings
  -> 同步回扫描配置页
```

## 设计注意点

- UI 不能直接执行耗时扫描，必须通过 `ScanWorker`。
- `core/` 不引用 PySide6，方便单独测试。
- 表格排序避免使用自定义 `QTableWidgetItem.__lt__`，曾触发 PySide6 原生崩溃；现在采用 Python 先排序数据再重绘表格。
- `fileaudit/reports/` 是源码目录，`.gitignore` 只忽略根目录 `/reports/` 生成物。
- 白名单扩展名只影响“可疑扩展名”和“双扩展名”规则，不会阻止文件被扫描。
