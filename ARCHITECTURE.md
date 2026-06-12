# 项目结构说明

FileAudit 当前已经从界面骨架推进到可用的桌面文件审计工具。代码按“界面、后台任务、扫描核心、数据模型、报告导出、配置持久化、测试”分层，避免把文件扫描、规则判断和界面控件混在一起。

## 当前目录

```text
FileAudit/
├─ main.py                    # 程序入口，只负责启动 QApplication
├─ fileaudit/
│  ├─ app.py                  # 主窗口，负责页面组装、扫描流程、清空结果、导出流程和设置同步
│  ├─ config/
│  │  └─ settings.py          # AppSettings、默认设置、JSON 读写
│  ├─ core/
│  │  └─ scanner.py           # 目录扫描、跳过规则、只扫描规则、风险规则、Hash、重复文件检测
│  ├─ models/
│  │  └─ scan.py              # ScanOptions、FileRecord、ScanResult 等数据结构
│  ├─ reports/
│  │  └─ exporter.py          # CSV 数据包和 HTML 图表报告导出
│  ├─ services/
│  │  └─ scan_worker.py       # QThread 后台扫描任务
│  └─ ui/
│     ├─ components.py        # 顶部栏、侧边栏、底部栏、统计卡片、条形图、环形图
│     ├─ pages.py             # 扫描配置、概览、明细、重复、风险、错误、导出、设置页面
│     └─ styles.py            # 全局 QSS 样式
├─ tests/
│  └─ test_scanner.py         # 扫描核心和报告导出测试
├─ docs/
│  ├─ 官方文档.md             # PySide6/Qt 官方文档入口
│  └─ 隐私与跳过规则临时方案.md # 隐私、跳过、只扫描和脱敏策略记录
├─ TEMP_ISSUES.md             # 当前问题和后续优化清单
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
- 清空当前扫描结果。
- 把扫描结果分发给概览、明细、重复文件、可疑文件和扫描错误页面。
- 调用报告导出，并传入是否导出完整路径的设置。
- 加载和保存设置，并同步到扫描配置页。

### `fileaudit/core/scanner.py`

纯业务逻辑，不依赖 UI 控件。负责：

- 遍历目录。
- 应用忽略目录和跳过目录规则。
- 在创建 `FileRecord` 前应用文件跳过规则。
- 应用“只扫描匹配规则”和冲突策略。
- 构造文件记录。
- 判断风险规则。
- 先按大小分组，再计算 Hash，识别重复文件。
- 支持取消扫描并返回部分结果。
- 构建包含跳过统计的 `ScanSummary`。

### `fileaudit/models/scan.py`

集中定义扫描相关数据结构：

- `ScanOptions`
- `FileRecord`
- `DuplicateGroup`
- `ScanError`
- `ScanSummary`
- `ScanResult`

`ScanOptions` 现在同时包含检测规则、跳过规则、只扫描规则和 Hash 选项。`ScanSummary` 包含文件/目录统计、风险统计、重复文件统计、错误统计和跳过统计。

### `fileaudit/services/scan_worker.py`

连接 UI 和扫描核心。用 `QThread` 在后台执行扫描，通过 Signal 通知：

- 扫描进度。
- Hash 阶段进度。
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

报告导出只使用 Python 标准库，不依赖 `openpyxl` 或 `pandas`。导出函数支持 `export_full_paths`，可以在报告中隐藏完整路径，只保留文件名或目录名。

### `fileaudit/config/settings.py`

负责应用设置：

- 默认扫描目录。
- 默认报告目录。
- 阈值和 Hash 算法。
- 检测开关。
- 忽略目录。
- 可疑扩展名。
- 白名单扩展名。
- 跳过隐藏文件。
- 跳过大文件阈值。
- 跳过目录名、文件名、扩展名和路径关键词。
- 只扫描规则和冲突策略。
- 报告是否导出完整路径。

设置保存到 `%USERPROFILE%\.fileaudit\settings.json`。

### `fileaudit/ui/pages.py`

集中放置页面类：

- `ScanConfigPage`
- `OverviewPage`
- `FileDetailPage`
- `DuplicatePage`
- `RiskPage`
- `ErrorPage`
- `ExportPage`
- `SettingsPage`

页面层负责展示、收集用户输入和发出 Signal，不直接执行耗时扫描。

### `fileaudit/ui/components.py`

通用控件：

- `TopBar`
- `Sidebar`
- `StatCard`
- `BarChart`
- `DonutChart`
- `BottomBar`

## 关键流程

### 扫描流程

```text
ScanConfigPage
  -> MainWindow.on_scan_requested
  -> ScanWorker
  -> core.scan_directory
  -> ScanResult
  -> OverviewPage/FileDetailPage/DuplicatePage/RiskPage/ErrorPage
```

### 跳过和只扫描流程

```text
目录遍历
  -> 目录名/路径关键词跳过
  -> 文件名/扩展名/隐藏/大小/路径关键词跳过
  -> 只扫描规则匹配
  -> 冲突策略判断
  -> 生成 FileRecord
  -> 风险规则标记
```

### 取消流程

```text
ScanConfigPage 取消按钮
  -> MainWindow.on_cancel_requested
  -> ScanWorker.cancel
  -> scan_directory 检查 should_cancel
  -> 返回 canceled=True 的部分 ScanResult
```

### 清空流程

```text
ScanConfigPage 清空结果按钮
  -> MainWindow.on_clear_requested
  -> 清空 scan_result
  -> 清空各结果页
  -> 重置顶部栏、侧边栏、底部栏
```

### 导出流程

```text
ExportPage
  -> MainWindow.on_export_requested
  -> reports.export_report_bundle(result, output_dir, export_full_paths)
  -> CSV + HTML
```

### 设置流程

```text
程序启动
  -> load_settings
  -> ScanConfigPage.apply_settings
  -> SettingsPage.apply_settings

设置页保存
  -> SettingsPage.current_settings
  -> save_settings
  -> 同步回扫描配置页
```

## 设计注意点

- UI 不能直接执行耗时扫描，必须通过 `ScanWorker`。
- `core/` 不引用 PySide6，方便单独测试。
- 跳过规则和风险规则必须分开：跳过表示不进入结果，风险表示进入结果但带标记。
- 白名单扩展名只影响“可疑扩展名”和“双扩展名”规则，不会阻止文件被扫描。
- “只扫描规则”只在开启 `include_only_matched` 后生效。
- 跳过规则和只扫描规则冲突时，由 `include_conflict_policy` 决定谁优先。
- 表格排序避免使用自定义 `QTableWidgetItem.__lt__`，曾触发 PySide6 原生崩溃；现在采用 Python 先排序数据再重绘表格。
- `fileaudit/reports/` 是源码目录，`.gitignore` 只忽略根目录 `/reports/` 生成物。
- 中文 Markdown 和界面文案保持 UTF-8 编码。

## 已遇到的问题和当前处理

### Hash 阶段看似卡住

现象：扫描 `C:\Windows` 这类目录时，底部文件数不再增长，当前文件停在类似 `winhlp32.exe.mui`。

原因：文件遍历已经完成或接近完成，程序进入重复文件 Hash 阶段。`.mui` 等系统资源文件可能同大小文件很多，会触发较多 Hash 读取。

当前处理：

- `scan_directory()` 支持阶段进度回调。
- `ScanWorker.progress_changed` 会传递阶段、当前数、总数和当前路径。
- UI 区分显示“正在扫描文件”和“正在计算重复文件 Hash”。
- `_hash_file()` 在读取大文件分块时检查取消请求。

### 大结果集 UI 内存过高

现象：扫描 60 万级文件时，完整结果灌入 `QTableWidget` 会创建大量控件项，内存可能达到数 GB。

当前处理：

- 扫描结果完整保留在 `ScanResult` 中。
- UI 表格只先渲染前 `INITIAL_TABLE_ROWS = 5000` 行。
- 用户可以通过“查看更多 1000 行”继续加载。
- 导出报告仍使用完整扫描结果。

后续建议：

- 改为分页表格。
- 或改为 `QTableView + QAbstractTableModel` 虚拟模型，按需读取显示行。

### PySide6 表格排序崩溃

现象：自定义 `QTableWidgetItem.__lt__` 后，点击排序或灌表时出现原生内存读取错误。

当前处理：

- 禁用 Qt 内置排序。
- 文件明细页维护 `sort_column` 和 `sort_reverse`。
- 点击表头后先排序 Python 数据列表，再重绘表格。

### 导出选项和真实行为不一致

早期导出页展示多个复选框，但导出逻辑固定生成完整报告包。当前已移除这些暂未生效的复选框，页面明确说明会生成完整报告包。

### `.gitignore` 误忽略源码目录

现象：新增 `fileaudit/reports/` 后，Git 不显示该源码目录。

原因：`.gitignore` 中的 `reports/` 会匹配任意层级目录。

当前处理：

- 改为 `/reports/`，只忽略仓库根目录下的报告输出目录。

## 后续架构建议

- 将 UI 和报告导出中重复的格式化函数抽到公共工具模块。
- 将 `fileaudit/ui/pages.py` 按页面拆分，避免继续膨胀。
- 大结果集表格改为虚拟模型。
- 增加 Excel 多 Sheet 导出模块。
- 增加扫描历史保存和两次扫描结果对比。
