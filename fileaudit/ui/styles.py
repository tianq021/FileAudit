APP_STYLE = """
    QMainWindow {
        background-color: #111827;
        color: #E5E7EB;
    }

    QLabel {
        color: #E5E7EB;
        font-size: 14px;
    }

    #TopBar {
        background-color: #111827;
        border-bottom: 1px solid #374151;
    }

    #AppTitle {
        font-size: 20px;
        font-weight: bold;
    }

    #TopStatus {
        color: #9CA3AF;
    }

    #SideBar {
        background-color: #0F172A;
        border-right: 1px solid #374151;
    }

    #NavButton {
        background-color: transparent;
        color: #D1D5DB;
        border: none;
        text-align: left;
        padding: 12px 14px;
        border-radius: 8px;
        font-size: 15px;
    }

    #NavButton:hover {
        background-color: #1F2937;
    }

    #NavButton[active="true"] {
        background-color: #2563EB;
        color: #FFFFFF;
        font-weight: bold;
    }

    #SideInfo {
        color: #9CA3AF;
        font-size: 12px;
        background-color: #111827;
        padding: 10px;
        border-radius: 8px;
    }

    #BottomBar {
        background-color: #111827;
        border-top: 1px solid #374151;
    }

    #PageTitle {
        font-size: 24px;
        font-weight: bold;
    }

    #PageDesc {
        color: #9CA3AF;
        font-size: 14px;
    }

    #Panel {
        background-color: #1F2937;
        border: 1px solid #374151;
        border-radius: 10px;
        padding: 12px;
    }

    #StatCard {
        background-color: #1F2937;
        border: 1px solid #374151;
        border-radius: 10px;
        min-height: 90px;
    }

    #CardTitle {
        color: #9CA3AF;
        font-size: 13px;
    }

    #CardValue {
        font-size: 24px;
        font-weight: bold;
        color: #F9FAFB;
    }

    QPushButton {
        background-color: #374151;
        color: #F9FAFB;
        border: none;
        padding: 9px 14px;
        border-radius: 8px;
        font-size: 14px;
    }

    QPushButton:hover {
        background-color: #4B5563;
    }

    #PrimaryButton {
        background-color: #2563EB;
        font-weight: bold;
    }

    #PrimaryButton:hover {
        background-color: #1D4ED8;
    }

    QLineEdit, QComboBox {
        background-color: #111827;
        color: #F9FAFB;
        border: 1px solid #4B5563;
        border-radius: 6px;
        padding: 8px;
        font-size: 14px;
    }

    QCheckBox {
        color: #E5E7EB;
        spacing: 8px;
        font-size: 14px;
    }

    QTabWidget::pane {
        border: none;
        margin-top: 12px;
    }

    QTabBar::tab {
        background-color: #1F2937;
        color: #D1D5DB;
        border: 1px solid #374151;
        border-radius: 8px;
        padding: 9px 18px;
        margin-right: 8px;
    }

    QTabBar::tab:selected {
        background-color: #2563EB;
        color: #FFFFFF;
        font-weight: bold;
    }

    QTabBar::tab:hover {
        background-color: #374151;
    }

    QTableWidget {
        background-color: #111827;
        color: #E5E7EB;
        gridline-color: #374151;
        border: 1px solid #374151;
        border-radius: 8px;
    }

    QHeaderView::section {
        background-color: #1F2937;
        color: #F9FAFB;
        padding: 8px;
        border: none;
        border-right: 1px solid #374151;
    }

    QHeaderView::section:hover {
        background-color: #2B3546;
    }

    QScrollArea {
        background-color: transparent;
        border: none;
    }

    QScrollBar:vertical {
        background-color: #111827;
        border: none;
        width: 14px;
        margin: 0;
    }

    QScrollBar:horizontal {
        background-color: #111827;
        border: none;
        height: 14px;
        margin: 0;
    }

    QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
        background-color: #60A5FA;
        border-radius: 6px;
        min-height: 28px;
        min-width: 28px;
    }

    QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {
        background-color: #93C5FD;
    }

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical,
    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {
        width: 0;
        height: 0;
    }

    QScrollBar::add-page:vertical,
    QScrollBar::sub-page:vertical,
    QScrollBar::add-page:horizontal,
    QScrollBar::sub-page:horizontal {
        background: #1F2937;
    }

    QProgressBar {
        background-color: #1F2937;
        color: white;
        border: 1px solid #374151;
        border-radius: 5px;
        text-align: center;
    }

    QProgressBar::chunk {
        background-color: #2563EB;
        border-radius: 5px;
    }
"""
