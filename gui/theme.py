"""Modern flat dark theme (QSS) for the scanner GUI."""
from __future__ import annotations

# GitHub-dark-inspired palette
BG = "#0d1117"
PANEL = "#161b22"
PANEL2 = "#1c2128"
BORDER = "#30363d"
TEXT = "#c9d1d9"
MUTED = "#8b949e"
ACCENT = "#2563eb"
ACCENT_HOVER = "#3b82f6"

STYLESHEET = f"""
* {{
    font-family: 'Segoe UI', 'Malgun Gothic', sans-serif;
    font-size: 12px;
}}
QWidget {{
    background: {BG};
    color: {TEXT};
}}
QToolTip {{
    background: {PANEL2};
    color: {TEXT};
    border: 1px solid {BORDER};
    padding: 4px 6px;
}}

/* Group boxes */
QGroupBox {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
    margin-top: 14px;
    padding: 10px 8px 8px 8px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 4px;
    color: {MUTED};
}}

/* Inputs */
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 5px 8px;
    selection-background-color: #264f78;
}}
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 1px solid {ACCENT_HOVER};
}}
QSpinBox::up-button, QSpinBox::down-button,
QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {{
    width: 16px; background: {PANEL2}; border-left: 1px solid {BORDER};
}}

/* Buttons */
QPushButton {{
    background: {PANEL2};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 12px;
    color: {TEXT};
}}
QPushButton:hover {{ background: {BORDER}; }}
QPushButton:pressed {{ background: #2d333b; }}
QPushButton:disabled {{ color: #565c66; background: {PANEL}; }}

/* Tree */
QTreeWidget, QListWidget {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
    outline: 0;
}}
QTreeWidget::item {{ padding: 3px 2px; }}
QTreeWidget::item:selected {{ background: #1f6feb33; color: {TEXT}; }}
QTreeWidget::item:hover {{ background: {PANEL2}; }}

/* Table */
QTableWidget {{
    background: {PANEL};
    alternate-background-color: {PANEL2};
    gridline-color: {BORDER};
    border: none;
    outline: 0;
}}
QTableWidget::item {{ padding: 3px 6px; }}
QTableWidget::item:selected {{ background: #1f6feb44; color: {TEXT}; }}
QHeaderView::section {{
    background: {PANEL2};
    color: {MUTED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 6px 8px;
    font-weight: 600;
}}

/* Tabs */
QTabWidget::pane {{ border: none; background: {BG}; }}
QTabBar::tab {{
    background: transparent;
    color: {MUTED};
    padding: 6px 14px;
    border: none;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {ACCENT_HOVER}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}

/* Progress */
QProgressBar {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 6px;
    text-align: center;
    color: {TEXT};
    height: 18px;
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}

/* Checkboxes */
QCheckBox {{ spacing: 6px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {BORDER}; border-radius: 4px; background: {BG};
}}
QCheckBox::indicator:checked {{
    background: {ACCENT}; border: 1px solid {ACCENT};
}}

/* Scrollbars */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: #484f58; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {BORDER}; border-radius: 5px; min-width: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* Dialogs */
QDialog {{ background: {BG}; }}
"""
