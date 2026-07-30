"""Main PyQt5 window: scope gate, technique tree, live log, findings table, report export."""
from __future__ import annotations


from PyQt5.QtCore import Qt, QByteArray, QSize
from PyQt5.QtGui import QColor, QFont, QIcon, QPixmap, QPainter
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QTreeWidget, QTreeWidgetItem,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QTabWidget, QProgressBar,
    QSpinBox, QDoubleSpinBox, QGroupBox, QMessageBox, QFileDialog, QSplitter,
    QHeaderView, QAbstractItemView, QDialog, QTextEdit,
)

from modules.base import modules_by_category
from modules import load_all
from core.result import Finding
from core import report
from core.http_utils import parse_headers_block, parse_cookie_string
from gui.worker import ScanWorker

SEV_COLORS = {
    "Critical": "#7b1fa2", "High": "#c62828", "Medium": "#ef6c00",
    "Low": "#f9a825", "Info": "#607d8b",
}

SCOPE_TEXT = ("본인은 이 대상에 대해 테스트 권한(소유/버그바운티 프로그램/서면 허가)이 있으며, "
              "모든 결과에 책임진다는 것에 동의합니다.")

# ---------------------------------------------------------------------------
# Feather-style SVG icons (currentColor is swapped at render time)
# ---------------------------------------------------------------------------
_SVG = {
    "gear": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    "play": '<polygon points="6 4 20 12 6 20 6 4"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="2"/>',
    "save": '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
    "target": '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    "share": '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>',
    "sliders": '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
    "terminal": '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
}


def _svg_markup(name: str, color: str) -> QByteArray:
    inner = _SVG[name]
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
           f'fill="{"currentColor" if name in ("play","stop") else "none"}" stroke="currentColor" '
           f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{inner}</svg>')
    return QByteArray(svg.replace("currentColor", color).encode())


def svg_icon(name: str, size: int = 18, color: str = "#c9d1d9") -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    QSvgRenderer(_svg_markup(name, color)).render(p)
    p.end()
    return QIcon(pm)


def svg_label(name: str, size: int = 18, color: str = "#8aa0b4") -> QLabel:
    lbl = QLabel()
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    QSvgRenderer(_svg_markup(name, color)).render(p)
    p.end()
    lbl.setPixmap(pm)
    return lbl


class FindingDetailDialog(QDialog):
    def __init__(self, finding: Finding, target: str = "", parent=None):
        super().__init__(parent)
        self.finding = finding
        self.target = target
        self.setWindowTitle(f"[{finding.severity.value}] {finding.title}")
        self.resize(760, 600)
        lay = QVBoxLayout(self)

        tabs = QTabWidget()

        # --- Tab 1: raw details ---
        te = QTextEdit()
        te.setReadOnly(True)
        te.setFont(QFont("Consolas", 10))
        parts = [
            f"Severity   : {finding.severity.value}",
            f"Confidence : {finding.confidence}",
            f"Module     : {finding.module_id}",
            f"URL        : {finding.url}",
            "",
            "── Description ──", finding.description or "(none)",
        ]
        if finding.request:
            parts += ["", "── Request ──", finding.request]
        if finding.evidence:
            parts += ["", "── Evidence ──", finding.evidence]
        if finding.remediation:
            parts += ["", "── Remediation ──", finding.remediation]
        te.setPlainText("\n".join(parts))
        tabs.addTab(te, "상세")

        # --- Tab 2: bug bounty report (Markdown) ---
        self.report_md = report.finding_to_report_md(target, finding)
        rep = QTextEdit()
        rep.setReadOnly(True)
        rep.setFont(QFont("Consolas", 10))
        rep.setPlainText(self.report_md)
        tabs.addTab(rep, "📋 보고서 형식")

        lay.addWidget(tabs)

        row = QHBoxLayout()
        copy_btn = QPushButton("보고서 복사")
        copy_btn.clicked.connect(self._copy_report)
        save_btn = QPushButton("보고서 저장(.md)")
        save_btn.clicked.connect(self._save_report)
        close_btn = QPushButton("닫기")
        close_btn.clicked.connect(self.accept)
        row.addWidget(copy_btn)
        row.addWidget(save_btn)
        row.addStretch(1)
        row.addWidget(close_btn)
        lay.addLayout(row)

    def _copy_report(self):
        QApplication.clipboard().setText(self.report_md)

    def _save_report(self):
        path, _ = QFileDialog.getSaveFileName(self, "보고서 저장", "finding_report.md",
                                              "Markdown (*.md);;텍스트 (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.report_md)
        except Exception as e:
            QMessageBox.critical(self, "저장 실패", str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nemesis")
        self.resize(1180, 780)
        self.worker: ScanWorker | None = None
        self.findings: list[Finding] = []
        self._live_pixmap = None
        load_all()  # ensure technique modules are registered before building the tree
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 6)
        root.setSpacing(6)

        # --- Top bar: target URL + settings gear ---
        topbar = QHBoxLayout()
        topbar.addWidget(svg_label("target", 20, "#3b82f6"))
        topbar.addWidget(QLabel("URL:"))
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com/page?id=1")
        topbar.addWidget(self.url_edit, 1)
        self.settings_btn = QPushButton(" 설정")
        self.settings_btn.setIcon(svg_icon("gear", 18, "#c9d1d9"))
        self.settings_btn.setIconSize(QSize(18, 18))
        self.settings_btn.setToolTip("인증/식별 · OOB/SSRF · 재귀 크롤 · 옵션 설정")
        self.settings_btn.clicked.connect(self._open_settings)
        topbar.addWidget(self.settings_btn)
        root.addLayout(topbar)

        # --- Scope gate ---
        self.scope_check = QCheckBox(SCOPE_TEXT)
        self.scope_check.setStyleSheet("color:#c62828; font-weight:600;")
        root.addWidget(self.scope_check)

        # --- Action bar: run / stop / export + progress ---
        action = QHBoxLayout()
        self.start_btn = QPushButton(" 스캔 시작")
        self.start_btn.setIcon(svg_icon("play", 16, "#ffffff"))
        self.start_btn.setStyleSheet("font-weight:600; padding:6px 14px; background:#2563eb; color:#fff; border-radius:4px;")
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton(" 중지")
        self.stop_btn.setIcon(svg_icon("stop", 16, "#c9d1d9"))
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.export_btn = QPushButton(" 리포트 저장")
        self.export_btn.setIcon(svg_icon("save", 16, "#c9d1d9"))
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_report)
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.status_label = QLabel("대기 중")
        action.addWidget(self.start_btn)
        action.addWidget(self.stop_btn)
        action.addWidget(self.export_btn)
        action.addWidget(self.progress, 1)
        action.addWidget(self.status_label)
        root.addLayout(action)

        # Build the settings dialog (holds all config widgets as self.* attrs).
        self._build_settings_dialog()

        # --- Vertical split: techniques (top) | terminal dock (bottom, fixed feel) ---
        vsplit = QSplitter(Qt.Vertical)

        tech_box = QGroupBox("공격 기법 선택 (Techniques)")
        tl = QVBoxLayout(tech_box)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemChanged.connect(self._on_item_changed)
        tl.addWidget(self.tree)
        sel_row = QHBoxLayout()
        btn_all = QPushButton("전체 선택")
        btn_none = QPushButton("전체 해제")
        btn_all.clicked.connect(lambda: self._set_all(Qt.Checked))
        btn_none.clicked.connect(lambda: self._set_all(Qt.Unchecked))
        sel_row.addWidget(btn_all)
        sel_row.addWidget(btn_none)
        sel_row.addStretch(1)
        tl.addLayout(sel_row)

        # Top area: techniques (left) | live Selenium view (right)
        hsplit = QSplitter(Qt.Horizontal)
        hsplit.addWidget(tech_box)

        live_box = QGroupBox("라이브 브라우저 (Selenium)")
        lv = QVBoxLayout(live_box)
        self.live_label = QLabel("스캔을 시작하면\n셀레니움이 공격 중인 화면이\n여기에 실시간으로 표시됩니다.")
        self.live_label.setAlignment(Qt.AlignCenter)
        self.live_label.setMinimumSize(360, 240)
        self.live_label.setStyleSheet(
            "background:#0d1117; color:#6e7681; border:1px solid #30363d; border-radius:6px;")
        lv.addWidget(self.live_label, 1)
        self.live_caption = QLabel("● 대기 중")
        self.live_caption.setStyleSheet("color:#8b949e; font-size:11px; font-family:Consolas,monospace;")
        lv.addWidget(self.live_caption)
        hsplit.addWidget(live_box)
        hsplit.setStretchFactor(0, 0)
        hsplit.setStretchFactor(1, 1)
        hsplit.setSizes([300, 660])

        vsplit.addWidget(hsplit)

        # Terminal-style bottom dock.
        term = QWidget()
        tv = QVBoxLayout(term)
        tv.setContentsMargins(0, 0, 0, 0)
        tv.setSpacing(0)
        hdr = QWidget()
        hdr.setStyleSheet("background:#0d1117; border-top-left-radius:6px; border-top-right-radius:6px;")
        hh = QHBoxLayout(hdr)
        hh.setContentsMargins(10, 5, 10, 5)
        hh.addWidget(svg_label("terminal", 15, "#3fb950"))
        tlbl = QLabel("TERMINAL — 탐지 결과 / 로그")
        tlbl.setStyleSheet("color:#8b949e; font-family:Consolas,monospace; font-size:11px; font-weight:600;")
        hh.addWidget(tlbl)
        hh.addStretch(1)
        tv.addWidget(hdr)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["심각도", "제목", "신뢰도", "URL", "모듈"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.doubleClicked.connect(self._show_finding_detail)
        self.tabs.addTab(self.table, "탐지 결과 (0)")

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 9))
        self.log_view.setStyleSheet(
            "QPlainTextEdit{background:#0d1117; color:#c9d1d9; border:none; "
            "selection-background-color:#264f78;}")
        self.tabs.addTab(self.log_view, "로그")
        tv.addWidget(self.tabs, 1)

        vsplit.addWidget(term)
        vsplit.setStretchFactor(0, 3)
        vsplit.setStretchFactor(1, 2)
        vsplit.setSizes([430, 300])
        term.setMinimumHeight(200)
        root.addWidget(vsplit, 1)

        self._populate_tree()

    # --------------------------------------------------- settings dialog
    def _section_header(self, icon_name: str, title: str) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(2, 8, 2, 2)
        h.addWidget(svg_label(icon_name, 18, "#3b82f6"))
        lbl = QLabel(title)
        lbl.setStyleSheet("font-weight:700; font-size:13px;")
        h.addWidget(lbl)
        h.addStretch(1)
        return w

    def _build_settings_dialog(self):
        self.settings_dialog = QDialog(self)
        self.settings_dialog.setWindowTitle("설정 (Settings)")
        self.settings_dialog.setWindowIcon(svg_icon("gear", 18, "#333333"))
        self.settings_dialog.resize(560, 640)
        dl = QVBoxLayout(self.settings_dialog)
        dl.setSpacing(4)

        # 1) Options
        dl.addWidget(self._section_header("sliders", "옵션 (Options)"))
        ow = QWidget(); og = QGridLayout(ow)
        self.headless_check = QCheckBox("헤드리스 브라우저")
        self.headless_check.setChecked(True)
        og.addWidget(self.headless_check, 0, 0, 1, 2)
        og.addWidget(QLabel("요청 간격(초):"), 1, 0)
        self.delay_spin = QDoubleSpinBox(); self.delay_spin.setRange(0.0, 10.0)
        self.delay_spin.setSingleStep(0.1); self.delay_spin.setValue(0.5)
        og.addWidget(self.delay_spin, 1, 1)
        og.addWidget(QLabel("페이지 타임아웃(초):"), 2, 0)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(5, 120); self.timeout_spin.setValue(20)
        og.addWidget(self.timeout_spin, 2, 1)
        self.verify_tls_check = QCheckBox("TLS 인증서 검증"); self.verify_tls_check.setChecked(True)
        og.addWidget(self.verify_tls_check, 3, 0, 1, 2)
        self.devtools_check = QCheckBox("DevTools(F12) 자동 열기 (헤드리스 해제)")
        self.devtools_check.setToolTip("체크 시 실제 크롬 창 + 개발자도구(F12)가 자동으로 열립니다.")
        self.devtools_check.setChecked(True)
        og.addWidget(self.devtools_check, 4, 0, 1, 2)
        dl.addWidget(ow)

        # 2) Recursive crawl / chaining
        dl.addWidget(self._section_header("share", "재귀 크롤 & 연쇄 공격 (Chaining)"))
        cw = QWidget(); cg = QGridLayout(cw)
        self.crawl_check = QCheckBox("같은 도메인 재귀 크롤 (발견한 페이지도 공격)")
        cg.addWidget(self.crawl_check, 0, 0, 1, 2)
        cg.addWidget(QLabel("최대 깊이:"), 1, 0)
        self.depth_spin = QSpinBox(); self.depth_spin.setRange(1, 5); self.depth_spin.setValue(2)
        cg.addWidget(self.depth_spin, 1, 1)
        cg.addWidget(QLabel("최대 페이지:"), 2, 0)
        self.maxpages_spin = QSpinBox(); self.maxpages_spin.setRange(1, 200); self.maxpages_spin.setValue(15)
        cg.addWidget(self.maxpages_spin, 2, 1)
        note2 = QLabel("· 취약점 발견 시 체인 엔진이 LFI/SQLi 심화 + 상관 연계(계정탈취 등) 수행")
        note2.setStyleSheet("color:#888; font-size:11px;"); note2.setWordWrap(True)
        cg.addWidget(note2, 3, 0, 1, 2)
        dl.addWidget(cw)

        # 3) Auth / Identity
        dl.addWidget(self._section_header("shield", "인증 / 식별 (Auth & Identity)"))
        aw = QWidget(); ag = QGridLayout(aw)
        ag.addWidget(QLabel("User-Agent (식별 토큰):"), 0, 0)
        self.ua_edit = QLineEdit()
        self.ua_edit.setPlaceholderText("예: research-team (h1-user) / 프로그램이 지정한 UA")
        ag.addWidget(self.ua_edit, 0, 1)
        ag.addWidget(QLabel("커스텀 헤더:"), 1, 0, Qt.AlignTop)
        self.headers_edit = QPlainTextEdit()
        self.headers_edit.setPlaceholderText("한 줄에 하나씩\nAuthorization: Bearer <token>\nX-Bug-Bounty: <handle>")
        self.headers_edit.setFixedHeight(58)
        ag.addWidget(self.headers_edit, 1, 1)
        ag.addWidget(QLabel("쿠키:"), 2, 0)
        self.cookies_edit = QLineEdit(); self.cookies_edit.setPlaceholderText("session=abc; token=xyz")
        ag.addWidget(self.cookies_edit, 2, 1)
        dl.addWidget(aw)

        # 4) OOB / SSRF
        dl.addWidget(self._section_header("globe", "OOB / SSRF (검증용 도메인 전용)"))
        bw = QWidget(); og2 = QGridLayout(bw)
        og2.addWidget(QLabel("카나리 도메인:"), 0, 0)
        self.canary_edit = QLineEdit()
        self.canary_edit.setPlaceholderText("예: abc123.oob.mydomain.com (내가 통제하는 도메인)")
        og2.addWidget(self.canary_edit, 0, 1)
        og2.addWidget(QLabel("OOB 폴 URL(선택):"), 1, 0)
        self.oob_poll_edit = QLineEdit()
        self.oob_poll_edit.setPlaceholderText("로그 조회 API (?token=…로 확인). 없으면 수동 검증")
        og2.addWidget(self.oob_poll_edit, 1, 1)
        note = QLabel("· 미설정 시 SSRF/블라인드 OOB 검사는 자동 skip (안전)")
        note.setStyleSheet("color:#888; font-size:11px;")
        og2.addWidget(note, 2, 0, 1, 2)
        dl.addWidget(bw)

        dl.addStretch(1)
        close_btn = QPushButton("닫기")
        close_btn.clicked.connect(self.settings_dialog.accept)
        dl.addWidget(close_btn)

    def _open_settings(self):
        self.settings_dialog.exec_()

    def _populate_tree(self):
        self.tree.blockSignals(True)
        for category, mods in sorted(modules_by_category().items()):
            parent = QTreeWidgetItem(self.tree, [category])
            parent.setFlags(parent.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsAutoTristate)
            parent.setCheckState(0, Qt.Checked)
            f = parent.font(0)
            f.setBold(True)
            parent.setFont(0, f)
            for cls in mods:
                child = QTreeWidgetItem(parent, [cls.name])
                child.setFlags(child.flags() | Qt.ItemIsUserCheckable)
                child.setCheckState(0, Qt.Checked if cls.default_enabled else Qt.Unchecked)
                child.setData(0, Qt.UserRole, cls.id)
                child.setToolTip(0, cls.description)
        self.tree.expandAll()
        self.tree.blockSignals(False)

    # --------------------------------------------------------------- events
    def _on_item_changed(self, item: QTreeWidgetItem, _col: int):
        # Parent auto-tristate handles propagation; nothing extra needed.
        pass

    def _set_all(self, state):
        self.tree.blockSignals(True)
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            top.setCheckState(0, state)
            for j in range(top.childCount()):
                top.child(j).setCheckState(0, state)
        self.tree.blockSignals(False)

    def _selected_module_ids(self) -> list[str]:
        ids: list[str] = []
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                child = top.child(j)
                if child.checkState(0) == Qt.Checked:
                    ids.append(child.data(0, Qt.UserRole))
        return ids

    # ---------------------------------------------------------------- scan
    def start_scan(self):
        url = self.url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "입력 오류", "대상 URL을 입력하세요.")
            return
        if not self.scope_check.isChecked():
            QMessageBox.warning(self, "권한 확인 필요",
                                "테스트 권한이 있는 대상임을 확인하는 체크박스에 동의해야 스캔할 수 있습니다.")
            return
        module_ids = self._selected_module_ids()
        if not module_ids:
            QMessageBox.warning(self, "선택 오류", "실행할 공격 기법을 하나 이상 선택하세요.")
            return

        options = {
            "headless": self.headless_check.isChecked(),
            "delay": self.delay_spin.value(),
            "page_timeout": self.timeout_spin.value(),
            "http_timeout": 15,
            "verify_tls": self.verify_tls_check.isChecked(),
            "user_agent": self.ua_edit.text().strip(),
            "extra_headers": parse_headers_block(self.headers_edit.toPlainText()),
            "cookies": parse_cookie_string(self.cookies_edit.text()),
            "canary_domain": self.canary_edit.text().strip(),
            "oob_poll_url": self.oob_poll_edit.text().strip(),
            "devtools": self.devtools_check.isChecked(),
            "crawl": self.crawl_check.isChecked(),
            "max_depth": self.depth_spin.value(),
            "max_pages": self.maxpages_spin.value(),
        }

        self.findings.clear()
        self.table.setRowCount(0)
        self.log_view.clear()
        self._set_running(True)
        pages = self.maxpages_spin.value() if self.crawl_check.isChecked() else 1
        self.progress.setRange(0, pages)
        self.progress.setValue(0)

        self.live_caption.setText("● 브라우저 시작 중…")
        self.worker = ScanWorker(url, module_ids, options)
        self.worker.log_line.connect(self._append_log)
        self.worker.finding.connect(self._add_finding)
        self.worker.progress.connect(self._on_progress)
        self.worker.done.connect(self._on_done)
        self.worker.frame.connect(self._on_frame_png)
        self.worker.start()

    def stop_scan(self):
        if self.worker is not None:
            self.status_label.setText("중지 요청됨…")
            self.stop_btn.setEnabled(False)
            self.worker.request_stop()

    def _set_running(self, running: bool):
        self.start_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)
        self.export_btn.setEnabled(not running and bool(self.findings))
        self.url_edit.setEnabled(not running)
        self.tree.setEnabled(not running)

    # -------------------------------------------------------------- signals
    def _append_log(self, text: str):
        self.log_view.appendPlainText(text)

    def _add_finding(self, finding: Finding):
        self.findings.append(finding)
        row = self.table.rowCount()
        self.table.insertRow(row)
        sev_item = QTableWidgetItem(finding.severity.value)
        sev_item.setForeground(QColor("#ffffff"))
        sev_item.setBackground(QColor(SEV_COLORS[finding.severity.value]))
        sev_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 0, sev_item)
        self.table.setItem(row, 1, QTableWidgetItem(finding.title))
        self.table.setItem(row, 2, QTableWidgetItem(finding.confidence))
        self.table.setItem(row, 3, QTableWidgetItem(finding.url))
        self.table.setItem(row, 4, QTableWidgetItem(finding.module_id))
        self.table.item(row, 1).setData(Qt.UserRole, finding)
        self.tabs.setTabText(0, f"탐지 결과 ({self.table.rowCount()})")

    def _on_progress(self, current: int, total: int, name: str):
        self.progress.setMaximum(max(total, 1))
        self.progress.setValue(current)
        label = name if len(name) < 70 else name[:67] + "..."
        self.status_label.setText(f"[{current}/{total}] {label}")
        self.live_caption.setText(f"● 공격 대상: {label}")

    def _on_frame_png(self, png: bytes):
        from PyQt5.QtGui import QPixmap
        pm = QPixmap()
        if not pm.loadFromData(png, "PNG") or pm.isNull():
            return
        self._live_pixmap = pm
        self._render_live()

    def _render_live(self):
        if self._live_pixmap is None:
            return
        scaled = self._live_pixmap.scaled(
            self.live_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.live_label.setPixmap(scaled)

    def resizeEvent(self, event):
        self._render_live()
        super().resizeEvent(event)

    def _on_done(self, findings: list):
        self._set_running(False)
        self.status_label.setText(f"완료 — {len(findings)}개 발견")
        self.progress.setValue(self.progress.maximum())
        self.live_caption.setText(f"● 완료 — {len(findings)}개 발견")

    def _show_finding_detail(self):
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 1)
        finding = item.data(Qt.UserRole) if item else None
        if finding:
            FindingDetailDialog(finding, self.url_edit.text().strip(), self).exec_()

    # -------------------------------------------------------------- export
    def export_report(self):
        if not self.findings:
            return
        path, chosen = QFileDialog.getSaveFileName(
            self, "리포트 저장", "bugbounty_report.html",
            "HTML 리포트 (*.html);;버그바운티 보고서 Markdown (*.md);;JSON (*.json)")
        if not path:
            return
        target = self.url_edit.text().strip()
        try:
            if path.lower().endswith(".json"):
                content = report.to_json(target, self.findings)
            elif path.lower().endswith(".md"):
                content = report.findings_to_report_md(target, self.findings)
            else:
                content = report.to_html(target, self.findings)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        except Exception as e:
            QMessageBox.critical(self, "저장 실패", str(e))
            return
        QMessageBox.information(self, "저장 완료", f"리포트를 저장했습니다:\n{path}")

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.worker.request_stop()
            self.worker.wait(4000)
        super().closeEvent(event)


def run_app():
    load_all()
    import sys
    from gui import theme
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(theme.STYLESHEET)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
