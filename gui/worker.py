"""QThread wrapper that runs a Scanner and marshals results back to the GUI."""
from __future__ import annotations

from PyQt5.QtCore import QThread, pyqtSignal

from core.scanner import Scanner
from core.result import Finding


class ScanWorker(QThread):
    log_line = pyqtSignal(str)
    finding = pyqtSignal(object)          # Finding
    progress = pyqtSignal(int, int, str)  # current, total, module name
    done = pyqtSignal(list)               # list[Finding]
    frame = pyqtSignal(bytes)             # live browser screenshot (PNG)

    def __init__(self, target: str, module_ids: list[str], options: dict, parent=None):
        super().__init__(parent)
        self.target = target
        self.module_ids = module_ids
        self.options = options
        self._scanner: Scanner | None = None

    def run(self) -> None:  # executes in the worker thread
        self._scanner = Scanner(
            target=self.target,
            module_ids=self.module_ids,
            options=self.options,
            on_log=lambda m: self.log_line.emit(m),
            on_finding=lambda f: self.finding.emit(f),
            on_progress=lambda c, t, n: self.progress.emit(c, t, n),
            on_done=lambda fs: self.done.emit(fs),
            on_frame=lambda png: self.frame.emit(png),
        )
        self._scanner.run()

    def request_stop(self) -> None:
        if self._scanner is not None:
            self._scanner.stop()
