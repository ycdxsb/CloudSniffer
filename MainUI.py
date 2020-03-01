import sys
import os

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *


class MainUI(QDialog):
    def __init__(self, parent=None):
        super(MainUI, self).__init__(parent)
        self.setUpUI()

    def setUpUI(self):
        self.resize(900, 600)
        pass


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainUI = MainUI()
    mainUI.show()
    sys.exit(app.exec_())
