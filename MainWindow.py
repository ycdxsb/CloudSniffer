import sys
import os

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setUpUI()

    def setUpUI(self):
        self.title = "Sniffer"
        self.setWindowTitle(self.title)
        self.setFixedSize(1000,800)

        self.widget = QWidget(self)
        self.setCentralWidget(self.widget)

        
        

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("./images/swords.ico"))
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())
