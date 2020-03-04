import sys
import os

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import qdarkstyle
from pcap import *


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setUpUI()

    def setUpUI(self):
        self.title = "Sniffer"
        self.setWindowTitle(self.title)
        self.setFixedSize(1000, 800)

        self.widget = QWidget(self)
        self.HLayoutTop = QHBoxLayout()
        self.HLayoutMiddle = QHBoxLayout()
        self.HLayoutBottom = QHBoxLayout()
        self.HwidgetTop = QWidget()
        self.HwidgetMiddle = QWidget()
        self.HwidgetBottom = QWidget()
        self.VLayout = QVBoxLayout()

        self.setCentralWidget(self.widget)

        # set HLayoutTop to HwidgetTop

        self.chooseNICLabel = QLabel("选择网卡:")
        self.chooseNICLabel.setFixedHeight(32)
        self.chooseNICLabel.setFixedWidth(100)
        self.chooseNICLabel.setAlignment(Qt.AlignCenter)

        self.chooseNICComboBox = QComboBox()
        self.chooseNICComboBox.setFixedHeight(32)
        self.chooseNICComboBox.setFixedWidth(160)
        devs = findalldevs()
        self.chooseNICComboBox.addItems(devs)

        self.beginBtn = QPushButton()
        self.beginBtn.setText("开始抓包")
        self.beginBtn.setFixedHeight(32)
        self.beginBtn.setFixedWidth(100)

        self.stopBtn = QPushButton()
        self.stopBtn.setText("停止抓包")
        self.stopBtn.setFixedHeight(32)
        self.stopBtn.setFixedWidth(100)

        self.saveBtn = QPushButton()
        self.saveBtn.setText("保存数据")
        self.saveBtn.setFixedHeight(32)
        self.saveBtn.setFixedWidth(100)

        self.existBtn = QPushButton()
        self.existBtn.setText("退出程序")
        self.existBtn.setFixedHeight(32)
        self.existBtn.setFixedWidth(100)

        self.HLayoutTop.addWidget(
            self.chooseNICLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.chooseNICComboBox, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.beginBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.stopBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.saveBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.existBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)

        self.HwidgetTop.setLayout(self.HLayoutTop)
        self.HwidgetTop.setFixedWidth(800)
        self.HwidgetTop.setFixedHeight(40)

        # set HLayoutMiddle to HwidgetMiddle
        '''
        self.filterLabel = QLabel()
        self.filterLabel.setText("过滤功能: ")
        self.filterLabel.setFixedHeight(32)
        self.filterLabel.setFixedWidth(60)
        self.filterLabel.setAlignment(Qt.AlignCenter)
        ''' 
        
        self.protolLabel = QLabel()
        self.protolLabel.setText("通讯协议: ")
        self.protolLabel.setFixedHeight(32)
        self.protolLabel.setFixedWidth(60)
        self.protolLabel.setAlignment(Qt.AlignCenter)

        self.protolLineEdit = QLineEdit()
        self.protolLineEdit.setFixedHeight(32)
        self.protolLineEdit.setFixedWidth(80)

        self.srcIpLabel = QLabel()
        self.srcIpLabel.setText("源地址: ")
        self.srcIpLabel.setFixedHeight(32)
        self.srcIpLabel.setFixedWidth(60)
        self.srcIpLabel.setAlignment(Qt.AlignCenter)

        self.srcIpLineEdit = QLineEdit()
        self.srcIpLineEdit.setFixedHeight(32)
        self.srcIpLineEdit.setFixedWidth(100)

        self.srcPortLabel = QLabel()
        self.srcPortLabel.setText("源端口: ")
        self.srcPortLabel.setFixedHeight(32)
        self.srcPortLabel.setFixedWidth(60)
        self.srcPortLabel.setAlignment(Qt.AlignCenter)

        self.srcPortLineEdit = QLineEdit()
        self.srcPortLineEdit.setFixedHeight(32)
        self.srcPortLineEdit.setFixedWidth(40)

        self.desIpLabel = QLabel()
        self.desIpLabel.setText("目的地址: ")
        self.desIpLabel.setFixedHeight(32)
        self.desIpLabel.setFixedWidth(60)
        self.desIpLabel.setAlignment(Qt.AlignCenter)

        self.desIpLineEdit = QLineEdit()
        self.desIpLineEdit.setFixedHeight(32)
        self.desIpLineEdit.setFixedWidth(100)

        self.desPortLabel = QLabel()
        self.desPortLabel.setText("目的端口: ")
        self.desPortLabel.setFixedHeight(32)
        self.desPortLabel.setFixedWidth(60)
        self.desPortLabel.setAlignment(Qt.AlignCenter)

        self.desPortLineEdit = QLineEdit()
        self.desPortLineEdit.setFixedHeight(32)
        self.desPortLineEdit.setFixedWidth(40)

        self.filterBtn = QPushButton()
        self.filterBtn.setText("设置过滤")
        self.filterBtn.setFixedHeight(32)
        self.filterBtn.setFixedWidth(100)

        #self.HLayoutMiddle.addWidget(
        #    self.filterLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.protolLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.protolLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.srcIpLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.srcIpLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.srcPortLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.srcPortLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.desIpLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.desIpLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.desPortLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.desPortLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.filterBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HwidgetMiddle.setLayout(self.HLayoutMiddle)
        
        # set HLayoutBottom to HLayoutBottom

        # ------
        self.VLayout.addWidget(self.HwidgetTop)
        self.VLayout.addWidget(self.HwidgetMiddle)
        self.widget.setLayout(self.VLayout)
        return


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("./images/swords.ico"))
    # app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())
