from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from pcap import *
from scapy.all import *
import dpkt
import sys
import os
import time
import datetime
import threading
import logging
from pcap_decode import PcapDecode

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        logger.info("Sniffer is starting")
        self.setUpUI()
        self.setUpSnifferInfos()
        self.setSignalConnect()

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
        self.chooseNICLabel.setFixedWidth(80)
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

        self.clearBtn = QPushButton()
        self.clearBtn.setText("清空数据")
        self.clearBtn.setFixedHeight(32)
        self.clearBtn.setFixedWidth(100)

        self.saveBtn = QPushButton()
        self.saveBtn.setText("保存数据")
        self.saveBtn.setFixedHeight(32)
        self.saveBtn.setFixedWidth(100)

        self.loadBtn = QPushButton()
        self.loadBtn.setText("读取数据")
        self.loadBtn.setFixedHeight(32)
        self.loadBtn.setFixedWidth(100)

        self.quitBtn = QPushButton()
        self.quitBtn.setText("退出程序")
        self.quitBtn.setFixedHeight(32)
        self.quitBtn.setFixedWidth(100)

        self.HLayoutTop.addWidget(
            self.chooseNICLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.chooseNICComboBox, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.beginBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.stopBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.clearBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.saveBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.loadBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutTop.addWidget(
            self.quitBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)

        self.HwidgetTop.setLayout(self.HLayoutTop)
        self.HwidgetTop.setFixedWidth(880)
        self.HwidgetTop.setFixedHeight(40)

        # set HLayoutMiddle to HwidgetMiddle
        self.protocolLabel = QLabel()
        self.protocolLabel.setText("协议类型: ")
        self.protocolLabel.setFixedHeight(32)
        self.protocolLabel.setFixedWidth(60)
        self.protocolLabel.setAlignment(Qt.AlignCenter)

        self.protocolLineEdit = QLineEdit()
        self.protocolLineEdit.setFixedHeight(32)
        self.protocolLineEdit.setFixedWidth(80)

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

        self.HLayoutMiddle.addWidget(
            self.protocolLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.protocolLineEdit, 0, Qt.AlignVCenter | Qt.AlignHCenter)
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

        # set package info
        # No Time Source Destination Protocol Length Info
        self.packageInfosTable = QTableWidget()
        self.packageInfosTable.verticalHeader().setVisible(False)
        self.packageInfosTable.setColumnCount(7)
        # self.packageInfosTable.setRowCount(50)
        self.packageInfosTable.setHorizontalHeaderLabels(
            ["序号", "时间", "源地址", "目的地址", "协议类型", "长度", "信息"])
        self.packageInfosTable.setEditTriggers(
            QAbstractItemView.NoEditTriggers)
        self.packageInfosTable.setSelectionBehavior(
            QAbstractItemView.SelectRows)
        self.packageInfosTable.setColumnWidth(0, 40)
        self.packageInfosTable.setColumnWidth(1, 140)
        self.packageInfosTable.setColumnWidth(2, 180)
        self.packageInfosTable.setColumnWidth(3, 180)
        self.packageInfosTable.setColumnWidth(4, 60)
        self.packageInfosTable.setColumnWidth(5, 80)
        self.packageInfosTable.setColumnWidth(6, 800)
        self.packageInfosTable.setFixedHeight(400)

        self.hexdumpWindow = QTextEdit()
        self.hexdumpWindow.setFixedHeight(300)
        self.hexdumpWindow.setReadOnly(True)
        self.hexdumpWindow.setFont(QFont("Source Code Pro",14))
        # set HLayoutBottom to HLayoutBottom

        # ------
        self.VLayout.addWidget(self.HwidgetTop)
        self.VLayout.addWidget(self.HwidgetMiddle)
        self.VLayout.addWidget(self.packageInfosTable)
        self.VLayout.addWidget(self.hexdumpWindow)
        self.widget.setLayout(self.VLayout)
        return

    def setUpSnifferInfos(self):
        if(len(findalldevs()) != 0):
            self.eth = findalldevs()[0]
            logger.info("Set interface %s" % self.eth)
        else:
            self.eth = None
            logger.warning("There is no interface on this os")
        self.protocol = None
        self.srcIp = None
        self.srcPort = None
        self.desIp = None
        self.desPort = None
        self.packageInfos = None
        self.stop_flag = False  # False: not stop; True: stop
        self.setfilter_flag = False  # False: have't set filter; True: have be setted
        self.pcapdecoder = PcapDecode()

    def setSignalConnect(self):
        self.quitBtn.clicked.connect(self.quitBtnHandle)
        self.chooseNICComboBox.activated.connect(self.chooseNICComboBoxHandle)
        self.beginBtn.clicked.connect(self.beginBtnHandle)
        self.stopBtn.clicked.connect(self.stopBtnHandle)
        self.clearBtn.clicked.connect(self.clearBtnHandle)
        self.saveBtn.clicked.connect(self.saveBtnHandle)
        self.loadBtn.clicked.connect(self.loadBtnHandle)
        self.filterBtn.clicked.connect(self.filterBtnHandle)
        self.packageInfosTable.clicked.connect(self.packageInfosTableHandle)

    def packageInfosTableHandle(self, index):
        row = index.row()
        self.hexdumpWindow.setText(
            hexdump(self.packageInfos[row]['pkt'], dump=True))

    def loadBtnHandle(self):
        logger.info("Load package begin")
        file, ok = QFileDialog.getOpenFileName(self)
        self.clearBtnHandle()
        pkts = rdpcap(file)
        for i in range(len(pkts)):
            self.deal_package(pkts[i])
        logger.info("Load package done")

    def saveBtnHandle(self):
        logger.info("Save package begin")
        file, ok = QFileDialog.getSaveFileName(self)
        if(file == ''):
            logger.warning("Save file name is None")
            return
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        wrpcap(file, pkts)
        logger.info("Save package done")

    def clearBtnHandle(self):
        logger.info("Clean packages begin")
        self.packageInfos = []
        count = self.packageInfosTable.rowCount()
        for i in range(count-1, -1, -1):
            self.packageInfosTable.removeRow(i)
        self.hexdumpWindow.clear()
        logger.info("Clean packages done")

    def quitBtnHandle(self):
        self.stopBtnHandle()
        qApp = QApplication.instance()
        logger.info("Sniffer is shutting down")
        qApp.quit()

    def chooseNICComboBoxHandle(self):
        self.eth = self.chooseNICComboBox.currentText()
        logger.info("Set interface %s" % self.eth)

    def beginBtnHandle(self):
        logger.info("Begin sniff on interface %s" % self.eth)
        self.stop_flag = False
        self.packageInfos = []
        th = threading.Thread(target=self.capture_packages)
        th.start()

    def capture_packages(self):
        logger.info("Capture begin")
        while(not self.stop_flag):
            if(self.setfilter_flag):
                pass
            else:
                sniff(filter="", prn=self.deal_package, iface=self.eth, count=5)
        logger.info("Capture finish")

    def deal_package(self, pkt):
        info = self.pcapdecoder.ether_decode(pkt)
        self.packageInfos.append({'pkt': pkt, 'info': info})
        self.showOnTable(info)

    def showOnTable(self, info):
        count = self.packageInfosTable.rowCount()
        self.packageInfosTable.insertRow(count)
        # ["序号", "时间", "源地址", "目的地址", "协议类型", "长度", "信息"]
        font = QFont("Source Code Pro",14)
        tmp = QTableWidgetItem(str(count+1))
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 0, tmp)
        tmp = QTableWidgetItem(info['time'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 1, tmp)
        tmp = QTableWidgetItem(info['Source'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 2, tmp)
        tmp = QTableWidgetItem(info['Destination'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 3, tmp)
        tmp = QTableWidgetItem(info['Procotol'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 4, tmp)
        tmp = QTableWidgetItem(str(info['len'])+' bytes')
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 5, tmp)
        tmp = QTableWidgetItem(info['info'])
        tmp.setFont(font)
        self.packageInfosTable.setItem(
            count, 6, tmp)

    def stopBtnHandle(self):
        self.stop_flag = True
        logger.info("Stop sniff on interface %s" % self.eth)

    def filterBtnHandle(self):
        self.setfilter_flag = True
        self.protocol = self.protocolLineEdit.text()
        logger.info("Set protocol: %s" % self.protocol)
        self.srcIp = self.srcIpLineEdit.text()
        logger.info("Set srcIp: %s" % self.srcIp)
        self.srcPort = self.srcPortLineEdit.text()
        logger.info("Set srcPort: %s" % self.srcPort)
        self.desIp = self.desIpLineEdit.text()
        logger.info("Set desIp: %s" % self.desIp)
        self.desPort = self.desPortLineEdit.text()
        logger.info("Set desPort: %s" % self.desPort)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("./images/swords.ico"))
    # app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())
