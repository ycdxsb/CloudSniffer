from statistics import *
from pcap_decode import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from qtpy.QtWebEngineWidgets import *
from pcap import *
from scapy.all import *
#import scapy_http.http as http
import dpkt
import sys
import os
import re
import time
import datetime
import threading
import logging
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
        font = QFont("Source Code Pro", 14)
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
        self.chooseNICComboBox.setFont(font)

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

        '''
        self.protocolLineEdit = QLineEdit()
        self.protocolLineEdit.setFixedHeight(32)
        self.protocolLineEdit.setFixedWidth(80)
        '''
        self.protocolComboBox = QComboBox()
        self.protocolComboBox.setFixedHeight(32)
        self.protocolComboBox.setFixedWidth(100)
        tmp = ['all', 'arp only', 'tcp only',
               'udp only', 'tcp or udp', 'ip only']
        self.protocolComboBox.addItems(tmp)
        self.protocolComboBox.setFont(font)

        self.srcIpLabel = QLabel()
        self.srcIpLabel.setText("源地址: ")
        self.srcIpLabel.setFixedHeight(32)
        self.srcIpLabel.setFixedWidth(60)
        self.srcIpLabel.setAlignment(Qt.AlignCenter)

        self.srcIpLineEdit = QLineEdit()
        self.srcIpLineEdit.setFixedHeight(32)
        self.srcIpLineEdit.setFixedWidth(100)
        self.srcIpLineEdit.setFont(font)

        self.srcPortLabel = QLabel()
        self.srcPortLabel.setText("源端口: ")
        self.srcPortLabel.setFixedHeight(32)
        self.srcPortLabel.setFixedWidth(60)
        self.srcPortLabel.setAlignment(Qt.AlignCenter)

        self.srcPortLineEdit = QLineEdit()
        self.srcPortLineEdit.setFixedHeight(32)
        self.srcPortLineEdit.setFixedWidth(40)
        self.srcPortLineEdit.setFont(font)

        self.desIpLabel = QLabel()
        self.desIpLabel.setText("目的地址: ")
        self.desIpLabel.setFixedHeight(32)
        self.desIpLabel.setFixedWidth(60)
        self.desIpLabel.setAlignment(Qt.AlignCenter)

        self.desIpLineEdit = QLineEdit()
        self.desIpLineEdit.setFixedHeight(32)
        self.desIpLineEdit.setFixedWidth(100)
        self.desIpLineEdit.setFont(font)

        self.desPortLabel = QLabel()
        self.desPortLabel.setText("目的端口: ")
        self.desPortLabel.setFixedHeight(32)
        self.desPortLabel.setFixedWidth(60)
        self.desPortLabel.setAlignment(Qt.AlignCenter)

        self.desPortLineEdit = QLineEdit()
        self.desPortLineEdit.setFixedHeight(32)
        self.desPortLineEdit.setFixedWidth(40)
        self.desPortLineEdit.setFont(font)

        self.filterBtn = QPushButton()
        self.filterBtn.setText("设置过滤")
        self.filterBtn.setFixedHeight(32)
        self.filterBtn.setFixedWidth(100)

        self.HLayoutMiddle.addWidget(
            self.protocolLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.HLayoutMiddle.addWidget(
            self.protocolComboBox, 0, Qt.AlignVCenter | Qt.AlignHCenter)
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
        self.HwidgetMiddle.setFixedHeight(40)

        # statistic
        self.statisticLabel = QLabel()
        self.statisticLabel.setFixedHeight(32)
        self.statisticLabel.setFixedWidth(100)
        self.statisticLabel.setText("统计功能 :")

        self.framesCountBtn = QPushButton()
        self.framesCountBtn.setText("帧数统计")
        self.framesCountBtn.setFixedHeight(32)
        self.framesCountBtn.setFixedWidth(100)

        self.bytesCountBtn = QPushButton()
        self.bytesCountBtn.setText("字节统计")
        self.bytesCountBtn.setFixedHeight(32)
        self.bytesCountBtn.setFixedWidth(100)

        self.statisitcHLayout = QHBoxLayout()
        self.statisticWidget = QWidget()
        self.statisitcHLayout.addWidget(
            self.statisticLabel, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.statisitcHLayout.addWidget(
            self.framesCountBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.statisitcHLayout.addWidget(
            self.bytesCountBtn, 0, Qt.AlignVCenter | Qt.AlignHCenter)
        self.statisticWidget.setLayout(self.statisitcHLayout)
        self.statisticWidget.setFixedHeight(40)

        # set package info
        # No Time Source Destination Protocol Length Info
        self.packageInfosTable = QTableWidget()
        self.packageInfosTable.verticalHeader().setVisible(False)
        self.packageInfosTable.setColumnCount(7)
        # self.packageInfosTable.setRowCount(50)
        self.packageInfosTable.setHorizontalHeaderLabels(
            ["序号", "时间", "源地址", "目的地址", "协议类型", "长度(bytes)", "信息"])
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
        self.packageInfosTable.setFixedHeight(350)

        self.packageDetailWin = QTextEdit()
        self.packageDetailWin.setFixedHeight(250)
        self.packageDetailWin.setFixedWidth(345)
        self.packageDetailWin.setStyleSheet(
            "border-right:5px solid #323232;border-top:2px solid #323232")
        self.packageDetailWin.setReadOnly(True)
        self.packageDetailWin.setFont(QFont("Source Code Pro", 14))

        self.hexdumpWindow = QTextEdit()
        self.hexdumpWindow.setFixedHeight(250)
        self.hexdumpWindow.setFixedWidth(650)
        self.hexdumpWindow.setStyleSheet("border-top:2px solid #323232")
        self.hexdumpWindow.setReadOnly(True)
        self.hexdumpWindow.setFont(QFont("Source Code Pro", 14))
        # set HLayoutBottom to HLayoutBottom
        self.HLayoutBottom.addWidget(self.packageDetailWin)
        self.HLayoutBottom.addWidget(self.hexdumpWindow)
        self.HwidgetBottom.setLayout(self.HLayoutBottom)

        # ------
        self.VLayout.addWidget(self.HwidgetTop)
        self.VLayout.addWidget(self.HwidgetMiddle)
        self.VLayout.addWidget(self.statisticWidget)
        self.VLayout.addWidget(self.packageInfosTable)
        self.VLayout.addWidget(self.HwidgetBottom)
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
        self.packageInfos = []
        self.stop_flag = False  # False: not stop; True: stop
        self.setfilter_flag = False  # False: have't set filter; True: have be setted
        self.filterString = ""
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

        self.framesCountBtn.clicked.connect(self.framesCountBtnHandle)
        self.bytesCountBtn.clicked.connect(self.bytesCountBtnHandle)

        self.packageInfosTable.clicked.connect(self.packageInfosTableHandle)

    def bytesCountBtnHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        #host_ip = get_host_ip(pkts)
        # print(host_ip)
        #print(data_in_out_ip(pkts, host_ip))
        datas = proto_flow_bytes(pkts)
        data = []
        for k, v in datas.items():
            data.append([k, v])
        pie = pie_rosetype(data, "")
        pie.render("./htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(800)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def framesCountBtnHandle(self):
        pkts = []
        for i in range(len(self.packageInfos)):
            pkts.append(self.packageInfos[i]['pkt'])
        datas = proto_flow_frames(pkts)
        data = []
        for k, v in datas.items():
            data.append([k, v])
        pie = pie_rosetype(data, "")
        pie.render("./htmls/render.html")
        view = QWebEngineView()
        view.load(QUrl("file:///%s/htmls/render.html" % (os.getcwd())))
        dialog = QDialog(self)
        dialog.setFixedHeight(600)
        dialog.setFixedWidth(800)
        l = QHBoxLayout()
        l.addWidget(view)
        dialog.setLayout(l)
        dialog.show()

    def packageInfosTableHandle(self, index):
        row = index.row()
        self.hexdumpWindow.setText(
            hexdump(self.packageInfos[row]['pkt'], dump=True))

        # detail show
        data = ""
        packageInfo = self.packageInfos[row]
        data += "Frame %d:\n\tlength: %d bytes\n\tinterface: %s\n" % (
            row+1, packageInfo['info']['len'], packageInfo['eth'])
        data += pkt_detail(packageInfo['pkt'])
        self.packageDetailWin.setText(data)

    def loadBtnHandle(self):
        logger.info("Load package begin")
        file, ok = QFileDialog.getOpenFileName(self)
        if(file == ''):
            logger.warning("Load file name is None")
            return
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
        self.packageDetailWin.clear()
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
        th = threading.Thread(target=self.capture_packages)
        th.start()

    def capture_packages(self):
        logger.info("Capture begin")
        while(not self.stop_flag):
            sniff(filter=self.filterString,
                  prn=self.deal_package, iface=self.eth, count=5)
        logger.info("Capture finish")

    def deal_package(self, pkt):
        info = self.pcapdecoder.ether_decode(pkt)
        self.packageInfos.append({'pkt': pkt, 'info': info, 'eth': self.eth})
        self.showOnTable(info)

    def showOnTable(self, info):
        count = self.packageInfosTable.rowCount()
        self.packageInfosTable.insertRow(count)
        # ["序号", "时间", "源地址", "目的地址", "协议类型", "长度", "信息"]
        font = QFont("Source Code Pro", 14)
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
        tmp = QTableWidgetItem(str(info['len']))
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

    def get_ip(self, ip):
        ip = ip.replace("\r", "")
        ip = ip.replace("\t", "")
        ip = ip.replace("\n", "")
        ip = ip.replace(" ", "")
        if(ip == ""):
            return ""
        trueIp = re.search(
            r'^(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])$', ip)
        if(trueIp == None):
            QMessageBox.warning(self, "警告", "ip格式有误，请重新输入",
                                QMessageBox.Yes, QMessageBox.Yes)
            return None
        return trueIp.string

    def get_port(self, port):
        port = port.replace("\r", "")
        port = port.replace("\t", "")
        port = port.replace("\n", "")
        port = port.replace(" ", "")
        if(port == ""):
            return -1
        try:
            port = int(port)
            if(port >= 0 and port <= 65535):
                return port
        except:
            QMessageBox.warning(self, "警告", "端口格式有误，请重新输入",
                                QMessageBox.Yes, QMessageBox.Yes)
            return None
        return -1

    def filterBtnHandle(self):
        # 1.filter the data showed on the table
        # 2.set the para for sniffer
        d = {'all': "", 'arp only': "arp", 'tcp only': "tcp",
             'udp only': "udp", 'tcp or udp': '(tcp or udp)', 'ip only': "ip"}
        self.protocol = d[self.protocolComboBox.currentText()]
        logger.info("Set protocol: %s" % self.protocol)
        tmp_srcIp = ""
        tmp_srcPort = -1
        tmp_desIp = ""
        tmp_desPort = -1
        tmp_srcIp = self.get_ip(self.srcIpLineEdit.text())
        if(tmp_srcIp == None):
            logger.info("Set srcIp error" % self.srcIp)
            return
        tmp_srcPort = self.get_port(self.srcPortLineEdit.text())
        if(tmp_srcPort == None):
            logger.info("Set srcPort error" % self.srcIp)
            return
        tmp_desIp = self.get_ip(self.desIpLineEdit.text())
        if(tmp_desIp == None):
            logger.info("Set desIp error" % self.srcIp)
            return
        tmp_desPort = self.get_port(self.desPortLineEdit.text())
        if(tmp_desPort == None):
            logger.info("Set desPort error" % self.srcIp)
            return
        self.srcIp = tmp_srcIp
        self.srcPort = tmp_srcPort
        self.desIp = tmp_desIp
        self.desPort = tmp_desPort
        logger.info("Set srcIp: %s" % self.srcIp)
        logger.info("Set srcPort: %s" % self.srcPort)
        logger.info("Set desIp: %s" % self.desIp)
        logger.info("Set desPort: %s" % self.desPort)
        tmp = []
        tmp.append(self.protocol) if(self.protocol != "") else None
        tmp.append("src host %s" % self.srcIp) if(self.srcIp != "") else None
        tmp.append("src port %d" % self.srcPort) if(
            self.srcPort != -1) else None
        tmp.append("dst host %s" % self.desIp) if(self.desIp != "") else None
        tmp.append("dst port %d" % self.desPort) if(
            self.desPort != -1) else None
        self.filterString = " and ".join(tmp)
        logger.info("filter string is: %s" % self.filterString)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("./images/swords.ico"))
    # app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())
