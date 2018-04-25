# -*- coding=utf-8 -*-
import os
import sys

from PyQt5.QtWidgets import *

from checkhole.check_xss_sql import scan_xss_sql

from port_scanner.port_scanner import PortScannerThread


class Scanner(QDialog):
    """主窗体类"""

    def __init__(self, parent=None):
        """构造函数"""
        super(Scanner, self).__init__(parent)
        self.initUI()   #初始化UI

    def initUI(self):

        # 设置窗体属性
        self.setWindowTitle("漏洞&端口扫描器")
        self.resize(700, 500)

        # 初始化控件
        targetURL = QLabel("请输入url和cookie(非必须)")
        self.targetURL = QLineEdit("http://website.com?param=")
        self.targetCookie = QLineEdit("非必须:security=low;PHPSESSID=olcj097i0t7ki99fc8rjp9pjl6")

        targetIP = QLabel("请输入ip：")
        self.targetIP = QLineEdit("127.0.0.1")

        hole_scan_btn = QPushButton("漏洞扫描")
        port_scan_btn = QPushButton("端口扫描")

        self.holeinfo = QListWidget()
        self.portinfo = QListWidget()

        # 布局控件
        gridLayout = QGridLayout()
        gridLayout.addWidget(targetURL, 0, 0, 1, 1)
        gridLayout.addWidget(self.targetURL, 1, 0, 1, 1)
        gridLayout.addWidget(self.targetCookie, 2, 0, 1, 1)
        gridLayout.addWidget(targetIP, 0, 1, 1, 3);
        gridLayout.addWidget(self.targetIP, 1, 1, 1, 3);

        gridLayout.addWidget(hole_scan_btn, 3, 0, 1, 1);
        gridLayout.addWidget(self.holeinfo, 4, 0, 3, 3);
        gridLayout.addWidget(port_scan_btn, 2, 1, 1, 3);
        gridLayout.addWidget(self.portinfo, 4, 1, 3, 3);

        self.setLayout(gridLayout)

        # 绑定按钮到方法
        hole_scan_btn.clicked.connect(self.hole_scan)
        port_scan_btn.clicked.connect(self.port_scan)


    def hole_scan(self):
        self.holeinfo.clear()
        targetURL = self.targetURL.text().encode("utf8")
        targetCookie = self.targetCookie.text().encode("utf8")
        result = scan_xss_sql(targetURL, targetCookie)
        self.holeinfo.addItems(result)

    def port_scan(self):
        self.portinfo.clear()
        targetIP = self.targetIP.text().encode("utf8")
        result = PortScannerThread(targetIP)
        self.portinfo.addItems(result)

app = QApplication(sys.argv)
dlg = Scanner()
dlg.show()
dlg.exec_()
app.exit()