import sys
import os
import ast  
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QRadioButton, QGroupBox, QFileDialog, QMessageBox, QStyle)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt
from algorithms import CryptoEngine

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Công Cụ Mã Hóa An Toàn")
        self.setGeometry(100, 100, 750, 550)
        
        self.engine = CryptoEngine()
        self.rsa_pub_key = None
        self.rsa_priv_key = None
        
        self.init_ui()
        self.apply_stylesheet()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(25, 25, 25, 25)

        grp_files = QGroupBox("FILE NGUỒN & ĐÍCH")
        grp_files.setObjectName("grp_files") 
        lyt_files = QVBoxLayout()
        lyt_files.setSpacing(15)

        lyt_in = QHBoxLayout()
        lbl_in = QLabel("Input:")
        lbl_in.setFixedWidth(120)
        self.txt_in = QLineEdit()
        self.txt_in.setPlaceholderText("Chọn đường dẫn file cần xử lý...")
        
        btn_in = QPushButton()
        btn_in.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        btn_in.setFixedWidth(40)
        btn_in.setObjectName("btn_browse")
        btn_in.clicked.connect(self.browse_in)

        lyt_in.addWidget(lbl_in)
        lyt_in.addWidget(self.txt_in)
        lyt_in.addWidget(btn_in)

        lyt_out = QHBoxLayout()
        lbl_out = QLabel("Output:")
        lbl_out.setFixedWidth(120)
        self.txt_out = QLineEdit()
        self.txt_out.setPlaceholderText("Chọn nơi lưu file kết quả...")

        btn_out = QPushButton()
        btn_out.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        btn_out.setFixedWidth(40)
        btn_out.setObjectName("btn_browse")
        btn_out.clicked.connect(self.browse_out)

        lyt_out.addWidget(lbl_out)
        lyt_out.addWidget(self.txt_out)
        lyt_out.addWidget(btn_out)

        lyt_files.addLayout(lyt_in)
        lyt_files.addLayout(lyt_out)
        grp_files.setLayout(lyt_files)
        main_layout.addWidget(grp_files)

        grp_algo = QGroupBox("THUẬT TOÁN & KHÓA BẢO MẬT")
        grp_algo.setObjectName("grp_algo")
        lyt_algo = QVBoxLayout()
        lyt_algo.setSpacing(15)

        lyt_rbs = QHBoxLayout()
        lyt_rbs.setSpacing(20)
        self.rb_aes = QRadioButton("AES")
        self.rb_des = QRadioButton("DES")
        self.rb_3des = QRadioButton("Triple DES")
        self.rb_rsa = QRadioButton("RSA ")
        
        self.rb_aes.setChecked(True)

        self.rb_aes.toggled.connect(self.toggle_rsa_mode)
        self.rb_des.toggled.connect(self.toggle_rsa_mode)
        self.rb_3des.toggled.connect(self.toggle_rsa_mode)
        self.rb_rsa.toggled.connect(self.toggle_rsa_mode)

        lyt_rbs.addWidget(self.rb_aes)
        lyt_rbs.addWidget(self.rb_des)
        lyt_rbs.addWidget(self.rb_3des)
        lyt_rbs.addWidget(self.rb_rsa)

        lyt_key = QHBoxLayout()
        self.lbl_key = QLabel("Khóa Bí Mật (Key):")
        self.lbl_key.setFixedWidth(120)
        self.txt_key = QLineEdit()
        self.txt_key.setEchoMode(QLineEdit.Password)
        self.txt_key.setPlaceholderText("Nhập mật khẩu...")
        self.txt_key.setObjectName("txt_key")

        self.btn_gen_rsa = QPushButton("Tạo Cặp Khóa RSA Mới")
        self.btn_gen_rsa.setObjectName("btn_gen_rsa")
        self.btn_gen_rsa.setVisible(False)
        self.btn_gen_rsa.clicked.connect(self.generate_rsa_keys)

        lyt_key.addWidget(self.lbl_key)
        lyt_key.addWidget(self.txt_key)
        lyt_key.addWidget(self.btn_gen_rsa)

        lyt_algo.addLayout(lyt_rbs)
        lyt_algo.addLayout(lyt_key)
        grp_algo.setLayout(lyt_algo)
        main_layout.addWidget(grp_algo)

        lyt_act = QHBoxLayout()
        lyt_act.setSpacing(30)
        
        btn_enc = QPushButton("MÃ HÓA (ENCRYPT)")
        btn_enc.setFixedHeight(55)
        btn_enc.setObjectName("btn_enc")
        btn_enc.clicked.connect(lambda: self.process(True))
        
        btn_dec = QPushButton("GIẢI MÃ (DECRYPT)")
        btn_dec.setFixedHeight(55)
        btn_dec.setObjectName("btn_dec")
        btn_dec.clicked.connect(lambda: self.process(False))

        lyt_act.addWidget(btn_enc)
        lyt_act.addWidget(btn_dec)
        main_layout.addLayout(lyt_act)

        main_widget.setLayout(main_layout)

    def apply_stylesheet(self):
        style = """
            QWidget {
                background-color: #f0f2f5;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 10pt;
            }
            QGroupBox {
                background-color: #ffffff;
                border: 2px solid #dce4ec;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
                color: #2c3e50;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                left: 10px;
            }
            QLineEdit {
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 6px;
                background-color: #ffffff;
            }
            QLineEdit:focus {
                border: 1px solid #3498db;
            }
            QLabel {
                color: #34495e;
                font-weight: 600;
            }
            QPushButton#btn_browse {
                background-color: #ecf0f1;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
            }
            QPushButton#btn_browse:hover {
                background-color: #bdc3c7;
            }
            QRadioButton {
                color: #2c3e50;
                font-weight: 500;
            }
            QPushButton#btn_enc {
                background-color: #2ecc71;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 12pt;
                font-weight: bold;
            }
            QPushButton#btn_enc:hover {
                background-color: #27ae60;
            }
            QPushButton#btn_dec {
                background-color: #e74c3c;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 12pt;
                font-weight: bold;
            }
            QPushButton#btn_dec:hover {
                background-color: #c0392b;
            }
            QPushButton#btn_gen_rsa {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton#btn_gen_rsa:hover {
                background-color: #2980b9;
            }
        """
        self.setStyleSheet(style)

    def browse_in(self):
        f, _ = QFileDialog.getOpenFileName(self, "Chọn File Nguồn")
        if f:
            self.txt_in.setText(f)
            if f.endswith(".enc"):
                self.txt_out.setText(f[:-4])
            else:
                self.txt_out.setText(f + ".enc")

    def browse_out(self):
        f, _ = QFileDialog.getSaveFileName(self, "Chọn File Đích")
        if f: self.txt_out.setText(f)

    def toggle_rsa_mode(self):
        is_rsa = self.rb_rsa.isChecked()
        self.txt_key.setVisible(not is_rsa)
        self.lbl_key.setVisible(not is_rsa)
        self.btn_gen_rsa.setVisible(is_rsa)
        
        if is_rsa and not self.rsa_pub_key:
             QMessageBox.information(self, "Chế Độ RSA", "Vui lòng nhấn nút 'Tạo Cặp Khóa RSA Mới' để bắt đầu.")

    def generate_rsa_keys(self):
        pub, priv = self.engine.rsa_gen_keys()
        self.rsa_pub_key = pub
        self.rsa_priv_key = priv
        QMessageBox.information(self, "Thành Công", f"Đã tạo khóa RSA!\n\nPublic Key: {pub}\nPrivate Key: {priv}\n(Khóa chỉ lưu tạm trong bộ nhớ)")

    def process(self, is_encrypt):
        inp_path = self.txt_in.text()
        out_path = self.txt_out.text()
        
        if not os.path.exists(inp_path):
            QMessageBox.warning(self, "Lỗi", "File nguồn không tồn tại!")
            return
        if not out_path:
             QMessageBox.warning(self, "Lỗi", "Vui lòng chọn đường dẫn file đích!")
             return

        try:
            with open(inp_path, 'rb') as f:
                data = f.read()

            result = b""

            if self.rb_aes.isChecked():
                key_raw = self.txt_key.text().encode()
                if not key_raw: raise ValueError("Vui lòng nhập khóa bí mật!")
                result = self.engine.aes_encrypt_file(data, key_raw) if is_encrypt else self.engine.aes_decrypt_file(data, key_raw)
            
            elif self.rb_des.isChecked():
                key_raw = self.txt_key.text().encode()
                if not key_raw: raise ValueError("Vui lòng nhập khóa bí mật!")
                result = self.engine.aes_encrypt_file(data, key_raw) if is_encrypt else self.engine.aes_decrypt_file(data, key_raw)

            elif self.rb_3des.isChecked():
                key_raw = self.txt_key.text().encode()
                if not key_raw: raise ValueError("Vui lòng nhập khóa bí mật!")
                result = self.engine.triple_des_encrypt_file(data, key_raw) if is_encrypt else self.engine.triple_des_decrypt_file(data, key_raw)

            elif self.rb_rsa.isChecked():
                if not self.rsa_pub_key:
                    raise ValueError("Bạn chưa tạo khóa RSA!")
                
                if is_encrypt:
                    cipher_ints = self.engine.rsa_encrypt(data, self.rsa_pub_key)
                    result = str(cipher_ints).encode('utf-8')
                else:
                    try:
                        cipher_ints = ast.literal_eval(data.decode('utf-8'))
                        result = self.engine.rsa_decrypt(cipher_ints, self.rsa_priv_key)
                    except:
                        raise ValueError("File input không đúng định dạng RSA!")

            with open(out_path, 'wb') as f:
                f.write(result)
            
            action = "Mã hóa" if is_encrypt else "Giải mã"
            QMessageBox.information(self, "Thành Công", f"{action} hoàn tất!\nFile lưu tại: {out_path}")

        except Exception as e:
            QMessageBox.critical(self, "Lỗi", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())