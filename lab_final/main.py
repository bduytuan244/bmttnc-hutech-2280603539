# FILE: main.py
import sys
import os
import ast # Dùng để đọc list RSA từ file text
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QRadioButton, QGroupBox, QFileDialog, QMessageBox)
from algorithms import CryptoEngine

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Lab Final - Encryption Tool (No Lib)")
        self.setGeometry(100, 100, 700, 500)
        
        self.engine = CryptoEngine()
        self.rsa_pub_key = None
        self.rsa_priv_key = None
        
        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        
        # --- SECTION 1: FILES ---
        grp_files = QGroupBox("1. File Selection")
        lyt_files = QVBoxLayout()
        
        # Input
        lyt_in = QHBoxLayout()
        self.txt_in = QLineEdit()
        btn_in = QPushButton("Browse Input")
        btn_in.clicked.connect(self.browse_in)
        lyt_in.addWidget(QLabel("Input:"))
        lyt_in.addWidget(self.txt_in)
        lyt_in.addWidget(btn_in)
        
        # Output
        lyt_out = QHBoxLayout()
        self.txt_out = QLineEdit()
        btn_out = QPushButton("Browse Output")
        btn_out.clicked.connect(self.browse_out)
        lyt_out.addWidget(QLabel("Output:"))
        lyt_out.addWidget(self.txt_out)
        lyt_out.addWidget(btn_out)
        
        lyt_files.addLayout(lyt_in)
        lyt_files.addLayout(lyt_out)
        grp_files.setLayout(lyt_files)
        layout.addWidget(grp_files)
        
        # --- SECTION 2: ALGORITHM & KEY ---
        grp_algo = QGroupBox("2. Settings")
        lyt_algo = QVBoxLayout()
        
        # Radio Buttons
        lyt_rbs = QHBoxLayout()
        self.rb_aes = QRadioButton("AES")
        self.rb_des = QRadioButton("DES (Demo)")
        self.rb_3des = QRadioButton("Triple DES") # <--- Mới thêm
        self.rb_rsa = QRadioButton("RSA")
        
        self.rb_aes.setChecked(True)
        
        # Kết nối sự kiện để ẩn/hiện ô nhập Key
        self.rb_aes.toggled.connect(self.toggle_rsa_mode)
        self.rb_des.toggled.connect(self.toggle_rsa_mode)
        self.rb_3des.toggled.connect(self.toggle_rsa_mode) # <--- Mới thêm
        self.rb_rsa.toggled.connect(self.toggle_rsa_mode)
        
        lyt_rbs.addWidget(self.rb_aes)
        lyt_rbs.addWidget(self.rb_des)
        lyt_rbs.addWidget(self.rb_3des) # <--- Mới thêm
        lyt_rbs.addWidget(self.rb_rsa)
        
        # Key Input
        lyt_key = QHBoxLayout()
        self.lbl_key = QLabel("Secret Key:")
        self.txt_key = QLineEdit()
        self.txt_key.setEchoMode(QLineEdit.Password)
        self.btn_gen_rsa = QPushButton("Generate RSA Keys")
        self.btn_gen_rsa.setVisible(False)
        self.btn_gen_rsa.clicked.connect(self.generate_rsa_keys)
        
        lyt_key.addWidget(self.lbl_key)
        lyt_key.addWidget(self.txt_key)
        lyt_key.addWidget(self.btn_gen_rsa)
        
        lyt_algo.addLayout(lyt_rbs)
        lyt_algo.addLayout(lyt_key)
        grp_algo.setLayout(lyt_algo)
        layout.addWidget(grp_algo)

        # --- SECTION 3: ACTIONS ---
        lyt_act = QHBoxLayout()
        btn_enc = QPushButton("ENCRYPT")
        btn_enc.setFixedHeight(50)
        btn_enc.setStyleSheet("background-color: #d4edda; font-weight: bold;")
        btn_enc.clicked.connect(lambda: self.process(True))
        
        btn_dec = QPushButton("DECRYPT")
        btn_dec.setFixedHeight(50)
        btn_dec.setStyleSheet("background-color: #f8d7da; font-weight: bold;")
        btn_dec.clicked.connect(lambda: self.process(False))
        
        lyt_act.addWidget(btn_enc)
        lyt_act.addWidget(btn_dec)
        layout.addLayout(lyt_act)
        
        main_widget.setLayout(layout)

    def browse_in(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select Input")
        if f:
            self.txt_in.setText(f)
            self.txt_out.setText(f + ".processed")

    def browse_out(self):
        f, _ = QFileDialog.getSaveFileName(self, "Select Output")
        if f: self.txt_out.setText(f)

    def toggle_rsa_mode(self):
        is_rsa = self.rb_rsa.isChecked()
        # Nếu chọn RSA thì ẩn ô Key đi, hiện nút Generate Key
        self.txt_key.setVisible(not is_rsa)
        self.lbl_key.setVisible(not is_rsa)
        self.btn_gen_rsa.setVisible(is_rsa)
        
        if is_rsa:
            QMessageBox.information(self, "RSA Mode", "Click 'Generate RSA Keys' to create a key pair first.")

    def generate_rsa_keys(self):
        # Tạo RSA Key và lưu vào biến
        pub, priv = self.engine.rsa_gen_keys()
        self.rsa_pub_key = pub
        self.rsa_priv_key = priv
        QMessageBox.information(self, "Keys Generated", f"Public: {pub}\nPrivate: {priv}\n(Saved in memory)")

    def process(self, is_encrypt):
        inp_path = self.txt_in.text()
        out_path = self.txt_out.text()
        
        if not os.path.exists(inp_path):
            QMessageBox.warning(self, "Error", "Input file not found!")
            return

        try:
            # 1. READ FILE
            with open(inp_path, 'rb') as f:
                data = f.read()

            result = b""

            # 2. PROCESS ALGORITHMS
            # --- AES ---
            if self.rb_aes.isChecked():
                key_raw = self.txt_key.text().encode()
                if not key_raw: raise ValueError("Please enter a key!")
                
                if is_encrypt:
                    result = self.engine.aes_encrypt_file(data, key_raw)
                else:
                    result = self.engine.aes_decrypt_file(data, key_raw)
            
            # --- DES ---
            elif self.rb_des.isChecked():
                key_raw = self.txt_key.text().encode()
                if not key_raw: raise ValueError("Please enter a key!")

                if is_encrypt:
                    result = self.engine.aes_encrypt_file(data, key_raw) # Demo dùng AES core
                else:
                    result = self.engine.aes_decrypt_file(data, key_raw)

            # --- TRIPLE DES --- (Đã thêm mới)
            elif self.rb_3des.isChecked():
                key_raw = self.txt_key.text().encode()
                if not key_raw: raise ValueError("Please enter a key!")
                
                if is_encrypt:
                    result = self.engine.triple_des_encrypt_file(data, key_raw)
                else:
                    result = self.engine.triple_des_decrypt_file(data, key_raw)

            # --- RSA ---
            elif self.rb_rsa.isChecked():
                if not self.rsa_pub_key:
                    raise ValueError("Please generate RSA keys first!")
                
                if is_encrypt:
                    # RSA trả về List int -> lưu dưới dạng text để dễ đọc lại
                    cipher_ints = self.engine.rsa_encrypt(data, self.rsa_pub_key)
                    result = str(cipher_ints).encode('utf-8')
                else:
                    # Đọc text -> List int -> Decrypt
                    try:
                        cipher_ints = ast.literal_eval(data.decode('utf-8'))
                        result = self.engine.rsa_decrypt(cipher_ints, self.rsa_priv_key)
                    except:
                        raise ValueError("Invalid RSA format input")

            # 3. WRITE FILE
            with open(out_path, 'wb') as f:
                f.write(result)
            
            msg = "Encryption" if is_encrypt else "Decryption"
            QMessageBox.information(self, "Success", f"{msg} Done!\nSaved to: {out_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())