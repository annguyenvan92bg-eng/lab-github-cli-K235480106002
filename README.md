\# Thông tin sinh viên

* Tên :Nguyễn Văn An
* MSSV:K235480106002
* Lớp :K59KMT


\# Môn An toàn và bảo mật thông tin

\## 1. Tìm hiểu thuật toán mã hoá hiện đại DES, AES



\### 1.1. DES (Data Encryption Standard)



\- Ra đời năm 1977, là thuật toán mã hoá khối (block cipher).

\- Kích thước khối: 64 bit. Kích thước khoá: 56 bit hiệu dụng (64 bit lưu trữ, 8 bit dùng kiểm tra chẵn lẻ).

\- Cấu trúc: mạng Feistel, gồm 16 vòng lặp, mỗi vòng sử dụng một khoá con (subkey) được sinh ra từ khoá gốc thông qua thuật toán Key Schedule.



\*\*Quy trình mã hoá:\*\*

1\. Bản rõ 64 bit đi qua hoán vị khởi tạo (Initial Permutation - IP).

2\. Chia thành 2 nửa trái/phải (L, R), mỗi nửa 32 bit.

3\. Thực hiện 16 vòng Feistel: `L(i) = R(i-1)`, `R(i) = L(i-1) XOR F(R(i-1), K(i))`.

4\. Ghép 2 nửa cuối, đi qua hoán vị nghịch đảo (Final Permutation - FP) để ra bản mã.



\*\*Quy trình giải mã:\*\* dùng đúng cấu trúc thuật toán trên nhưng áp dụng các khoá con theo thứ tự ngược lại (K16 → K1).



\*\*Hạn chế:\*\* khoá 56 bit quá ngắn, dễ bị tấn công vét cạn (brute-force). Do đó DES đã bị thay thế bởi AES.



\### 1.2. AES (Advanced Encryption Standard)



\- Được NIST chuẩn hoá năm 2001 để thay thế DES.

\- Kích thước khối: 128 bit cố định. Kích thước khoá: 128 / 192 / 256 bit, tương ứng số vòng lặp 10 / 12 / 14.

\- Cấu trúc: mạng thay thế - hoán vị (SPN), không dùng cấu trúc Feistel như DES.



\*\*Mỗi vòng lặp AES gồm 4 bước biến đổi:\*\*

1\. \*\*SubBytes:\*\* thay thế từng byte qua bảng tra cứu S-box.

2\. \*\*ShiftRows:\*\* dịch vòng các hàng của ma trận trạng thái.

3\. \*\*MixColumns:\*\* trộn dữ liệu theo cột bằng phép nhân trên GF(2^8) (bỏ qua ở vòng cuối).

4\. \*\*AddRoundKey:\*\* XOR trạng thái hiện tại với khoá con của vòng đó.



\*\*Quy trình mã hoá/giải mã:\*\* mã hoá thực hiện tuần tự 4 bước trên qua các vòng; giải mã thực hiện các phép biến đổi nghịch đảo theo thứ tự ngược lại.



\*\*Ưu điểm so với DES:\*\* khoá dài hơn nhiều, cấu trúc SPN khuếch tán và gây rối hiệu quả hơn, hiện chưa có tấn công thực tế nào phá được AES với khoá đủ dài.



\### 1.3. Cài đặt AES bằng Python



Xem file \[`aes\_demo.py`](./aes\_demo.py) — cài đặt minh hoạ mã hoá/giải mã AES-128 chế độ CBC bằng thư viện `pycryptodome`.



Cách chạy:

pip install pycryptodome

python aes\_demo.py

\## 2. Tìm hiểu thuật toán mã hoá bất đối xứng RSA



\### 2.1. Nguyên lý sinh cặp khoá bí mật / công khai



1\. Chọn 2 số nguyên tố lớn `p` và `q` (giữ bí mật).

2\. Tính `n = p × q`.

3\. Tính hàm Euler: `φ(n) = (p - 1)(q - 1)`.

4\. Chọn `e` sao cho `1 < e < φ(n)` và `gcd(e, φ(n)) = 1`.

5\. Tính `d` là nghịch đảo modulo của `e`: `d × e ≡ 1 (mod φ(n))`.

6\. \*\*Khoá công khai:\*\* `(e, n)` — công bố rộng rãi.

7\. \*\*Khoá bí mật:\*\* `(d, n)` — chỉ chủ sở hữu giữ.



\### 2.2. Mã hoá / giải mã



\- Mã hoá: `C = M^e mod n`

\- Giải mã: `M = C^d mod n`



Độ an toàn của RSA dựa trên độ khó của bài toán phân tích một số nguyên rất lớn thành tích 2 số nguyên tố, với `n` thường dài 2048 bit trở lên trong thực tế.



\## 3. Mô hình và ứng dụng thuật toán RSA



\### 3.1. Xác thực người gửi (chữ ký số)



Người gửi mã hoá (ký) bằng \*\*khoá bí mật của chính mình\*\*. Ai cũng có thể xác minh bằng khoá công khai tương ứng, chứng tỏ thông điệp đúng do người gửi tạo ra, không bị giả mạo.



\### 3.2. Xác thực người nhận (bảo mật thông tin)



Người gửi mã hoá bằng \*\*khoá công khai của người nhận\*\*. Chỉ người nhận giữ khoá bí mật tương ứng mới giải mã được.



\### 3.3. Kết hợp cả hai (ký + mã hoá)



Ký bằng khoá bí mật người gửi, sau đó mã hoá bằng khoá công khai người nhận → vừa xác thực nguồn gốc, vừa bảo mật nội dung.



\### 3.4. So sánh thời gian mã hoá/giải mã RSA với AES



| Tiêu chí | AES | RSA |

|---|---|---|

| Loại thuật toán | Đối xứng | Bất đối xứng |

| Tốc độ | Rất nhanh | Chậm hơn AES hàng trăm-nghìn lần |

| Độ dài khoá | 128/192/256 bit | 2048+ bit |

| Vấn đề chính | Cần trao đổi khoá bí mật an toàn trước | Không cần trao đổi khoá bí mật, nhưng chậm |



\### 3.5. Kết hợp sức mạnh RSA và AES (mô hình lai)



1\. Sinh ngẫu nhiên khoá phiên (session key) dùng cho AES.

2\. Dùng \*\*RSA\*\* mã hoá khoá phiên này bằng khoá công khai người nhận rồi gửi đi.

3\. Dùng \*\*AES\*\* với khoá phiên vừa trao đổi để mã hoá toàn bộ dữ liệu thực tế.



Mô hình này (dùng trong TLS/HTTPS) tận dụng khả năng trao đổi khoá an toàn của RSA và tốc độ xử lý nhanh của AES.

