Thông tin sinh viên

* Tên :Nguyễn Văn An
* MSSV:K235480106002
* Lớp :K59KMT


I. Môn An toàn và bảo mật thông tin

1\. Tìm hiểu thuật toán mã hoá hiện đại DES, AES

1.1. DES (Data Encryption Standard)

Ra đời năm 1977, là thuật toán mã hoá khối (block cipher).

Kích thước khối: 64 bit. Kích thước khoá: 56 bit hiệu dụng (64 bit lưu trữ, 8 bit dùng kiểm tra chẵn lẻ).

Cấu trúc: mạng Feistel, gồm 16 vòng lặp, mỗi vòng sử dụng một khoá con (subkey) được sinh ra từ khoá gốc thông qua thuật toán Key Schedule.



Quy trình mã hoá:



Bản rõ 64 bit đi qua hoán vị khởi tạo (Initial Permutation - IP).

Chia thành 2 nửa trái/phải (L, R), mỗi nửa 32 bit.

Thực hiện 16 vòng Feistel: L(i) = R(i-1), R(i) = L(i-1) XOR F(R(i-1), K(i)).

Ghép 2 nửa cuối, đi qua hoán vị nghịch đảo (Final Permutation - FP) để ra bản mã.



Quy trình giải mã: dùng đúng cấu trúc thuật toán trên nhưng áp dụng các khoá con theo thứ tự ngược lại (K16 → K1).



Hạn chế: khoá 56 bit quá ngắn so với khả năng tính toán hiện đại, dễ bị tấn công vét cạn (brute-force). Do đó DES đã bị thay thế bởi AES.



1.2. AES (Advanced Encryption Standard)

Được NIST chuẩn hoá năm 2001 để thay thế DES.

Kích thước khối: 128 bit cố định. Kích thước khoá: 128 / 192 / 256 bit, tương ứng số vòng lặp 10 / 12 / 14.

Cấu trúc: mạng thay thế - hoán vị (Substitution-Permutation Network - SPN), không dùng cấu trúc Feistel như DES.



Mỗi vòng lặp AES gồm 4 bước biến đổi:



SubBytes: thay thế từng byte của khối dữ liệu thông qua bảng tra cứu phi tuyến S-box.

ShiftRows: dịch vòng các hàng của ma trận trạng thái (state) theo các mức khác nhau.

MixColumns: trộn dữ liệu theo từng cột bằng phép nhân trên trường hữu hạn GF(2^8) (bước này bị bỏ qua ở vòng cuối).

AddRoundKey: thực hiện phép XOR giữa trạng thái hiện tại với khoá con của vòng đó.



Quy trình mã hoá/giải mã: mã hoá thực hiện tuần tự 4 bước trên qua các vòng; giải mã thực hiện các phép biến đổi nghịch đảo theo thứ tự ngược lại (InvSubBytes, InvShiftRows, InvMixColumns, AddRoundKey).



Ưu điểm so với DES: khoá dài hơn nhiều, cấu trúc SPN giúp khuếch tán (diffusion) và gây rối (confusion) hiệu quả hơn, hiện chưa có phương pháp tấn công thực tế nào phá được AES với khoá đủ dài.



1.3. Cài đặt AES bằng Python



Xem file aes\_demo.py — cài đặt minh hoạ quá trình mã hoá/giải mã AES-128 chế độ CBC bằng thư viện pycryptodome.



Cách chạy:



bash

pip install pycryptodome

python aes\_demo.py

2\. Tìm hiểu thuật toán mã hoá bất đối xứng RSA

2.1. Nguyên lý sinh cặp khoá bí mật / công khai

Chọn 2 số nguyên tố lớn p và q (giữ bí mật).

Tính n = p × q — dùng làm modulus cho cả khoá công khai và bí mật.

Tính hàm Euler: φ(n) = (p - 1)(q - 1).

Chọn số nguyên e sao cho 1 < e < φ(n) và gcd(e, φ(n)) = 1.

Tính d là nghịch đảo modulo của e: d × e ≡ 1 (mod φ(n)).

Khoá công khai (public key): (e, n) — được công bố rộng rãi.

Khoá bí mật (private key): (d, n) — chỉ chủ sở hữu giữ, không chia sẻ.

2.2. Mã hoá / giải mã

Mã hoá: C = M^e mod n

Giải mã: M = C^d mod n



Độ an toàn của RSA dựa trên độ khó của bài toán phân tích một số nguyên rất lớn thành tích 2 số nguyên tố (bài toán phân tích thừa số - integer factorization), với n thường có độ dài 2048 bit trở lên trong thực tế.



3\. Mô hình và ứng dụng thuật toán RSA

3.1. Xác thực người gửi (chữ ký số)



Người gửi mã hoá (ký) thông điệp bằng khoá bí mật của chính mình. Bất kỳ ai cũng có thể giải mã (xác minh) bằng khoá công khai tương ứng của người gửi. Nếu giải mã ra đúng nội dung, chứng tỏ thông điệp thực sự do người gửi đó tạo ra, không bị giả mạo → dùng cho chữ ký số.



3.2. Xác thực người nhận (bảo mật thông tin)



Người gửi mã hoá thông điệp bằng khoá công khai của người nhận. Chỉ người nhận — người duy nhất giữ khoá bí mật tương ứng — mới có thể giải mã được. Đảm bảo chỉ đúng người nhận đọc được nội dung → dùng để bảo mật dữ liệu truyền đi.



3.3. Kết hợp cả hai (ký + mã hoá)



Áp dụng cả 2 mô hình trên: người gửi ký bằng khoá bí mật của mình, sau đó mã hoá kết quả bằng khoá công khai của người nhận. Cách này vừa xác thực được nguồn gốc thông điệp, vừa đảm bảo bí mật nội dung, chỉ người nhận hợp lệ mới đọc được.



3.4. So sánh thời gian mã hoá/giải mã của RSA với AES

Tiêu chí	AES	RSA

Loại thuật toán	Đối xứng (symmetric)	Bất đối xứng (asymmetric)

Tốc độ	Rất nhanh, phù hợp mã hoá khối lượng dữ liệu lớn	Chậm hơn AES hàng trăm đến hàng nghìn lần do phải tính luỹ thừa modulo với số rất lớn

Độ dài khoá phổ biến	128 / 192 / 256 bit	2048 bit trở lên để đạt độ an toàn tương đương

Vấn đề chính	Cần có kênh an toàn để trao đổi khoá bí mật trước khi liên lạc	Không cần trao đổi khoá bí mật trước, nhưng tốc độ xử lý chậm

3.5. Kết hợp sức mạnh của RSA và AES (mô hình lai - Hybrid Encryption)



Đây là mô hình được sử dụng phổ biến trong thực tế, ví dụ giao thức TLS/HTTPS:



Sinh ngẫu nhiên một khoá phiên (session key) dùng cho AES.

Dùng RSA (khoá công khai của người nhận) để mã hoá khoá phiên AES này rồi gửi đi — tận dụng khả năng trao đổi khoá an toàn không cần kênh bí mật trước của RSA.

Dùng AES với khoá phiên vừa trao đổi để mã hoá toàn bộ dữ liệu thực tế — tận dụng tốc độ xử lý nhanh của AES.



Nhờ vậy hệ thống vừa giải quyết được bài toán trao đổi khoá an toàn (điểm mạnh của RSA), vừa đảm bảo hiệu năng xử lý dữ liệu lớn (điểm mạnh của AES).

