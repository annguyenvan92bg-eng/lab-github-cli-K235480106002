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



pip install pycryptodome

python aes\_demo.py
<img width="2560" height="1600" alt="Ảnh chụp màn hình 2026-09-26 160050" src="https://github.com/user-attachments/assets/3ef97a50-7c2b-476e-8339-2fac2184c8a8" />
*Ảnh kết quả chạy file demo thuật toán aes

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





II. Môn Lập trình Web 

\- Bài tập 1



&#x20;1. Lý thuyết



&#x20;1.1. Giả lập Linux OS 



Ảo hoá (virtualization) là công nghệ cho phép chạy một hệ điều hành (guest OS) bên trong một hệ điều hành khác (host OS) thông qua một lớp trung gian gọi là hypervisor.



Các công cụ phổ biến:

\- Hyper-V: hypervisor tích hợp sẵn trong Windows (bản Pro/Enterprise), thuộc loại Type-1 (chạy trực tiếp trên phần cứng).

\- VirtualBox / VMware: phần mềm ảo hoá Type-2 (chạy trên nền hệ điều hành host), giao diện quản lý máy ảo trực quan, cài đặt như một OS đầy đủ.

\- WSL (Windows Subsystem for Linux): không phải máy ảo truyền thống, mà là lớp tương thích cho phép chạy trực tiếp các bản phân phối Linux trên Windows. WSL2 (bản hiện tại) sử dụng một nhân Linux thật chạy trong một máy ảo nhẹ (lightweight VM) dựa trên nền tảng Hyper-V, nhưng được tích hợp sâu vào Windows (chia sẻ mạng, ổ đĩa, tài nguyên linh hoạt hơn máy ảo thông thường).



Em chọn WSL2 cho bài tập này vì: nhẹ hơn, khởi động nhanh hơn máy ảo đầy đủ, tích hợp trực tiếp với Docker Desktop, không cần cấp phát cứng RAM/CPU cố định như VirtualBox/VMware.



1.2. Docker và Docker Compose



\- Docker: nền tảng ảo hoá ở mức container (container hoá) - đóng gói ứng dụng cùng toàn bộ môi trường chạy (thư viện, cấu hình) vào một "container", chạy độc lập, nhẹ hơn máy ảo vì các container dùng chung nhân hệ điều hành host thay vì mô phỏng phần cứng riêng.

\- Docker Image: bản mẫu (template) chỉ đọc, dùng để tạo container.

\- Docker Compose: công cụ định nghĩa và chạy đồng thời nhiều container liên quan tới nhau (multi-container application) bằng một file cấu hình duy nhất viết theo cú pháp YAML (`docker-compose.yml`), thay vì phải chạy từng lệnh `docker run` riêng lẻ cho mỗi dịch vụ.



1.3. Các dịch vụ triển khai trên Docker Compose

Dịch vụ và vai trò

- Nginx: Web server / reverse proxy hiệu năng cao, dùng để phục vụ nội dung tĩnh và định tuyến request tới đúng dịch vụ backend dựa theo domain (virtual hosting) 

- Node-RED :Công cụ lập trình trực quan dạng kéo-thả (flow-based programming), thường dùng cho IoT và tự động hoá; có thể tạo API HTTP đơn giản bằng cặp node `http in` (nhận request) và `http response` (trả kết quả) 

- MariaDB : Hệ quản trị cơ sở dữ liệu quan hệ mã nguồn mở, là một nhánh phát triển tương thích của MySQL 

- phpMyAdmin: Công cụ quản trị MySQL/MariaDB qua giao diện web, cho phép xem/sửa dữ liệu, chạy truy vấn SQL trực quan mà không cần dùng dòng lệnh 

- Cloudflared: Client của Cloudflare Tunnel, tạo một đường hầm (tunnel) mã hoá từ máy cục bộ ra internet thông qua hạ tầng Cloudflare, cho phép truy cập dịch vụ chạy trong mạng nội bộ (localhost) từ domain thật công khai mà không cần mở port trên router/firewall


1.4. Cấu hình Nginx phục vụ nhiều domain (Virtual Hosting)



Nginx cho phép một server vật lý/container duy nhất phục vụ nhiều website khác nhau bằng cơ chế server block (tương đương "virtual host" ở Apache). Mỗi server { ... } trong file cấu hình định nghĩa:

\- listen: cổng lắng nghe (thường là 80 cho HTTP, 443 cho HTTPS)

\- server\_name: tên miền mà block này sẽ xử lý

\- root/index: thư mục và file mặc định phục vụ cho domain đó



Khi có request tới, Nginx đọc header Host trong HTTP request để xác định request đó thuộc domain nào, từ đó chọn đúng server block tương ứng để xử lý - đây là cách 1 con Nginx duy nhất chạy được nhiều website với domain khác nhau.



2\. Hướng dẫn thực hiện



2.1. Cài đặt môi trường Linux (WSL2)



```powershell

wsl --install

```

Khởi động lại máy, tạo username/password cho Ubuntu khi được yêu cầu. Kiểm tra phiên bản WSL:

```powershell

wsl -l -v

```



2.2. Cài Docker Desktop và tích hợp WSL2



\- Tải và cài Docker Desktop for Windows (chọn đúng bản theo máy)

\- Vào Settings → Resources → WSL Integration, bật tích hợp cho Ubuntu

\- Kiểm tra trong Ubuntu:

```bash

docker --version

docker compose version

```



2.3. Viết file docker-compose.yml



Khai báo 5 dịch vụ (nginx, nodered, mariadb, phpmyadmin, cloudflared), mỗi dịch vụ gồm: image (phiên bản dùng), ports (ánh xạ cổng), volumes (lưu trữ dữ liệu/cấu hình), networks (mạng nội bộ dùng chung giữa các container để chúng gọi được lẫn nhau qua tên service).



2.4. Cấu hình Nginx cho 2 website/domain khác nhau



Tạo 2 file cấu hình riêng trong nginx/conf.d/ (site1.conf, site2.conf), mỗi file 1 server block với server\_name là domain riêng , trỏ tới 2 thư mục nội dung HTML khác nhau.



2.5. Thiết lập Cloudflare Tunnel với domain thật



1\. Đăng nhập cloudflared, xác thực domain qua trình duyệt (cloudflared tunnel login)

2\. Tạo tunnel (cloudflared tunnel create), lấy Tunnel ID

3\. Viết file config.yml khai báo ánh xạ domain → dịch vụ nội bộ (ingress)

4\. Trỏ DNS 2 subdomain về tunnel (cloudflared tunnel route dns)

5\. Khai báo container cloudflared trong docker-compose.yml, chạy bằng chính file config.yml đó

 .6. Khởi động và kiểm tra

```bash
docker compose up -d
docker compose ps
```

<img width="945" height="591" alt="image" src="https://github.com/user-attachments/assets/d5574889-3b4b-4652-96eb-87a0bbb014fc" />
*Ảnh hiển thị kết quả các dịch vụ đã hoạt động đúng
Sau đó truy cập thử vào các trang web theo tên miền đã cài đặt
<img width="945" height="591" alt="image" src="https://github.com/user-attachments/assets/b1b08250-f0c3-45fd-a7cd-94eee8ff0e3b" />
<img width="945" height="591" alt="image" src="https://github.com/user-attachments/assets/8b2f95eb-bf82-4657-bec4-9a476e64f4a2" />
*Kết quả hai trang web với 2 domain khác nhau đã chạy đúng cấu hình nginx


---

- Bài tập 2

1. Lý thuyết

1.1. Node-RED 

Node-RED là công cụ lập trình trực quan, xây dựng ứng dụng bằng cách kéo-thả và nối các "node" (khối chức năng) lại thành một "flow" (luồng xử lý), thay vì viết code tuần tự truyền thống. Mỗi node đảm nhiệm một nhiệm vụ nhỏ (nhận request, xử lý dữ liệu, gọi API khác, trả kết quả...), dữ liệu (gọi là `msg`) được truyền từ node này sang node kế tiếp qua các dây nối (wires).

1.2. Tạo API bằng cặp node `http in` + `http response`

- `http in`: node lắng nghe một HTTP endpoint cụ thể (khai báo `method` - GET/POST/... và `url` - đường dẫn), đóng vai trò tương đương route/endpoint trong các framework backend truyền thống (Express, Flask...). Khi có request khớp, node này nhận request và chuyển tiếp `msg` sang node kế tiếp trong flow.
- `function` (node trung gian, tuỳ chọn): cho phép viết đoạn code JavaScript ngắn để xử lý logic, xây dựng dữ liệu trả về, gán vào `msg.payload`.
- `http response`: node cuối flow, lấy `msg.payload` và trả về cho client dưới dạng HTTP response. Nếu `msg.payload` là object JavaScript, Node-RED tự động chuyển thành JSON khi trả về (kèm header `Content-Type: application/json` nếu được khai báo trong `msg.headers`).

	Quy trình xử lý 1 request: Client gửi HTTP request → node `http in` bắt được request theo đúng `method` + `url` khai báo → dữ liệu chuyển qua node `function` để xử lý/tạo nội dung trả về → node `http response` gửi kết quả JSON về lại client.

1.3. Nginx đóng vai trò Reverse Proxy cho API

	Reverse Proxy là mô hình trong đó server trung gian (ở đây là Nginx) nhận request từ client, rồi chuyển tiếp (forward) request đó tới một server backend khác (ở đây là Node-RED), sau đó trả kết quả ngược lại cho client — toàn bộ quá trình này client không biết (và không cần biết) backend thật sự nằm ở đâu.

Trong bài tập, cấu hình `location /api/ { proxy_pass http://nodered:1880/api/; ... }` giúp:
- Client chỉ cần gọi tới domain chính (`web1.anxper.id.vn/api/...`), không cần biết cổng `1880` hay tên container `nodered`
- Ẩn cấu trúc hạ tầng bên trong (chỉ Nginx là điểm truy cập công khai duy nhất)
- Cho phép mở rộng sau này (thêm cache, giới hạn tốc độ request - rate limiting, SSL...) mà không cần sửa code backend

`proxy_set_header Host $host;` và `proxy_set_header X-Real-IP $remote_addr;` giúp giữ lại thông tin gốc của request (domain, địa chỉ IP client thật) khi chuyển tiếp qua Node-RED, tránh backend nhận nhầm là request đến từ chính Nginx.

1.4. Gọi API từ JavaScript bằng Fetch API

`fetch()` là hàm có sẵn trong JavaScript (chạy trên trình duyệt), dùng để gửi HTTP request bất đồng bộ (asynchronous) tới một địa chỉ (URL) mà không cần tải lại trang (AJAX). Quy trình xử lý:

1. `fetch('/api/sach')` gửi HTTP GET request tới endpoint đó
2. `.then(response => response.json())` nhận response, chuyển phần thân (body) từ dạng text sang object JavaScript (parse JSON)
3. `.then(data => { ... })` nhận được object dữ liệu, từ đó xử lý và cập nhật giao diện (ở đây là build bảng HTML từ mảng `data.danh_sach_sach`)
4. `.catch(err => { ... })` bắt lỗi nếu quá trình gọi API thất bại (mất mạng, server lỗi...)

2. Hướng dẫn thực hiện

2.1. Tạo API bằng Node-RED

1. Vào giao diện Node-RED (`http://localhost:1880`)
2. Kéo node `http in` vào canvas, cấu hình: method `GET`, url `/api/sach`
3. Kéo node `function` vào, nối tiếp sau `http in`, viết code JavaScript gán `msg.payload` là object chứa danh sách sách (tên, giá, tồn kho)
4. Kéo node `http response` vào, nối tiếp sau `function`
5. Bấm Deploy để kích hoạt flow

2.2. Cấu hình Nginx proxy API

Thêm block `location /api/` vào file cấu hình site, trỏ `proxy_pass` về địa chỉ nội bộ của Node-RED trong cùng Docker network (`http://nodered:1880/`), sử dụng đúng tên service khai báo trong `docker-compose.yml` (Docker DNS tự phân giải tên service thành địa chỉ IP container tương ứng).

2.3. Viết trang HTML dùng JavaScript gọi API

Tạo file HTML tĩnh, dùng `fetch()` gọi tới endpoint `/api/sach` (đường dẫn tương đối, tự động gọi đúng domain hiện tại của trang), nhận dữ liệu JSON, dựng thành bảng HTML hiển thị cho người dùng.

2.4. Kiểm tra kết quả

- Gọi trực tiếp API qua domain thật: `https://web1.anxper.id.vn/api/sach` → xác nhận trả về đúng JSON
- Mở trang demo: `https://web1.anxper.id.vn/api-demo.html` → xác nhận bảng dữ liệu hiển thị đúng, khớp với dữ liệu API trả về




