# Chú thích từ khóa và cú pháp Splunk SPL

-   `index=main`: tìm trong index có tên `main`.
-   `sourcetype=...`: giới hạn theo loại dữ liệu Splunk đã gán cho sự
    kiện.
-   `EventCode=1`: lọc sự kiện có mã sự kiện bằng `1` (ý nghĩa cụ thể
    phụ thuộc nguồn log; trong Sysmon, Event ID 1 thường là Process
    Create).
-   `|`: chuyển kết quả của lệnh bên trái sang lệnh bên phải.
-   `table ...`: chỉ hiển thị các cột được chỉ định.
-   `sort - _time`: sắp xếp theo thời gian giảm dần, sự kiện mới hơn ở
    trên.

## Dấu pipe `|` và các lệnh SPL thường gặp

Pipe đưa tập kết quả hiện tại sang lệnh tiếp theo. Thứ tự các lệnh có
thể ảnh hưởng đến kết quả và hiệu năng.

  -----------------------------------------------------------------------------------------------------
  Lệnh / hàm              Ý nghĩa                 Ví dụ
  ----------------------- ----------------------- -----------------------------------------------------
  `search`                Lọc sự kiện theo điều   `... \| search user="alice"`
                          kiện tìm kiếm.          

  `where`                 Lọc kết quả bằng biểu   `... \| where count>10`
                          thức; hữu ích khi so    
                          sánh field với field    
                          hoặc dùng hàm.          

  `table`                 Hiển thị các field được `... \| table _time host user`
                          chọn thành cột.         

  `fields`                Giữ lại hoặc loại bỏ    `... \| fields _time host user`
                          field khỏi kết quả.     

  `stats`                 Tính toán thống kê và   `... \| stats count by user`
                          thường gom nhóm theo    
                          một hoặc nhiều field.   

  `eventstats`            Tính thống kê rồi bổ    `... \| eventstats count by user`
                          sung kết quả thống kê   
                          vào từng sự kiện mà     
                          không gom toàn bộ thành 
                          các hàng tổng hợp như   
                          `stats`.                

  `streamstats`           Tính toán thống kê theo `... \| streamstats count by user`
                          luồng kết quả, thường   
                          hữu ích cho cửa         
                          sổ/chuỗi sự kiện.       

  `timechart`             Tổng hợp số liệu theo   `... \| timechart count`
                          các khoảng thời gian để 
                          xem xu hướng.           

  `bin`                   Chia giá trị, thường là `... \| bin _time span=5m`
                          thời gian hoặc số,      
                          thành các nhóm/khoảng.  

  `sort`                  Sắp xếp kết quả. Dấu    `... \| sort - _time`
                          `-` trước field số/thời 
                          gian thường biểu thị    
                          giảm dần.               

  `head`                  Lấy một số hàng đầu của `... \| head 20`
                          kết quả.                

  `tail`                  Lấy một số hàng cuối    `... \| tail 20`
                          của kết quả.            

  `dedup`                 Loại các hàng trùng     `... \| dedup host user`
                          nhau theo field chỉ     
                          định.                   

  `rename`                Đổi tên field trong kết `... \| rename ComputerName AS host`
                          quả.                    

  `eval`                  Tạo hoặc tính toán      `... \| eval is_admin=if(user="Administrator",1,0)`
                          field bằng biểu thức.   

  `rex`                   Trích xuất hoặc thay    `... \| rex field=_raw "User=(?<user>\\S+)"`
                          thế dữ liệu bằng biểu   
                          thức chính quy.         

  `lookup`                Bổ sung dữ liệu từ bảng `... \| lookup asset_inventory host OUTPUT owner`
                          lookup.                 

  `inputlookup`           Đọc dữ liệu từ lookup   `| inputlookup asset_inventory.csv`
                          table.                  

  `outputlookup`          Ghi kết quả vào lookup  `... \| outputlookup results.csv`
                          table; cần cân nhắc     
                          quyền và tác động trước 
                          khi chạy.               

  `append`                Ghép kết quả từ một tìm `... \| append [ search ... ]`
                          kiếm khác vào kết quả   
                          hiện tại.               

  `join`                  Ghép dữ liệu từ hai tập `... \| join host [ search ... ]`
                          kết quả theo field      
                          chung; có giới hạn và   
                          có thể tốn tài nguyên.  

  `transaction`           Gom sự kiện thành giao  `... \| transaction user maxspan=10m`
                          dịch theo tiêu chí và   
                          thời gian; có thể nặng  
                          với dữ liệu lớn.        

  `return`                Trả về giá trị từ kết   `... \| return $field`
                          quả, thường dùng trong  
                          subsearch.              
  -----------------------------------------------------------------------------------------------------

## Hàm thường gặp trong `stats`, `eval` và `where`

  ----------------------------------------------------------------------------------------------------------------------------------
  Hàm                                Ý nghĩa                 Ví dụ
  ---------------------------------- ----------------------- -----------------------------------------------------------------------
  `count`                            Đếm số sự kiện hoặc số  `stats count by user`
                                     bản ghi trong nhóm.     

  `dc(field)`                        Đếm số giá trị khác     `stats dc(dest) by user`
                                     nhau của field.         

  `values(field)`                    Trả về tập các giá trị  `stats values(process) by host`
                                     khác nhau của field     
                                     trong nhóm.             

  `earliest(field)`                  Lấy giá trị tương ứng   `stats earliest(_time) by user`
                                     sớm nhất theo thứ tự    
                                     thời gian của kết quả.  

  `latest(field)`                    Lấy giá trị tương ứng   `stats latest(_time) by user`
                                     mới nhất theo thứ tự    
                                     thời gian của kết quả.  

  `min(field)` / `max(field)`        Giá trị nhỏ nhất / lớn  `stats max(bytes) by host`
                                     nhất.                   

  `sum(field)` / `avg(field)`        Tổng / trung bình.      `stats sum(bytes) by user`

  `if(condition,a,b)`                Trả về `a` nếu điều     `eval result=if(count>10,"high","low")`
                                     kiện đúng, ngược lại    
                                     trả về `b`.             

  `case(...)`                        Kiểm tra nhiều điều     `eval severity=case(count>100,"high",count>10,"medium",true(),"low")`
                                     kiện theo thứ tự và trả 
                                     về giá trị tương ứng.   

  `coalesce(a,b,...)`                Trả về giá trị đầu tiên `eval account=coalesce(user,Account_Name)`
                                     không rỗng/null trong   
                                     các đối số.             

  `isnull(field)`                    Kiểm tra field có null  `where isnull(user)`
                                     hay không.              

  `isnotnull(field)`                 Kiểm tra field không    `where isnotnull(user)`
                                     null.                   

  `match(field,"regex")`             Kiểm tra giá trị field  `where match(CommandLine,"(?i)powershell")`
                                     có khớp biểu thức chính 
                                     quy hay không.          

  `like(field,"pattern")`            So khớp chuỗi theo mẫu  `where like(user,"adm%")`
                                     với `%` và `_` trong    
                                     ngữ cảnh hỗ trợ.        

  `lower(field)` / `upper(field)`    Chuyển chuỗi thành chữ  `eval proc=lower(Image)`
                                     thường / chữ hoa.       

  `len(field)`                       Độ dài chuỗi.           `where len(CommandLine)>200`

  `substr(field,start,length)`       Lấy một phần chuỗi.     `eval short=substr(user,1,8)`

  `strftime(time,"%...")`            Định dạng thời gian     `eval readable=strftime(_time,"%F %T")`
                                     thành chuỗi.            

  `relative_time(time,"modifier")`   Tính thời điểm tương    `eval cutoff=relative_time(now(),"-24h")`
                                     đối từ một timestamp.   
  ----------------------------------------------------------------------------------------------------------------------------------
