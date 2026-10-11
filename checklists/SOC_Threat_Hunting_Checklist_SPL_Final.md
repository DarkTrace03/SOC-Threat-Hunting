# Checklist Threat Hunting trên Splunk

> Tổng hợp các query Windows và Linux dùng để hunting trên Splunk. 


### 1. Windows_reg

- Phát hiện việc sử dụng reg.exe để truy vấn hoặc thay đổi Registry; kẻ tấn công có thể thu thập cấu hình, kiểm tra cơ chế bảo mật, persistence hoặc sửa cấu hình hệ thống.
- MITRE ATT&CK T1012 – Query Registry (khớp trực tiếp khi truy vấn Registry); T1112 – Modify Registry (chỉ khi xác nhận có thao tác sửa)


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_path = *reg.exe*
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 2. Windows_service install

- Tìm sự kiện tạo service mới trên Windows. Service có thể được dùng để duy trì hiện diện hoặc thực thi payload với quyền cao.
- MITRE ATT&CK T1543.003 – Windows Service

**SPL**
```spl
index=oswin AND (EventCode=7045 OR EventCode=4697)
| table _time, host, EventCode, ip, service_path, service_name, ServiceFileName
```

### 3. Windows_sqlservr

- Phát hiện tiến trình con được khởi chạy bởi SQL Server. Đây có thể là dấu hiệu lạm dụng SQL Server để chạy lệnh hệ điều hành hoặc khai thác máy chủ cơ sở dữ liệu.
- MITRE ATT&CK T1059.003 – Windows Command Shell; T1059.001 – PowerShell (chỉ áp dụng khi tiến trình con phù hợp)


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process = "*sqlservr*"
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 4. Windows_ssh tunnel

- Tìm dấu hiệu đăng nhập liên quan SSH hoặc loopback có thể xuất hiện khi tạo tunnel/proxy. Event 4624 đơn lẻ không chứng minh có tunnel.
- MITRE ATT&CK T1572 – Protocol Tunneling; T1090.001 – Internal Proxy (nếu xác nhận proxy nội bộ)

**SPL**
```spl
index=oswin AND EventCode=4624 AND (src_ip="127.0.0.1" OR process_name=*ssh*) | table _time, host, user, src_ip, ip, Logon_Type, name, process_name
```

### 5. Windows_task create/ update

- Theo dõi tạo, xóa, bật/tắt hoặc cập nhật Scheduled Task; tác vụ có thể được dùng để persistence hoặc thực thi theo lịch.
- MITRE ATT&CK T1053.005 – Scheduled Task/Job: Scheduled Task

**SPL**
```spl
index=oswin AND EventCode IN (4699, 4698, 4700, 4701, 4702)
| table _time, host, EventCode, SubjectUserName, name, ProcessID, TaskName, Schedule_Command_Value, Schedule_Arg
```

### 6. Windows_user add

- Phát hiện thêm thành viên vào nhóm bảo mật, đặc biệt nhóm đặc quyền. Đây là thay đổi quyền truy cập có thể hỗ trợ privilege escalation.
- MITRE ATT&CK T1098.007 – Additional Local or Domain Groups; T1098 – Account Manipulation


**SPL**
```spl
index=oswin AND (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time, host, EventCode, src_user, name, user_group, user_name, member_user_name
```

### 7. Windows_w3wp

- Tìm tiến trình con do IIS worker process w3wp.exe khởi chạy. Shell, PowerShell hoặc công cụ hệ thống chạy từ worker process có thể cho thấy web compromise.
- MITRE ATT&CK T1505.003 – Server Software Component: Web Shell; T1059 – Command and Scripting Interpreter (phụ thuộc tiến trình con)


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process = "*w3wp.exe*"
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 8. Windows_wmi

- Theo dõi Sysmon WMI event filter/consumer/binding, có thể chỉ ra WMI Event Subscription được tạo để persistence hoặc thực thi lệnh.
- MITRE ATT&CK T1546.003 – Event Triggered Execution: Windows Management Instrumentation Event Subscription

**SPL**
```spl
index=oswin AND source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode IN (19, 20, 21)
```

### 9. Windows_discovery

- Tìm lệnh thu thập thông tin máy, mạng, domain và kết nối đang hoạt động trước khi di chuyển ngang hoặc lựa chọn mục tiêu.
- MITRE ATT&CK T1033 – System Owner/User Discovery; T1082 – System Information Discovery; T1016 – System Network Configuration Discovery; T1049 – System Network Connections Discovery; T1018 – Remote System Discovery

**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process IN (*whoami*, *ipconfig*, *systeminfo*, *hostname*, *arp.exe*, *nbtstat*, *netstat*)
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 10. Windows_dns query_1

- Tìm DNS query khớp chuỗi IOC cụ thể được đặt trong truy vấn. DNS bất thường có thể liên quan C2 hoặc kiểm tra kết nối, nhưng cần xác thực IOC.
- MITRE ATT&CK T1071.004 – Application Layer Protocol: DNS (chỉ khi query thuộc hoạt động C2); IOC match tự nó chưa đủ kết luận


**SPL**
```spl
index=oswin AND EventCode=22
QueryName=*UWhRCA*
| table _time, host, Computer, User, Image, QueryName, QueryResults, QueryStatus
```

### 11. Windows_echo

- Tìm việc dùng echo trong command line. Đây là tín hiệu rất rộng, có thể xuất hiện trong script hợp lệ; chỉ hữu ích khi kết hợp nội dung lệnh và ngữ cảnh.
- MITRE ATT&CK Chưa ánh xạ duy nhất; có thể T1059.003 – Windows Command Shell nếu xác nhận được thực thi qua cmd.exe


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process = "*echo*"
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 12. Windows_file create

- Tìm file mới có phần mở rộng thường gặp ở web application. File ASPX/PHP/JSP mới có thể là web shell hoặc mã độc được đặt vào web root.
- MITRE ATT&CK T1505.003 – Server Software Component: Web Shell (khi xác minh file/behavior là web shell)

**SPL**
```spl
index=oswin AND EventCode=11 AND (TargetFilename=*.aspx* OR *.ashx* OR *.php* OR *.jsp* OR *.asp* OR *.cs* OR *.asax*)
| table _time, CreationUtcTime, host, ProcessId, Image, TargetFilename, User
```

### 13. Windows_http

- Truy vấn hiện tại tìm process có chuỗi process bằng http; điều kiện này chưa đủ xác định một hành vi tấn công cụ thể và có thể không bắt được command line thực tế.
- MITRE ATT&CK 

**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process = "http"
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 14. Windows_java

- Tìm tiến trình con được khởi chạy bởi java.exe. Ứng dụng Java server bị khai thác có thể sinh shell, script hoặc công cụ tải/chạy payload.
- MITRE ATT&CK T1059.003 – Windows Command Shell; T1059.001 – PowerShell; T1190 – Exploit Public-Facing Application (chỉ khi có bằng chứng khai thác)


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_path = "*java.exe*"
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 15. Windows_net

- Theo dõi net.exe/net1.exe dùng để liệt kê hoặc thay đổi user, group, share và thông tin domain; có thể phục vụ discovery hoặc quản trị tài khoản.
- MITRE ATT&CK T1087.001 – Account Discovery: Local Account; T1069.001 – Permission Groups Discovery: Local Groups; T1018 – Remote System Discovery (tùy command line)


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process = "*net.exe*" OR Processes.process="*net1.exe*"
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 16. Windows_node, tomcat

- Tìm tiến trình con của node.exe hoặc Tomcat. Web/application runtime sinh shell hoặc công cụ hệ thống có thể cho thấy ứng dụng bị lạm dụng.
- MITRE ATT&CK T1059 – Command and Scripting Interpreter; T1505.003 – Web Shell (chỉ khi có bằng chứng web shell/compromise)



**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process IN (*node.exe*, *tomcat*)
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 17. Windows_pass the hash

- Tìm logon network-cleartext/provider seclogo với LogonType 9, thường liên quan NewCredentials; có thể hỗ trợ điều tra Pass-the-Hash nhưng không phải bằng chứng độc lập.
- MITRE ATT&CK T1550.002 – Use Alternate Authentication Material: Pass the Hash (cần correlation bổ sung)


**SPL**
```spl
index=oswin AND EventCode=4624 AND LogonProcessName=seclogo AND LogonType=9
```

### 18. Windows_psexec

- Tìm chuỗi process có psexec trong command line/name. PsExec có thể được dùng để thực thi lệnh từ xa và di chuyển ngang.
- MITRE ATT&CK T1021.002 – Remote Services: SMB/Windows Admin Shares; T1569.002 – System Services: Service Execution


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process = "*psexec*"
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 19. Windows_4672

- Theo dõi sự kiện gán đặc quyền nhạy cảm cho logon mới; hữu ích để tìm phiên đăng nhập có quyền cao bất thường.
- MITRE ATT&CK T1078 – Valid Accounts (ngữ cảnh sử dụng tài khoản hợp lệ); không phải ánh xạ trực tiếp cho mọi Event 4672


**SPL**
```spl
index=oswin AND EventCode=4672
| stats values(host) as hosts count by SubjectUserName
```

### 20. Windows_ad object modify

- Theo dõi thay đổi đối tượng AD liên quan Group Policy hoặc các quyền replication nhạy cảm; có thể chỉ ra sửa GPO hoặc chuẩn bị DCSync.
- MITRE ATT&CK T1484.001 – Domain Policy Modification: Group Policy Modification; T1003.006 – OS Credential Dumping: DCSync (khi thuộc quyền replication)


**SPL**
```spl
index=oswin AND EventCode=5136 AND (
(AttributeLDAPDisplayName=*groupPolicyContaine* OR *31B2F340-016D-11D2-945F-00C04FB984F9* OR *6AC1786C-016F-11D2-945F-00C04fB984F9*)
OR (ObjectDN=*UWhRCA*)
OR (AttributeValue IN (*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*, *1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*, *9923a32a-3607-11d2-b9be-0000f87a36b2*, *89e95b76-444d-4c62-991a-0facbeda640c*))
)
| table _time, host, SubjectUserSid, SubjectLogonId, ObjectDN, ObjectClass, OperationType, AttributeLDAPDisplayName, AttributeValue
```

### 21. Windows_appcmd

- Theo dõi appcmd.exe, công cụ quản trị IIS có thể dùng để thay đổi cấu hình site/app pool hoặc thu thập cấu hình máy chủ web.
- MITRE ATT&CK T1505.004 – Server Software Component: IIS Components (chỉ khi hành vi liên quan thành phần IIS độc hại); chưa đủ để gán kỹ thuật chỉ từ tên appcmd.exe


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process = "*appcmd.exe*"
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 22. Windows_bat/vbs file

- Tìm command line hoặc process path liên quan .bat/.vbs. Script có thể được dùng để chạy lệnh, tải payload hoặc duy trì persistence.
- MITRE ATT&CK T1059.003 – Windows Command Shell (batch); T1059.005 – Visual Basic (VBScript)


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process IN ("*.bat*", "*.vbs*") OR Processes.process_path IN ("*.bat*", "*.vbs*")
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, dest, user, process_path, process, parent_process, parent_process_path, process_id, parent_process_id, process_hash
```

### 23. Windows_built-in process 1

- Theo dõi nhóm công cụ quản trị có sẵn của Windows (LOLBins). Các công cụ này hợp pháp nhưng có thể bị lạm dụng để discovery, tải/chạy payload, sửa cấu hình hoặc xóa bản sao lưu.
- MITRE ATT&CK T1218 – System Binary Proxy Execution; T1105 – Ingress Tool Transfer; T1059 – Command and Scripting Interpreter; T1490 – Inhibit System Recovery (chỉ với lệnh phù hợp)


**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("at.exe", *Bitsadmin.exe*, *Certutil.exe*, *Cmdkey.exe*, *Cmstp.exe*, *Control.exe*, *Dnscmd.exe*, *Esentutl.exe*, *Eventvwr.exe*, *Expand.exe*, *Findstr.exe*, *fltMC.exe*, *Forfiles.exe*, *Fsutil.exe*, *Ftp.exe*, *hh.exe*, *Makecab.exe*, *Mmc.exe*, *Mofcomp.exe*, *Mshta.exe*, *Msiexec.exe*, *Netsh.exe*, *Query.exe*, *Schtasks.exe*, "sc.exe", *scp.exe*, *Sftp.exe*, *Vssadmin.exe*, *Verclsid.exe*, *Wab.exe*, *wbadmin.exe*, *Wlrmdr.exe*, *wmic.exe*, *wuauclt.exe*, *Wsl.exe*)
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats values(parent_process) as parent_cmdline count by user, process_path, process, parent_process_path
| sort by count
```

### 24. Windows_built-in process 2

- Theo dõi nhóm binary ít phổ biến hoặc có khả năng bị lạm dụng để proxy execution, nạp assembly, thao tác AD/NTDS hoặc chạy công cụ hệ thống.
- MITRE ATT&CK T1218 – System Binary Proxy Execution; T1003.003 – OS Credential Dumping: NTDS; T1059 – Command and Scripting Interpreter (tùy binary/lệnh)



**SPL**
```spl
| tstats fillnull_value=null count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN (*AddinUtil.exe*, *AppInstaller.exe*, *Applaunch.exe*, *CertOC.exe*, *CertReq.exe*, *Change.exe*, *Cipher.exe*, *cmdl32.exe*, *ComputerDefaults.exe*, *CustomShellHost.exe*, *Desktopimgdownldr.exe*, *Dfsvc.exe*, *Diantz.exe*, *Diskshadow.exe*, *Eudcedit.exe*, *Extexport.exe*, *Extrac32.exe*, *Finger.exe*, *IMEWDBLD.exe*, *Ie4uinit.exe*, *iediagcmd.exe*, *Ieexec.exe*, *Ilasm.exe*, *Installutil.exe*, *iscsicpl.exe*, *Ldifde.exe*, *Mavinject.exe*, *Msdt.exe*, *msoxmled.exe*, *Odbcconf.exe*, *Pcalua.exe*, *Pcwrun.exe*, *Pktmon.exe*, *Pnputil.exe*, *Print.exe*, *PrintBrm.exe*, *Provlaunch.exe*, *Psr.exe*, *Rasautou.exe*, *Regasm.exe*, *Regini.exe*, *Replace.exe*, *Rpcping.exe*, *Runexehelper.exe*, *Runonce.exe*, *Scriptrunner.exe*, *Ttdinject.exe*, *Tttracer.exe*, *Unregmp2.exe*, *wbemtest.exe*, *winget.exe*, *wt.exe*, *odbcad32.exe*, *Cdb.exe*, *Bcp.exe*, *ntdsutil.exe*, *Vshadow.exe*, )
by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process Processes.parent_process_path Processes.process_id Processes.parent_process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats values(parent_process) as parent_cmdline, count by user, process_path, process, parent_process_path
| sort by count
```

### 25. Windows_clear log

- Tìm dấu hiệu xóa Security log, xóa event log hoặc lỗi audit log; có thể là hành vi che giấu hoạt động.
- MITRE ATT&CK T1070.001 – Indicator Removal: Clear Windows Event Logs
**Log cần có:** Windows Security 1102; EventLog/System 104; 1101 là audit event loss
**Ưu tiên:** High
**Khi có kết quả, kiểm tra:** Xác định log/channel bị tác động, user, host, thời điểm; đối chiếu khoảng trống log, process creation và các sự kiện ngay trước/sau.

**SPL**
```spl
index=oswin AND (EventCode=1102 OR EventCode=1101 OR EventCode=104)
```

### 26. Windows_create remote thread

- Sysmon Event ID 8 ghi nhận CreateRemoteThread; đây có thể là dấu hiệu process injection, nhưng cần đánh giá source/target và module/function.
- MITRE ATT&CK T1055.002 – Process Injection: Portable Executable Injection (mapping gần; xác minh phương thức thực tế)


**SPL**
```spl
index=oswin AND (EventCode = 8)
| table host, EventCode, SourceImage, TargetImage, EventDescription, host, parent_process_path
```

### 27. Windows_create user

- Phát hiện tạo tài khoản Windows mới; tài khoản lạ hoặc tạo ngoài quy trình có thể được dùng để duy trì truy cập.
- MITRE ATT&CK T1136.001 – Create Account: Local Account (nếu tạo local); T1136.002 – Domain Account (nếu tạo domain)


**SPL**
```spl
index=oswin AND EventCode=4720
```

### 28. Windows_dcsync

- Tìm quyền/hoạt động replication AD nhạy cảm trong Event 4662. Kẻ tấn công có thể lạm dụng quyền này để lấy hash thông tin xác thực qua DCSync.
- MITRE ATT&CK T1003.006 – OS Credential Dumping: DCSync


**SPL**
```spl
index=oswin AND EventCode=4662 AND (
(Properties IN ("*Replicating Directory Changes All*","*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*","*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*","*9923a32a-3607-11d2-b9be-0000f87a36b2*","*89e95b76-444d-4c62-991a-0facbeda640c*"))
OR (ObjectName=*UWhRCA*)
)
| table _time, host, ip, SubjectUserSid, Caller_User_Name, Logon_ID, AccessMask, ObjectName, ObjectType, OperationType, Properties, action
```

### 29. Linux_File create

- Tìm sự kiện audit tạo file có phần mở rộng web/script. File mới trong web root có thể là web shell hoặc mã được triển khai trái phép.
- MITRE ATT&CK T1505.003 – Server Software Component: Web Shell (nếu xác minh); T1105 – Ingress Tool Transfer (nếu file được tải từ ngoài)


**SPL**
```spl
index=osnix AND type=PATH AND nametype="CREATE" AND name IN (*.php*, *.jsp*, *.asp*, *.ash*, *.pl*, *.cgi*, *.cfm*)
```

### 30. Linux_bashrc

- Tìm thao tác hoặc lệnh tham chiếu .bashrc/.bash_profile/.profile; chỉnh sửa shell startup file có thể tạo persistence khi người dùng đăng nhập.
- MITRE ATT&CK T1546.004 – Event Triggered Execution: Unix Shell Configuration Modification


**SPL**
```spl
index=osnix AND sourcetype=linux_audit AND type=EXECVE AND (Command_Arg=*.bashrc* OR Command_Arg=*.bash_profile* OR Command_Arg=*.profile*)
```

### 31. Linux_curl, wget

- Theo dõi curl/wget trong audit EXECVE vì chúng thường được dùng để tải payload, gọi URL hoặc chuyển dữ liệu ra ngoài.
- MITRE ATT&CK T1105 – Ingress Tool Transfer; T1071.001 – Web Protocols (nếu dùng HTTP/S cho C2)


**SPL**
```spl
index=osnix AND type=EXECVE AND Command_Arg IN (*curl*, *wget*)
| stats values(host) as host count by Command_Arg
| table host, count, Command_Arg
```

### 32. Linux_passwd

- Tìm lệnh có tham chiếu /etc/passwd, /etc/shadow hoặc /proc; có thể là thu thập tài khoản, truy cập dữ liệu xác thực hoặc kiểm tra tiến trình.
- MITRE ATT&CK T1003.008 – OS Credential Dumping: /etc/passwd and /etc/shadow; T1003.007 – OS Credential Dumping: Proc Filesystem (nếu hành vi đúng mục tiêu)


**SPL**
```spl
index=osnix AND sourcetype=linux_audit AND type=EXECVE AND Command_Arg IN (*/etc/passwd*, */etc/shadow*, */proc/*)
| stats values(host) as host count by Command_Arg
```

### 33. Linux_passwd 2

- Tìm mọi lệnh có chuỗi passwd. Phạm vi rất rộng, có thể bắt đổi mật khẩu hợp lệ lẫn thao tác đáng ngờ.
- MITRE ATT&CK T1098 – Account Manipulation hoặc T1003.008 – OS Credential Dumping (chỉ khi command line xác nhận hành vi tương ứng)


**SPL**
```spl
index=osnix AND sourcetype=linux_audit AND type=EXECVE AND Command_Arg=*passwd* | stats count by Command_Arg
```

### 34. Linux_scp

- Theo dõi scp/sftp/ftp để phát hiện truyền file qua giao thức quản trị hoặc FTP; có thể liên quan exfiltration hoặc chuyển payload.
- MITRE ATT&CK T1021.004 – Remote Services: SSH; T1048 – Exfiltration Over Alternative Protocol (chỉ khi có bằng chứng exfiltration); T1105 – Ingress Tool Transfer


**SPL**
```spl
index=osnix AND sourcetype=linux_audit AND type=EXECVE AND (Command_Arg=*scp* OR *Command_Arg=sftp* OR *Command_Arg=ftp*)
```

### 35. Linux_systemctl

- Theo dõi systemctl vì thao tác tạo/sửa/khởi động service có thể tạo persistence hoặc chạy payload dưới quyền service.
- MITRE ATT&CK T1543.002 – Create or Modify System Process: Systemd Service


**SPL**
```spl
index=osnix AND sourcetype=linux_audit AND type=EXECVE AND Command_Arg=*systemctl*
| stats count by Command_Arg
```

### 36. Linux_tcpdump

- Phát hiện sử dụng tcpdump để bắt gói tin; có thể là troubleshooting hợp lệ hoặc thu thập thông tin mạng/credential.
- MITRE ATT&CK T1040 – Network Sniffing


**SPL**
```spl
index=osnix AND sourcetype=linux_audit AND type=EXECVE AND Command_Arg=*tcpdump*
```

### 37. Linux_useradd

- Theo dõi useradd/usermod/userdel để phát hiện tạo, sửa hoặc xóa tài khoản; thay đổi trái phép có thể hỗ trợ persistence/privilege escalation.
- MITRE ATT&CK T1136.001 – Create Account: Local Account; T1098 – Account Manipulation


**SPL**
```spl
index=osnix AND sourcetype=linux_audit AND type=EXECVE AND Command_Arg IN (*usermod*, *useradd*, *userdel*)
```

### 38. Linux_web user

- Theo dõi syscall do tài khoản dịch vụ web (www/apache/nginx) thực hiện. Hoạt động shell, truy cập nhạy cảm hoặc tạo file từ tài khoản web có thể chỉ ra web server compromise.
- MITRE ATT&CK T1505.003 – Server Software Component: Web Shell; T1059.004 – Unix Shell (chỉ khi có bằng chứng thực thi shell)


**SPL**
```spl
index=osnix AND sourcetype=linux_audit AND type=SYSCALL AND UID IN (*www*, *apache*, *nginx*)
```

## Những điểm cần rà soát trước khi dùng thường xuyên

- `Windows_dns query_1`: `QueryName=*UWhRCA*` là IOC/chuỗi cụ thể; thay bằng IOC đã xác minh hoặc lookup/KV Store phù hợp với quy trình CTI.
- `Windows_http`: điều kiện `Processes.process = "http"` có thể không biểu diễn đúng hành vi dự định. Xác minh dữ liệu mẫu và viết lại hunt theo mục tiêu cụ thể trước khi triển khai.
- `Windows_echo`, `Linux_passwd 2` và các hunt LOLBins có độ rộng cao; không nên tự động tạo incident chỉ từ tên binary/chuỗi lệnh.
- `Windows_pass the hash`: Event 4624 với `LogonProcessName=seclogo` và `LogonType=9` không đủ để kết luận Pass-the-Hash; cần correlation với nguồn xác thực, remote access và process telemetry.
- `Windows_create remote thread`: Sysmon Event ID 8 là tín hiệu process injection tiềm năng, nhưng cần phân tích SourceImage/TargetImage và các trường StartModule/StartFunction nếu được ghi nhận.
- `Windows_dcsync` và `Windows_ad object modify`: xác minh audit policy, GUID/Properties được parse đúng, domain controller coverage và tài khoản replication hợp lệ.
- Linux hunts: xác minh `index=osnix`, `sourcetype=linux_audit`, tên field `Command_Arg`, `UID`, `a0/a1` và việc auditd ghi đủ EXECVE/PATH/SYSCALL.
- Những SPL dùng `tstats` cần Data Model Acceleration/field mapping tương thích; kiểm tra macro `drop_dm_object_name` và `security_content_ctime` có tồn tại trong Splunk.
- Vì yêu cầu đã bỏ ngoại lệ NOT, kết quả sẽ rộng hơn và có thể tăng false positive. Không khôi phục ngoại lệ hàng loạt; ghi nhận baseline và chỉ tuning dựa trên evidence/owner xác nhận.
