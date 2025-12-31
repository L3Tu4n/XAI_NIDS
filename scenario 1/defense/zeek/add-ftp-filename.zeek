@load base/protocols/ftp
@load base/frameworks/files

# Mở rộng bản ghi fa_file để lưu filename tạm thời
redef record fa_file += {
    filename: string &optional;
};

# Chỉ mở rộng Files::Info nếu filename chưa tồn tại
@if ( ! ("filename" in record_fields(Files::Info)) )
redef record Files::Info += {
    filename: string &log &optional;
};
@endif

# Chỉ mở rộng FTP::Info nếu filename chưa tồn tại
@if ( ! ("filename" in record_fields(FTP::Info)) )
redef record FTP::Info += {
    filename: string &log &optional;
};
@endif

# Bảng lưu trữ filename theo fuid
global ftp_filenames: table[string] of string &default="";

# Bảng lưu thông tin tạm thời theo uid của kết nối điều khiển
global ftp_pending: table[string] of record {
    filename: string;
    fuid: string &optional;
};

# Hàm trích xuất tên tệp từ arg
function extract_filename(arg: string): string {
    if ( /.*\// in arg ) {
        local parts = split_string(arg, /\//);
        return parts[|parts|-1];
    }
    return arg;
}

# Xử lý sự kiện ftp_request để lưu filename
event ftp_request(c: connection, command: string, arg: string) {
    if (command == "RETR" || command == "STOR") {
        local filename = extract_filename(arg);
        ftp_pending[c$uid] = [$filename=filename];
        if (c?$ftp) {
            c$ftp$filename = filename;
            print fmt("ts=%s, ftp_request: Lưu filename '%s' cho kết nối điều khiển %s", network_time(), filename, c$uid);
        }
    }
}

# Xử lý sự kiện file_new để liên kết fuid với filename
event file_new(f: fa_file) {
    print fmt("ts=%s, file_new: Xử lý tệp %s, source=%s", network_time(), f$id, f?$source ? f$source : "");
    if (f?$source && f$source == "FTP_DATA" && f?$conns) {
        for (cid in f$conns) {
            local c = lookup_connection(cid);
            print fmt("file_new: Kiểm tra kết nối %s, cổng đích=%s, uid=%s", cid, c$id$resp_p, c$uid);
            # Kiểm tra kết nối dữ liệu trong phạm vi cổng passive
            if (c$id$resp_p >= 40000/tcp && c$id$resp_p <= 40010/tcp) {
                # Tìm kết nối điều khiển liên quan
                for (uid in ftp_pending) {
                    ftp_pending[uid]$fuid = f$id;
                    f$filename = ftp_pending[uid]$filename;
                    ftp_filenames[f$id] = f$filename;
                    print fmt("file_new: Gán filename '%s' cho fuid %s từ kết nối điều khiển %s", f$filename, f$id, uid);
                    break;
                }
            }
        }
    }
}

# Xử lý sự kiện file_state_remove để gán filename vào Files::Info
event file_state_remove(f: fa_file) {
    print fmt("ts=%s, file_state_remove: Xử lý tệp %s", network_time(), f$id);
    if (f?$filename && f?$info) {
        f$info$filename = f$filename;
        print fmt("file_state_remove: Tệp %s, filename=%s (đã gán vào Files::Info)", f$id, f$filename);
        # Xóa filename khỏi ftp_filenames
        if (f$id in ftp_filenames) {
            delete ftp_filenames[f$id];
            print fmt("file_state_remove: Xóa filename '%s' khỏi ftp_filenames cho fuid %s", f$filename, f$id);
        }
        # Tìm uid cần xóa từ ftp_pending
        local uid_to_delete: string = "";
        for (uid in ftp_pending) {
            if (ftp_pending[uid]?$fuid && ftp_pending[uid]$fuid == f$id) {
                uid_to_delete = uid;
                break;
            }
        }
        # Xóa uid sau khi thoát vòng lặp
        if (uid_to_delete != "") {
            delete ftp_pending[uid_to_delete];
            print fmt("file_state_remove: Xóa ftp_pending cho uid %s", uid_to_delete);
        }
    } else {
        print fmt("file_state_remove: Tệp %s, filename=%s (không gán được)", f$id, f?$filename ? f$filename : "");
    }
}