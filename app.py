import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime, date
import os
import plotly.express as px
import hashlib
import time  
import io
import re
import base64

# ==============================================================================
# 1. HÀM HỆ THỐNG 
# ==============================================================================

@st.cache_resource
def get_conn():
    """Tạo kết nối DB cache để tránh mở quá nhiều connection"""
    return sqlite3.connect("data.db", check_same_thread=False)

def create_indexes():
    """Tạo chỉ mục (Index) để tăng tốc độ truy vấn"""
    with sqlite3.connect("data.db") as conn:
        c = conn.cursor()
        c.execute("CREATE INDEX IF NOT EXISTS idx_ccdl_user ON cham_cong_di_lam(username)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ccdl_time ON cham_cong_di_lam(thoi_gian)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cc_status ON cham_cong(trang_thai)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cc_user ON cham_cong(ten)")
        conn.commit()

@st.cache_resource
def init_db():
    """Khởi tạo cấu trúc Database (Chạy 1 lần)"""
    with sqlite3.connect("data.db", timeout=10, check_same_thread=False) as conn:
        c = conn.cursor()   
        # 1. Bảng chấm công lắp đặt
        c.execute('''CREATE TABLE IF NOT EXISTS cham_cong (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ten TEXT, 
            thoi_gian TEXT, 
            so_hoa_don TEXT UNIQUE,
            noi_dung TEXT, 
            quang_duong REAL, 
            combo INTEGER,
            thanh_tien REAL, 
            hinh_anh TEXT, 
            trang_thai TEXT DEFAULT 'Chờ duyệt',
            ghi_chu_duyet TEXT DEFAULT ''
        )''')

        # 2. Bảng chấm công đi làm
        c.execute('''CREATE TABLE IF NOT EXISTS cham_cong_di_lam (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, 
            thoi_gian TEXT, 
            trang_thai_lam TEXT,
            ghi_chu TEXT,         
            nguoi_thao_tac TEXT
        )''')
        
        # Bổ sung cột nếu thiếu (Migration)
        try:
            c.execute("ALTER TABLE cham_cong_di_lam ADD COLUMN nguoi_thao_tac TEXT")
        except sqlite3.OperationalError: pass
        try:
            c.execute("ALTER TABLE cham_cong_di_lam ADD COLUMN ghi_chu TEXT")
        except sqlite3.OperationalError: pass
        try:
            c.execute("ALTER TABLE cham_cong ADD COLUMN ghi_chu_duyet TEXT DEFAULT ''")
        except sqlite3.OperationalError: pass

        # 3. Bảng quản trị viên
        c.execute('''CREATE TABLE IF NOT EXISTS quan_tri_vien (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE, 
            password TEXT, 
            role TEXT, 
            nhan_vien_id INTEGER DEFAULT NULL,
            ho_ten TEXT,
            chuc_danh TEXT,
            ngay_sinh TEXT,
            so_dien_thoai TEXT,
            dia_chi TEXT
        )''')

        # Tạo tài khoản Admin mặc định
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM quan_tri_vien WHERE username IN ('sysadmin', 'admin')")
        if cursor.fetchone()[0] == 0:
            try:
                # Pass mặc định: admin123
                h_pass = hashlib.sha256("admin123".encode()).hexdigest()
                c.execute("""INSERT INTO quan_tri_vien 
                             (username, password, role, ho_ten, chuc_danh, ngay_sinh, so_dien_thoai, dia_chi) 
                             VALUES ('admin', ?, 'System Admin', 'Quản Trị Viên', 'Hệ Thống', '1993-12-26', '0931334450', 'Hệ thống')""", 
                          (h_pass,))
            except sqlite3.IntegrityError: pass
            
        conn.commit()
    
    if not os.path.exists("saved_images"): 
        os.makedirs("saved_images")
    
    # Gọi hàm tạo index ngay sau khi init DB
    create_indexes()

# Gọi hàm khởi tạo
init_db()

@st.cache_data
def load_logo_base64():
    """Cache ảnh logo để không phải đọc file mỗi lần rerun"""
    if os.path.exists("LOGO.png"):
        with open("LOGO.png", "rb") as f:
            return base64.b64encode(f.read()).decode()
    return None

def hash_password(pw: str):
    return hashlib.sha256(pw.encode()).hexdigest()

def check_login(u, p):
    h = hash_password(p)
    with sqlite3.connect("data.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT role, username, chuc_danh, ho_ten FROM quan_tri_vien WHERE username = ? AND password = ?", (u, h))
        return cur.fetchone()

def get_attendance_report(target_username, filter_month=None):
    """Hàm tính toán công - Đã tối ưu logic"""
    query = "SELECT thoi_gian, trang_thai_lam, ghi_chu FROM cham_cong_di_lam WHERE username=?"
    params = [target_username]
    if filter_month:
        query += " AND thoi_gian LIKE ?"
        params.append(f"{filter_month}%")
    query += " ORDER BY thoi_gian DESC"
    
    with sqlite3.connect("data.db") as conn:
        df = pd.read_sql(query, conn, params=params)
        
    if df.empty: return pd.DataFrame()
    
    df['thoi_gian'] = pd.to_datetime(df['thoi_gian'])
    df['ngay'] = df['thoi_gian'].dt.date
    summary = []
    
    for date_val, group in df.groupby('ngay', sort=False):
        # 1. Xử lý nghỉ
        if any(group['trang_thai_lam'].str.contains("Nghỉ")):
            status_row = group[group['trang_thai_lam'].str.contains("Nghỉ")].iloc[0]
            loai_cong = status_row['trang_thai_lam']
            summary.append({
                "Ngày": date_val.strftime("%d/%m/%Y"),
                "Giờ vào làm": "--:--", "Kết thúc làm": "--:--", "Tổng giờ": "0h",
                "Loại công": loai_cong, 
                "Ghi chú": status_row['ghi_chu'] if status_row['ghi_chu'] else loai_cong
            })
            continue

        # 2. Xử lý đi làm
        v_time = group[group['trang_thai_lam'] == "Vào làm"]['thoi_gian'].min()
        r_time = group[group['trang_thai_lam'] == "Ra về"]['thoi_gian'].max()
        
        tong_gio = 0
        loai_cong = "Chưa hoàn thành"
        ghi_chu_hien_thi = ""
        
        if pd.notnull(v_time) and pd.notnull(r_time):
            import datetime as dt_lib 
            lunch_start = dt_lib.datetime.combine(date_val, dt_lib.time(12, 0))
            lunch_end = dt_lib.datetime.combine(date_val, dt_lib.time(13, 30))      
            
            total_seconds = (r_time - v_time).total_seconds()
            overlap_start = max(v_time, lunch_start)
            overlap_end = min(r_time, lunch_end)
            
            lunch_break_seconds = 0
            if overlap_start < overlap_end:
                lunch_break_seconds = (overlap_end - overlap_start).total_seconds()
            
            actual_seconds = total_seconds - lunch_break_seconds
            tong_gio = round(actual_seconds / 3600, 2)
            
            if tong_gio < 3.5: 
                loai_cong = "Không tính công"
                ghi_chu_hien_thi = "Chấm công sai"
            elif 3.5 <= tong_gio < 7: 
                loai_cong = "1/2 ngày"
                ghi_chu_hien_thi = "Nửa ngày"
            elif tong_gio >= 7: 
                loai_cong = "Ngày"
                ghi_chu_hien_thi = "Một ngày"
                
        elif pd.notnull(v_time) and pd.isnull(r_time):
            loai_cong = "Đang làm"
            ghi_chu_hien_thi = "Chưa kết thúc chấm công"

        db_note = group['ghi_chu'].dropna().unique()
        final_note = db_note[0] if len(db_note) > 0 and db_note[0] != "" else ghi_chu_hien_thi       
        
        summary.append({
            "Ngày": date_val.strftime("%d/%m/%Y"),
            "Giờ vào làm": v_time.strftime("%H:%M:%S") if pd.notnull(v_time) else "--:--",
            "Kết thúc làm": r_time.strftime("%H:%M:%S") if pd.notnull(r_time) else "--:--",
            "Tổng giờ": f"{tong_gio}h",
            "Loại công": loai_cong,
            "Ghi chú": final_note
        })
        
    res = pd.DataFrame(summary)
    if not res.empty: res.insert(0, 'STT', range(1, len(res) + 1))
    return res

@st.cache_data(ttl=300)
def get_attendance_report_cached(user, month=None):
    return get_attendance_report(user, month)

# ==============================================================================
# 2. CẤU HÌNH GIAO DIỆN & AUTH
# ==============================================================================
st.set_page_config(page_title="Đại Thành - Ứng Dụng Nội Bộ", layout="wide")

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""
if "role" not in st.session_state:
    st.session_state["role"] = ""
if "ho_ten" not in st.session_state:
    st.session_state["ho_ten"] = ""

st.markdown("""
    <style>
        .stTabs [data-baseweb="tab-list"] { gap: 8px; background-color: transparent; }
        .stTabs [data-baseweb="tab"] {
            height: 40px; white-space: pre; background-color: #f8f9fa; 
            border-radius: 8px 8px 0px 0px; border: 1px solid #e0e0e0;
            padding: 8px 16px; color: #495057; font-weight: 500;
        }
        .stTabs [aria-selected="true"] {
            background-color: #ff4b4b !important; color: white !important;
            border-color: #ff4b4b !important; font-weight: 700 !important;
        }
        div.stButton > button[kind="primary"] {
            background-color: #28a745 !important; color: white !important;
            border-radius: 8px !important; font-weight: bold !important;
        }
    </style>
""", unsafe_allow_html=True)

# === MÀN HÌNH ĐĂNG NHẬP ===
if not st.session_state["authenticated"]:
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        logo_b64 = load_logo_base64()
        if logo_b64:
            st.markdown(f"""
                <div style="display: flex; justify-content: center;">
                    <img src="data:image/png;base64,{logo_b64}" width="200">
                </div>""", unsafe_allow_html=True)
        
        st.markdown("<h3 style='text-align: center; margin-top: 10px;'>🔐 Đăng nhập hệ thống</h3>", unsafe_allow_html=True)
        
        with st.form("login_form"):
            u_in = st.text_input("Tên tài khoản").lower().strip()
            p_in = st.text_input("Mật khẩu", type="password")
            
            if st.form_submit_button("ĐĂNG NHẬP", use_container_width=True):
                res = check_login(u_in, p_in)
                if res:
                    st.session_state["authenticated"] = True
                    st.session_state["role"], st.session_state["username"] = res[0], res[1]
                    st.session_state["chuc_danh"], st.session_state["ho_ten"] = res[2], res[3]
                    st.rerun()
                else: 
                    st.error("❌ Sai tài khoản hoặc mật khẩu")
    st.stop()

# ==============================================================================
# 3. GIAO DIỆN CHÍNH (SIDEBAR & MENU)
# ==============================================================================

role = st.session_state.get("role", "N/A")
user = st.session_state.get("username", "N/A")
ho_ten = st.session_state.get("ho_ten", "Nhân viên")
chuc_danh = st.session_state.get("chuc_danh", "N/A")

with st.sidebar:    
    st.markdown(f"👤 Nhân viên: **{ho_ten}**")
    st.caption(f"🎭 Quyền: {role}")
    if st.button("🚪 Đăng xuất", use_container_width=True):
        st.session_state["authenticated"] = False
        st.rerun()
    st.divider()
    st.markdown("### 🛠️ MENU CHỨC NĂNG")
    menu = st.radio("Chọn mục làm việc:", 
                    ["📦 Giao hàng - Lắp đặt", "🕒 Chấm công đi làm", "⚙️ Quản trị hệ thống"],
                    label_visibility="collapsed")
if "list_chuc_danh" not in st.session_state:
    st.session_state["list_chuc_danh"] = [
        "Hệ thống", "Kế toán", "KTV Lắp đặt", 
        "Quản lý", "Giao nhận", "Kinh doanh", "Nhân viên"
    ]
# ==============================================================================
# PHÂN HỆ 1: CHẤM CÔNG ĐI LÀM
# ==============================================================================
if menu == "🕒 Chấm công đi làm":
    if role in ["Admin", "System Admin"]:
        tabs = st.tabs(["📍 Chấm công", "🛠️ Quản lý & Sửa công", "📊 Báo cáo chấm công"])
    else:
        tabs = st.tabs(["📍 Chấm công"])

    # --- TAB 1: DÀNH CHO NHÂN VIÊN ---
    with tabs[0]:
        with sqlite3.connect("data.db") as conn:
            user_data = pd.read_sql("SELECT ho_ten, role FROM quan_tri_vien WHERE username = ?", conn, params=(user,))
        
        if not user_data.empty:
            info_nv = user_data.iloc[0]
            if info_nv['role'] == "System Admin":
                st.info("💡 Sếp trả lương cho nhân viên là công đức vô lượng rồi không cần chấm công")
            else:
                st.markdown(f"##### ⏰ Chấm công: {info_nv['ho_ten']}")
                today_str = datetime.now().strftime("%Y-%m-%d")
                current_month = datetime.now().strftime("%Y-%m")
                display_month = datetime.now().strftime("%m/%Y")

                with sqlite3.connect("data.db") as conn:
                    df_today = pd.read_sql("SELECT trang_thai_lam FROM cham_cong_di_lam WHERE username = ? AND thoi_gian LIKE ?", conn, params=(user, f"{today_str}%"))
                
                has_in = any(df_today['trang_thai_lam'] == "Vào làm")
                has_out = any(df_today['trang_thai_lam'] == "Ra về")
                has_off = any(df_today['trang_thai_lam'].str.contains("Nghỉ"))

                c_left, c_right = st.columns([1, 2.2])
                with c_left:
                    col_in, col_out = st.columns(2)
                    if col_in.button("📍 VÀO LÀM", use_container_width=True, type="primary", disabled=(has_in or has_off)):
                        with sqlite3.connect("data.db") as conn:
                            conn.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", (user, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Vào làm", user))
                        st.toast("✅ Đã ghi nhận giờ vào")
                        time.sleep(1)
                        st.rerun()
                        
                    if col_out.button("🏁 RA VỀ", use_container_width=True, disabled=(not has_in or has_out or has_off)):
                        with sqlite3.connect("data.db") as conn:
                            conn.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", (user, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Ra về", user))
                        st.toast("🏁 Đã ghi nhận giờ ra")
                        time.sleep(1)
                        st.rerun()

                    with st.expander("🛌 Đăng ký nghỉ hôm nay", expanded=False):
                        if has_off: st.warning("Bạn đã đăng ký nghỉ hôm nay")
                        elif has_in: st.error("Đã chấm công vào làm, không thể đăng ký nghỉ")
                        else:
                            type_off = st.selectbox("Loại nghỉ", ["Có phép", "Không phép"], key="type_off")
                            reason_off = st.text_input("Lý do nghỉ", placeholder="Nhập lý do cụ thể...")
                            if st.button("Xác nhận nghỉ", use_container_width=True, type="secondary"):
                                if not reason_off: st.error("Vui lòng nhập lý do")
                                else:
                                    with sqlite3.connect("data.db") as conn:
                                        conn.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, ghi_chu, nguoi_thao_tac) VALUES (?,?,?,?,?)", (user, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f"Nghỉ {type_off}", reason_off, user))
                                    st.success("Đã gửi đăng ký nghỉ")
                                    time.sleep(1)
                                    st.rerun()
                    
                    show_detail = st.button("📊 Chi tiết chấm công cá nhân", use_container_width=True)

                with c_right:
                    df_quick = get_attendance_report_cached(user)
                    if not df_quick.empty:
                        st.caption("Ngày làm việc gần nhất")
                        st.dataframe(df_quick.head(3), use_container_width=True, hide_index=True)

                if show_detail:
                    @st.dialog("Bảng chi tiết chấm công cá nhân", width="large")
                    def show_month_detail_dialog():
                        st.subheader(f"📅 Tháng {display_month}")
                        df_detail = get_attendance_report(user, current_month)
                        import calendar
                        now = datetime.now()
                        num_days = calendar.monthrange(now.year, now.month)[1]
                        
                        if not df_detail.empty:
                            di_lam = len(df_detail[~df_detail['Loại công'].str.contains("Nghỉ")])
                            dang_lam = len(df_detail[df_detail['Loại công'] == "Đang làm"])
                            half_day = len(df_detail[df_detail['Loại công'].str.contains("1/2", na=False)])
                            nghi_cp = len(df_detail[df_detail['Loại công'] == "Nghỉ Có phép"])
                            nghi_kp = len(df_detail[df_detail['Loại công'] == "Nghỉ Không phép"])
                            day_now = now.day 
                            chua_cham = max(0, day_now - len(df_detail))
                            total_full = len(df_detail[df_detail['Loại công'].str.contains("Ngày", na=False)])

                            st.metric("Tổng công tích lũy", f"{total_full + (half_day * 0.5)} công")
                            st.dataframe(df_detail, use_container_width=True, hide_index=True)
                            st.divider()
                            m1, m2, m3, m4 = st.columns(4)
                            m1.info(f"**Đi làm**\n\n {di_lam} ngày")
                            m2.warning(f"**Đang làm**\n\n {dang_lam} ngày")
                            m3.success(f"**1/2 ngày**\n\n {half_day} ngày")
                            m4.error(f"**Chưa chấm**\n\n {chua_cham} ngày")
                        else: 
                            st.write("Chưa có dữ liệu trong tháng này.")
                    show_month_detail_dialog()
        else:
            st.warning("⚠️ Tài khoản chưa được liên kết thông tin nhân sự.")

    # --- TAB 2: QUẢN LÝ & SỬA CÔNG (ADMIN) ---
    if role in ["Admin", "System Admin"]:
        with tabs[1]:
            st.markdown("#### 🛠️ Điều chỉnh công nhân viên")
            with sqlite3.connect("data.db") as conn:
                query_nv = "SELECT username, ho_ten FROM quan_tri_vien WHERE role != 'System Admin'"
                if role == "Admin": query_nv += f" AND username != '{user}'"
                list_nv = pd.read_sql(query_nv, conn)

            if not list_nv.empty:
                list_nv['label'] = list_nv['ho_ten'] + " (" + list_nv['username'] + ")"
                label_to_user = dict(zip(list_nv['label'], list_nv['username']))
                
                cl1, cl2 = st.columns(2)
                sel_label = cl1.selectbox("👤 Chọn nhân viên", options=list_nv['label'].tolist(), key="mgr_sel_user")
                sel_u = label_to_user.get(sel_label)
                sel_d = cl2.date_input("📅 Ngày điều chỉnh", datetime.now(), key="mgr_sel_date")
                d_str = sel_d.strftime("%Y-%m-%d")

                with sqlite3.connect("data.db") as conn:
                    df_check = pd.read_sql("SELECT thoi_gian, trang_thai_lam, nguoi_thao_tac FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", conn, params=(sel_u, f"{d_str}%"))

                c_info, c_action = st.columns([2, 1])
                if not df_check.empty:
                    c_info.dataframe(df_check, use_container_width=True, hide_index=True)
                    if c_action.button("🔥 Reset ngày này", use_container_width=True):
                        with sqlite3.connect("data.db") as conn: 
                            conn.execute("DELETE FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", (sel_u, f"{d_str}%"))
                        st.success(f"✅ Đã xóa dữ liệu ngày {d_str}")
                        time.sleep(1)
                        st.rerun()
                else: 
                    c_info.info(f"ℹ️ Ngày {d_str} không có dữ liệu.")

                st.divider()
                st.markdown("##### 📝 Gán công nhanh")
                b1, b2, b3 = st.columns([1, 1, 1])
                
                if b1.button("✅ Gán 1 Ngày công", use_container_width=True):
                    with sqlite3.connect("data.db") as conn:
                        conn.execute("DELETE FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", (sel_u, f"{d_str}%"))
                        conn.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", (sel_u, f"{d_str} 08:00:00", "Vào làm", user))
                        conn.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", (sel_u, f"{d_str} 17:30:00", "Ra về", user))
                    st.success("🎯 Đã gán 1 ngày công thành công")
                    time.sleep(1)
                    st.rerun()
                
                if b2.button("🌗 Gán 1/2 Ngày công", use_container_width=True):
                    with sqlite3.connect("data.db") as conn:
                        conn.execute("DELETE FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", (sel_u, f"{d_str}%"))
                        conn.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", (sel_u, f"{d_str} 08:00:00", "Vào làm", user))
                        conn.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", (sel_u, f"{d_str} 12:00:00", "Ra về", user))
                    st.success("🎯 Đã gán 1/2 ngày công thành công")
                    time.sleep(1)
                    st.rerun()

    # --- TAB 3: BÁO CÁO TỔNG HỢP (ADMIN) ---
    if role in ["Admin", "System Admin"]:
        with tabs[2]:
            st.markdown("#### 📊 Báo cáo chấm công nhân viên")
            col_f1, col_f2 = st.columns(2)
            with sqlite3.connect("data.db") as conn:
                df_users = pd.read_sql("SELECT username, ho_ten FROM quan_tri_vien WHERE role != 'System Admin'", conn)
            
            if not df_users.empty:
                df_users['label'] = df_users['ho_ten'] + " (" + df_users['username'] + ")"
                user_dict = dict(zip(df_users['label'], df_users['username']))
                selected_label = col_f1.selectbox("👤 Chọn nhân viên báo cáo", options=df_users['label'].tolist())
                target_user_rpt = user_dict.get(selected_label)
                
                c_month, c_year = col_f2.columns(2)
                now_dt = datetime.now()
                sel_m = c_month.selectbox("📅 Tháng", range(1, 13), index=now_dt.month - 1)
                sel_y = c_year.selectbox("📅 Năm", range(now_dt.year - 1, now_dt.year + 2), index=1)
                
                month_str = f"{sel_y}-{sel_m:02d}"
                df_report = get_attendance_report(target_user_rpt, month_str)
                
                if not df_report.empty:
                    total_full = len(df_report[df_report['Loại công'].str.contains("Ngày", na=False)])
                    total_half = len(df_report[df_report['Loại công'].str.contains("1/2", na=False)])
                    st.metric(f"Tổng công tháng {sel_m}/{sel_y}", f"{total_full + (total_half * 0.5)} công")
                    st.dataframe(df_report, use_container_width=True, hide_index=True)
                    
                    output = io.BytesIO()
                    with pd.ExcelWriter(output, engine='xlsxwriter') as writer: 
                        df_report.to_excel(writer, index=False, sheet_name='BaoCaoChamCong')
                    
                    st.download_button("📥 Tải báo cáo Excel", data=output.getvalue(), file_name=f"ChamCong_{target_user_rpt}_{month_str}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                else: 
                    st.info(f"ℹ️ Không có dữ liệu tháng {sel_m}/{sel_y}")

# ==============================================================================
# PHÂN HỆ 2: GIAO HÀNG - LẮP ĐẶT
# ==============================================================================
elif menu == "📦 Giao hàng - Lắp đặt":
    # 1. PHÂN QUYỀN TABS (Rõ ràng hơn)
    if role in ["Admin", "System Admin", "Manager"]:
        tabs = st.tabs(["📸 Chấm công lắp đặt", "📋 Duyệt đơn", "📈 Báo cáo lắp đặt"])
    elif chuc_danh in ["KTV Lắp đặt", "Lắp đặt", "Giao nhận"]:
        tabs = st.tabs(["📸 Chấm công lắp đặt", "📈 Báo cáo lắp đặt"]) 
    else:
        st.warning("⚠️ Bạn không có quyền truy cập chức năng này.")
        st.stop()

    def quick_update_status(record_id, new_status, reason=""):
        with sqlite3.connect("data.db") as conn:
            conn.execute("UPDATE cham_cong SET trang_thai = ?, ghi_chu_duyet = ? WHERE id = ?", (new_status, reason, record_id))

    # --- TAB 1: GỬI ĐƠN LẮP ĐẶT ---
    with tabs[0]:
        with sqlite3.connect("data.db") as conn:
            res_me = pd.read_sql("SELECT ho_ten FROM quan_tri_vien WHERE username = ?", conn, params=(user,))
            ten_nguoi_thao_tac = res_me.iloc[0]['ho_ten'] if not res_me.empty else user

        target_user = user
        is_management = role in ["Manager", "Admin", "System Admin"]
        
        if is_management:
            with sqlite3.connect("data.db") as conn:
                df_nv_list = pd.read_sql("SELECT username, ho_ten FROM quan_tri_vien WHERE role IN ('User', 'Manager') AND username IS NOT NULL", conn)
            
            if not df_nv_list.empty:
                df_nv_list['display'] = df_nv_list['ho_ten'] + " (" + df_nv_list['username'] + ")"
                options = df_nv_list['display'].tolist() if role in ["System Admin", "Admin"] else ["Tự chấm công"] + df_nv_list['display'].tolist()
                sel_nv_display = st.selectbox("🎯 Chấm công lắp đặt thay cho:", options)
                
                if sel_nv_display != "Tự chấm công":
                    target_user = df_nv_list[df_nv_list['display'] == sel_nv_display]['username'].values[0]

        if "f_up_key" not in st.session_state: st.session_state["f_up_key"] = 0
        uploaded_file = st.file_uploader("🖼️ Ảnh hóa đơn", type=["jpg", "png", "jpeg"], key=f"up_{st.session_state['f_up_key']}")
        
        with st.form("form_lap_dat", clear_on_submit=True):
            c1, c2 = st.columns(2)
            so_hd_in = c1.text_input("📝 Số hóa đơn (VD: HD12345)")
            quang_duong = c1.number_input("🛣️ Quãng đường (km)", min_value=1, step=1)
            combo = c2.selectbox("📦 Số lượng máy (Combo)", [1, 2, 3, 4, 5, 6])
            noi_dung = c2.text_area("📍 Địa chỉ / Ghi chú")     
            
            if st.form_submit_button("🚀 GỬI YÊU CẦU", use_container_width=True):
                if not uploaded_file or not so_hd_in:
                    st.error("❌ Thiếu Ảnh hoặc Số hóa đơn!")
                else:
                    so_hd = so_hd_in.upper().strip()
                    don_gia = 30000 if quang_duong < 20 else 50000 if quang_duong <= 30 else 70000
                    tong_tien = combo * don_gia
                    
                    if not os.path.exists("saved_images"): os.makedirs("saved_images")
                    img_path = f"saved_images/{so_hd}_{datetime.now().strftime('%H%M%S')}.jpg"
                    
                    try:
                        with sqlite3.connect("data.db") as conn:
                            conn.execute("""INSERT INTO cham_cong (ten, thoi_gian, so_hoa_don, noi_dung, quang_duong, combo, thanh_tien, hinh_anh, trang_thai) 
                                VALUES (?,?,?,?,?,?,?,?,?)""", (target_user, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), so_hd, noi_dung, quang_duong, combo, tong_tien, img_path, 'Chờ duyệt'))
                            with open(img_path, "wb") as f: f.write(uploaded_file.getbuffer())
                            
                        st.success(f"✅ Đã gửi đơn! (Tiền công: {tong_tien:,.0f} VNĐ)")
                        st.session_state["f_up_key"] += 1
                        time.sleep(1.5)
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error(f"❌ Số hóa đơn **{so_hd}** đã tồn tại!")

    # --- TAB 2: DUYỆT ĐƠN (CHỈ ADMIN/MANAGER) ---
    if role in ["Admin", "System Admin", "Manager"]:
        with tabs[1]:
            st.markdown("### 📋 Danh sách đơn chờ duyệt")
            with sqlite3.connect("data.db") as conn:
                df_p = pd.read_sql("SELECT c.*, q.ho_ten FROM cham_cong c LEFT JOIN quan_tri_vien q ON c.ten = q.username WHERE c.trang_thai='Chờ duyệt' ORDER BY c.thoi_gian DESC", conn)

            if df_p.empty:
                st.info("📭 Không có đơn nào chờ duyệt.")
            else:
                for _, r in df_p.iterrows():
                    with st.expander(f"📦 HĐ: {r['so_hoa_don']} — 👤 {r['ho_ten']}"):
                        cl, cr = st.columns([1.5, 1])
                        with cl:
                            st.write(f"**📍 Đ/C:** {r['noi_dung']}")
                            st.write(f"🛣️ {r['quang_duong']} km | 📦 {r['combo']} máy")
                            st.markdown(f"#### 💰: `{r['thanh_tien']:,.0f}` VNĐ")
                            b1, b2 = st.columns(2)
                            if b1.button("✅ DUYỆT", key=f"ap_{r['id']}", use_container_width=True, type="primary"):
                                quick_update_status(r["id"], "Đã duyệt", "Thông tin chính xác")
                                st.rerun()
                            with b2:
                                with st.popover("❌ TỪ CHỐI", use_container_width=True):
                                    reason = st.text_area("Lý do:", key=f"txt_{r['id']}")
                                    if st.button("Xác nhận", key=f"conf_{r['id']}", use_container_width=True):
                                        quick_update_status(r["id"], "Từ chối", reason)
                                        st.rerun()
                        with cr:
                            if r["hinh_anh"] and os.path.exists(r["hinh_anh"]):
                                st.image(r["hinh_anh"], use_container_width=True)

    # --- TAB 3 (HOẶC TAB CUỐI): BÁO CÁO LẮP ĐẶT ---
    # QUAN TRỌNG: Đặt logic này RA NGOÀI khối if admin để User cũng thấy (thông qua tabs[-1])
    with tabs[-1]:
        with sqlite3.connect("data.db") as conn:
            query = """
                SELECT c.id, q.ho_ten AS 'Tên', c.ten AS 'username', c.thoi_gian AS 'Thời Gian',
                    c.so_hoa_don AS 'Số HĐ', c.noi_dung AS 'Địa chỉ', c.quang_duong AS 'Km', c.combo,
                    c.thanh_tien AS 'Thành tiền', c.trang_thai AS 'Trạng thái', c.ghi_chu_duyet AS 'Lý do'
                FROM cham_cong AS c LEFT JOIN quan_tri_vien AS q ON c.ten = q.username
            """
            df_raw = pd.read_sql(query, conn)

        if df_raw.empty:
            st.info("📭 Chưa có dữ liệu đơn hàng.")
        else:
            df_raw["Thời Gian"] = pd.to_datetime(df_raw["Thời Gian"])
            # Phân quyền xem dữ liệu
            if role in ["Admin", "System Admin", "Manager"]:
                df_all = df_raw.copy()
            else:
                df_all = df_raw[df_raw["username"] == user].copy()

            if df_all.empty:
                st.info("ℹ️ Bạn chưa có đơn hàng nào.")
            else:
                # 1. BIỂU ĐỒ (ADMIN)
                if role in ["Admin", "System Admin", "Manager"]:
                    st.markdown("### 📈 Tổng quan")
                    df_ok = df_all[df_all["Trạng thái"] == "Đã duyệt"]
                    if not df_ok.empty:
                        stats = df_ok.groupby("Tên").agg(So_don=("Số HĐ", "count"), Doanh_thu=("Thành tiền", "sum")).reset_index()
                        c1, c2 = st.columns(2)
                        with c1: st.plotly_chart(px.bar(stats, x="Tên", y="So_don", title="Đơn thành công", text_auto=True), use_container_width=True)
                        with c2: st.plotly_chart(px.pie(stats, values="Doanh_thu", names="Tên", title="Doanh thu"), use_container_width=True)
                    st.divider()

                # 2. BỘ LỌC
                st.subheader("📄 Chi tiết đơn hàng")
                col_f1, col_f2, col_f3 = st.columns(3)
                d_range = col_f1.date_input("📅 Thời gian", value=[date.today().replace(day=1), date.today()])
                
                nv_opts = ["Tất cả"] + sorted(df_all["Tên"].astype(str).unique().tolist())
                is_disabled = role not in ["Admin", "System Admin", "Manager"]
                sel_nv = col_f2.selectbox("👤 Nhân viên", nv_opts, disabled=is_disabled)
                sel_tt = col_f3.selectbox("📌 Trạng thái", ["Tất cả", "Chờ duyệt", "Đã duyệt", "Từ chối"])

                if len(d_range) == 2:
                    mask = (df_all["Thời Gian"].dt.date >= d_range[0]) & (df_all["Thời Gian"].dt.date <= d_range[1])
                    if sel_nv != "Tất cả": mask &= df_all["Tên"] == sel_nv
                    if sel_tt != "Tất cả": mask &= df_all["Trạng thái"] == sel_tt
                    
                    df_display = df_all[mask].sort_values("Thời Gian", ascending=False)
                    
                    if df_display.empty:
                        st.info("🔍 Không có dữ liệu.")
                    else:
                        c_met, c_exp = st.columns([2, 1])
                        rev_sum = df_display[df_display["Trạng thái"] == "Đã duyệt"]["Thành tiền"].sum()
                        c_met.metric("💰 Doanh thu duyệt", f"{rev_sum:,.0f} VNĐ")
                        
                        out = io.BytesIO()
                        with pd.ExcelWriter(out, engine="xlsxwriter") as writer:
                            df_display.drop(columns=["id", "username"]).to_excel(writer, index=False)
                        c_exp.download_button("📥 Tải Excel", out.getvalue(), "BaoCao.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

                        st.dataframe(
                            df_display.drop(columns=["username", "id"]),
                            use_container_width=True, hide_index=True,
                            column_config={
                                "Thời Gian": st.column_config.DatetimeColumn("Thời gian", format="DD/MM/YYYY HH:mm"),
                                "Thành tiền": st.column_config.NumberColumn("Thành tiền", format="%d VNĐ"),
                            }
                        )

                        # 3. SỬA ĐƠN (USER)
                        if role not in ["Admin", "System Admin", "Manager"]:
                            st.divider()
                            st.subheader("🛠 Sửa đơn (Đơn Chờ duyệt)")
                            df_edit = df_display[df_display["Trạng thái"] == "Chờ duyệt"]
                            if not df_edit.empty:
                                sel_hd = st.selectbox("Chọn Số HĐ sửa:", df_edit["Số HĐ"].tolist())
                                row = df_edit[df_edit["Số HĐ"] == sel_hd].iloc[0]
                                
                                with st.form("edit_form"):
                                    c1, c2 = st.columns(2)
                                    n_hd = c1.text_input("Số HĐ", value=row["Số HĐ"])
                                    n_km = c1.number_input("Km", value=float(row["Km"]))
                                    n_dc = c2.text_input("Địa chỉ", value=row["Địa chỉ"])
                                    n_cb = c2.selectbox("Combo", [1,2,3,4,5,6], index=int(row["combo"])-1)
                                    
                                    if st.form_submit_button("💾 Cập nhật", use_container_width=True):
                                        n_tien = n_cb * (30000 if n_km < 20 else 50000 if n_km <= 30 else 70000)
                                        with sqlite3.connect("data.db") as conn:
                                            conn.execute("UPDATE cham_cong SET so_hoa_don=?, noi_dung=?, quang_duong=?, combo=?, thanh_tien=? WHERE id=? AND trang_thai='Chờ duyệt'", 
                                                         (n_hd, n_dc, n_km, n_cb, n_tien, int(row["id"])))
                                        st.success("Cập nhật thành công!")
                                        time.sleep(1)
                                        st.rerun()

# ==============================================================================
# ==============================================================================
# PHÂN HỆ 3: QUẢN TRỊ HỆ THỐNG
# ==============================================================================
elif menu == "⚙️ Quản trị hệ thống":
    # 1. LOGIC CHIA TAB THEO QUYỀN
    if role == "System Admin":
        list_tabs = ["👥 Nhân sự", "🛠️ Quản trị tài khoản", "🔐 Đổi mật khẩu"]
    elif role in ["Admin", "Manager"]:
        list_tabs = ["👥 Nhân sự", "🔐 Đổi mật khẩu"]
    else: # Role là User
        list_tabs = ["🔐 Đổi mật khẩu"]
    
    tabs = st.tabs(list_tabs)

    # 2. XỬ LÝ NỘI DUNG TỪNG TAB
    
   # ---------------------------------------------------------
    # TAB: QUẢN LÝ NHÂN SỰ (👥) - PATCH LOGIC CẬP NHẬT ĐA TẦNG
    # ---------------------------------------------------------
    if "👥 Nhân sự" in list_tabs:
        idx = list_tabs.index("👥 Nhân sự")
        with tabs[idx]:
            st.subheader("👥 Danh sách nhân sự")
            
            with sqlite3.connect("data.db") as conn:
                df_users = pd.read_sql("SELECT * FROM quan_tri_vien", conn)
            
            if df_users.empty:
                st.info("Chưa có dữ liệu nhân sự.")
            else:
                # 1. TẠO BẢNG HIỂN THỊ
                df_users_display = df_users.reset_index()
                df_users_display['index'] = df_users_display['index'] + 1
                
                st.dataframe(
                    df_users_display,
                    use_container_width=True,
                    hide_index=True,
                    column_order=("index", "ho_ten", "chuc_danh", "role", "so_dien_thoai", "dia_chi"),
                    column_config={
                        "index": "STT", "ho_ten": "Họ tên", "chuc_danh": "Chức danh",
                        "role": "Quyền", "so_dien_thoai": "SĐT", "dia_chi": "Địa chỉ"
                    }
                )

                st.divider()
                st.markdown("#### 🛠️ Cập nhật thông tin nhân sự")

                # 2. LOGIC LỌC LISTBOX & PHÂN QUYỀN
                if role == "Admin":
                    df_filter = df_users[df_users['role'] != 'System Admin'].copy()
                else:
                    df_filter = df_users.copy()

                df_filter['display_name'] = df_filter['ho_ten'] + " (" + df_filter['chuc_danh'] + ")"
                
                selected_display = st.selectbox(
                    "Chọn nhân viên cần cập nhật thông tin:", 
                    options=df_filter['display_name'].tolist(),
                    key="sel_edit_user_name"
                )
                
                target_u = df_filter[df_filter['display_name'] == selected_display]['username'].values[0]
                row = df_users[df_users['username'] == target_u].iloc[0]
                
                is_disabled_for_admin = (role != "System Admin")

                # 3. FORM CẬP NHẬT
                with st.form(f"form_edit_nv_{target_u}"):
                    st.caption(f"Đang chỉnh sửa tài khoản: {target_u}")
                    c1, c2 = st.columns(2)
                    with c1:
                        new_name = st.text_input("Họ và tên", value=str(row['ho_ten']))
                        new_phone = st.text_input("Số điện thoại", value=str(row['so_dien_thoai']))
                        new_addr = st.text_area("Địa chỉ", value=str(row['dia_chi']), height=100)
                    with c2:
                        # CHỨC DANH: Chuyển sang Selectbox lấy từ danh mục
                        current_cd = str(row['chuc_danh'])
                        if current_cd not in st.session_state["list_chuc_danh"]:
                            st.session_state["list_chuc_danh"].append(current_cd)
                        
                        new_cd = st.selectbox("Chức danh", st.session_state["list_chuc_danh"], 
                                            index=st.session_state["list_chuc_danh"].index(current_cd),
                                            disabled=is_disabled_for_admin)
                        
                        roles_list = ["User", "Manager", "Admin", "System Admin"]
                        curr_role_idx = roles_list.index(row['role']) if row['role'] in roles_list else 0
                        new_role = st.selectbox("Quyền hệ thống", roles_list, index=curr_role_idx, disabled=is_disabled_for_admin)
                        
                        new_pass = st.text_input("Mật khẩu mới (Để trống nếu giữ nguyên)", type="password")
                        
                        current_birth = date.today()
                        if row['ngay_sinh'] and str(row['ngay_sinh']) != 'None':
                            try: current_birth = pd.to_datetime(row['ngay_sinh']).date()
                            except: pass
                        new_birth = st.date_input("Ngày sinh", value=current_birth)

                    if st.form_submit_button("💾 XÁC NHẬN CẬP NHẬT", use_container_width=True):
                        try:
                            with sqlite3.connect("data.db") as conn:
                                if new_pass.strip():
                                    conn.execute("""UPDATE quan_tri_vien 
                                                 SET ho_ten=?, so_dien_thoai=?, dia_chi=?, ngay_sinh=?, password=?, chuc_danh=?, role=?
                                                 WHERE username=?""",
                                                (new_name, new_phone, new_addr, new_birth.strftime("%Y-%m-%d"), hash_password(new_pass), new_cd, new_role, target_u))
                                else:
                                    conn.execute("""UPDATE quan_tri_vien 
                                                 SET ho_ten=?, so_dien_thoai=?, dia_chi=?, ngay_sinh=?, chuc_danh=?, role=?
                                                 WHERE username=?""",
                                                (new_name, new_phone, new_addr, new_birth.strftime("%Y-%m-%d"), new_cd, new_role, target_u))
                            st.success(f"✅ Đã cập nhật thành công cho {new_name}!")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Lỗi: {e}")

    # --- TAB 2: QUẢN TRỊ TÀI KHOẢN (Chỉ dành cho System Admin) ---
    if "🛠️ Quản trị tài khoản" in list_tabs:
        idx = list_tabs.index("🛠️ Quản trị tài khoản")
        with tabs[idx]:
            

            # --- MỤC 3: QUẢN LÝ CHỨC DANH (Code cũ của bạn) ---
            with st.expander("📂 Quản lý danh mục Chức danh"):
                col_a, col_b = st.columns([3, 1])
                new_cd_input = col_a.text_input("Nhập chức danh mới:", key="new_cd_add")
                if col_b.button("➕ Thêm", use_container_width=True):
                    if new_cd_input and new_cd_input not in st.session_state["list_chuc_danh"]:
                        st.session_state["list_chuc_danh"].append(new_cd_input)
                        st.success(f"Đã thêm '{new_cd_input}'")
                        time.sleep(0.5)
                        st.rerun()
                st.write("Danh sách hiện tại:", ", ".join(st.session_state["list_chuc_danh"]))

            # --- MỤC 4: TẠO TÀI KHOẢN MỚI (Code cũ của bạn) ---
            with st.expander("➕ Tạo tài khoản nhân sự mới", expanded=False):
                with st.form("add_user_full", clear_on_submit=True): 
                    c1, c2, c3 = st.columns(3)
                    n_u = c1.text_input("Username*").lower().strip()
                    n_p = c2.text_input("Mật khẩu*", type="password")
                    n_r = c3.selectbox("Quyền", ["User", "Manager", "Admin", "System Admin"])
                    n_ten = st.text_input("Họ và tên*")
                    c4, c5 = st.columns(2)
                    n_cd = c4.selectbox("Chức danh", st.session_state["list_chuc_danh"])
                    n_phone = c5.text_input("Số điện thoại")
                    
                    if st.form_submit_button("🚀 TẠO TÀI KHOẢN", use_container_width=True):
                        if not n_u or not n_p or not n_ten:
                            st.error("❌ Thiếu thông tin!")
                        else:
                            try:
                                with sqlite3.connect("data.db") as conn:
                                    conn.execute("""
                                        INSERT INTO quan_tri_vien (username, password, role, ho_ten, chuc_danh, so_dien_thoai) 
                                        VALUES (?,?,?,?,?,?)
                                    """, (n_u, hash_password(n_p), n_r, n_ten, n_cd, n_phone))
                                st.success("✅ Thành công!")
                                time.sleep(1); st.rerun()
                            except: st.error("❌ Username tồn tại!")

            st.divider()

            # --- MỤC 5: XÓA TÀI KHOẢN (Code cũ của bạn) ---
            st.markdown("#### 🗑️ Xóa tài khoản nhân sự")
            with sqlite3.connect("data.db") as conn:
                df_to_del = pd.read_sql("SELECT username, ho_ten, role FROM quan_tri_vien WHERE username != ?", conn, params=(user,))
            
            if not df_to_del.empty:
                df_to_del['display'] = df_to_del['ho_ten'] + " (" + df_to_del['username'] + ")"
                u_del_display = st.selectbox("Chọn tài khoản xóa:", options=df_to_del['display'].tolist())
                u_selected = df_to_del[df_to_del['display'] == u_del_display]['username'].values[0]
                
                confirm_del = st.checkbox(f"Xác nhận xóa tài khoản {u_selected}")
                if st.button("❌ XÓA USER", type="primary", disabled=not confirm_del, use_container_width=True):
                    with sqlite3.connect("data.db") as conn:
                        conn.execute("DELETE FROM quan_tri_vien WHERE username=?", (u_selected,))
                    st.success("💥 Đã xóa!"); time.sleep(1); st.rerun()
            st.divider()
            st.subheader("🔑 Bảo trì hệ thống")
            
            # --- MỤC 1: BACKUP & PHỤC HỒI DỮ LIỆU ---
            with st.expander("💾 Sao lưu và Phục hồi "):
                c1, c2 = st.columns(2)
                
                with c1:
                    st.markdown("##### 📥 Xuất dữ liệu (Backup)")
                    if os.path.exists("data.db"):
                        with open("data.db", "rb") as f:
                            st.download_button(
                                label="📥 Tải tệp Backup (.db)",
                                data=f,
                                file_name=f"backup_data_{datetime.now().strftime('%d%m%Y_%H%M')}.db",
                                mime="application/octet-stream",
                                use_container_width=True
                            )
                        st.info("Nên backup dữ liệu định kỳ hoặc trước khi xóa database.")
                
                with c2:
                    st.markdown("##### 📤 Phục hồi dữ liệu (Recovery)")
                    uploaded_db = st.file_upload_label = st.file_uploader("Chọn tệp .db để phục hồi", type=["db"])
                    if uploaded_db is not None:
                        if st.button("🔄 Xác nhận Ghi đè & Phục hồi", type="secondary", use_container_width=True):
                            try:
                                with open("data.db", "wb") as f:
                                    f.write(uploaded_db.getbuffer())
                                st.success("✅ Phục hồi thành công! Hệ thống sẽ khởi động lại...")
                                time.sleep(2)
                                st.rerun()
                            except Exception as e:
                                st.error(f"Lỗi phục hồi: {e}")

            # --- MỤC 2: RESET DATABASE (DÀNH CHO TEST) ---
            with st.expander("🔥 Dọn dẹp & Xóa dữ liệu"):
                st.error("⚠️ CẢNH BÁO: Thao tác này sẽ xóa sạch các bảng Chấm công/Đơn hàng. Không thể hoàn tác!")
                confirm_reset = st.checkbox("Tôi hiểu và muốn xóa toàn bộ dữ liệu giao hàng/chấm công.")
                
                if st.button("🗑️ THỰC HIỆN RESET DATABASE", type="primary", disabled=not confirm_reset, use_container_width=True):
                    try:
                        with sqlite3.connect("data.db") as conn:
                            # Xóa dữ liệu các bảng nghiệp vụ (không xóa bảng nhân sự để tránh mất quyền đăng nhập)
                            # Bạn có thể thêm tên các bảng khác vào đây nếu có
                            conn.execute("DELETE FROM cham_cong") 
                            conn.execute("DELETE FROM cham_cong_di_lam")
                            conn.execute("DELETE FROM quan_tri_vien WHERE role NOT IN ('System Admin')")
                            # conn.execute("DELETE FROM bang_khac") # Ví dụ
                            conn.commit()
                        st.success("💥 Đã dọn dẹp sạch dữ liệu test!")
                        time.sleep(1)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Lỗi khi xóa: {e}")

                   

    # --- TAB: ĐỔI MẬT KHẨU (Tất cả mọi người) ---
    # Giữ nguyên logic cũ nhưng thay st.toast và tối ưu giao diện
    if "🔐 Đổi mật khẩu" in list_tabs:
        idx = list_tabs.index("🔐 Đổi mật khẩu")
        with tabs[idx]:
            with st.form("change_pass_form"):
                p_old = st.text_input("Mật khẩu hiện tại", type="password")
                p_new = st.text_input("Mật khẩu mới", type="password")
                p_conf = st.text_input("Xác nhận mật khẩu mới", type="password")
                
                if st.form_submit_button("💾 CẬP NHẬT MẬT KHẨU", use_container_width=True):
                    if not p_old or not p_new:
                        st.error("❌ Vui lòng nhập đầy đủ thông tin")
                    elif p_new != p_conf:
                        st.error("❌ Mật khẩu xác nhận không khớp")
                    elif len(p_new) < 4:
                        st.error("❌ Mật khẩu mới phải có ít nhất 4 ký tự")
                    else:
                        with sqlite3.connect("data.db") as conn:
                            res = conn.execute("SELECT password FROM quan_tri_vien WHERE username=?", (user,)).fetchone()
                            if res and res[0] == hash_password(p_old):
                                conn.execute("UPDATE quan_tri_vien SET password=? WHERE username=?", (hash_password(p_new), user))
                                st.success("✅ Đổi mật khẩu thành công!")
                                # Tự động đăng xuất để yêu cầu đăng nhập lại với mật khẩu mới
                                time.sleep(1.5)
                                st.session_state["authenticated"] = False
                                st.rerun()
                            else:
                                st.error("❌ Mật khẩu cũ không chính xác")
