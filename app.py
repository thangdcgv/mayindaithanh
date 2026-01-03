import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime, date
import os
import plotly.express as px
import hashlib
import time  # Quan trọng: Dùng để delay thông báo trước khi rerun
import io
import re
import base64


# ==============================================================================
# 1. HÀM HỆ THỐNG & TỐI ƯU DATABASE (PERFORMANCE PATCH)
# ==============================================================================

@st.cache_resource
def get_conn():
    """Tạo kết nối DB cache để tránh mở quá nhiều connection"""
    return sqlite3.connect("data.db", check_same_thread=False)
def read_sql(query, params=()):
    conn = get_conn()
    return pd.read_sql(query, conn, params=params)

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
    st.markdown(f"👤 Chào: **{ho_ten}**")
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

                    # --- NÚT VÀO LÀM ---
                    if col_in.button("📍 VÀO LÀM", use_container_width=True, type="primary", disabled=(has_in or has_off)):                       
                        try:
                            cur = conn.cursor()
                            cur.execute("""
                                INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) 
                                VALUES (?,?,?,?)
                            """, (user, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Vào làm", user))
                            conn.commit() # Quan trọng nhất
                            
                            st.toast("✅ Đã ghi nhận giờ vào")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Lỗi: {e}")

                    # --- NÚT RA VỀ ---
                    if col_out.button("🏁 RA VỀ", use_container_width=True, disabled=(not has_in or has_out or has_off)):
                        try:
                            cur = conn.cursor()
                            cur.execute("""
                                INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) 
                                VALUES (?,?,?,?)
                            """, (user, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Ra về", user))
                            conn.commit()
                            
                            st.toast("🏁 Đã ghi nhận giờ ra")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Lỗi: {e}")

                    # --- ĐĂNG KÝ NGHỈ ---
                    with st.expander("🛌 Đăng ký nghỉ hôm nay", expanded=False):
                        if has_off: 
                            st.warning("Bạn đã đăng ký nghỉ hôm nay")
                        elif has_in: 
                            st.error("Đã chấm công vào làm, không thể đăng ký nghỉ")
                        else:
                            type_off = st.selectbox("Loại nghỉ", ["Có phép", "Không phép"], key="type_off")
                            reason_off = st.text_input("Lý do nghỉ", placeholder="Nhập lý do cụ thể...")
                            
                            if st.button("Xác nhận nghỉ", use_container_width=True, type="secondary"):
                                if not reason_off: 
                                    st.error("Vui lòng nhập lý do")
                                else:
                                    try:
                                        cur = conn.cursor()
                                        cur.execute("""
                                            INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, ghi_chu, nguoi_thao_tac) 
                                            VALUES (?,?,?,?,?)
                                        """, (user, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f"Nghỉ {type_off}", reason_off, user))
                                        conn.commit()
                                        
                                        st.success("Đã gửi đăng ký nghỉ")
                                        time.sleep(1)
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"Lỗi: {e}")

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
                
                # 1. Lấy danh sách nhân viên để chọn
                with sqlite3.connect("data.db") as conn:
                    query_nv = "SELECT username, ho_ten FROM quan_tri_vien WHERE role != 'System Admin'"
                    if role == "Admin": 
                        query_nv += f" AND username != '{user}'"
                    # Lưu ý: pd.read_sql dùng con=
                    list_nv = pd.read_sql(query_nv, con=conn)

                if not list_nv.empty:
                    list_nv['label'] = list_nv['ho_ten'] + " (" + list_nv['username'] + ")"
                    label_to_user = dict(zip(list_nv['label'], list_nv['username']))
                    
                    cl1, cl2 = st.columns(2)
                    sel_label = cl1.selectbox("👤 Chọn nhân viên", options=list_nv['label'].tolist(), key="mgr_sel_user")
                    sel_u = label_to_user.get(sel_label)
                    sel_d = cl2.date_input("📅 Ngày điều chỉnh", datetime.now(), key="mgr_sel_date")
                    d_str = sel_d.strftime("%Y-%m-%d")

                    # 2. Kiểm tra dữ liệu hiện có của ngày đã chọn
                    with sqlite3.connect("data.db") as conn:
                        df_check = pd.read_sql(
                            "SELECT thoi_gian, trang_thai_lam, nguoi_thao_tac FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", 
                            con=conn, 
                            params=(sel_u, f"{d_str}%")
                        )

                    c_info, c_action = st.columns([2, 1])
                    if not df_check.empty:
                        c_info.dataframe(df_check, use_container_width=True, hide_index=True)
                        if c_action.button("🔥 Reset ngày này", use_container_width=True):
                            with sqlite3.connect("data.db") as conn: 
                                cur = conn.cursor()
                                cur.execute("DELETE FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", (sel_u, f"{d_str}%"))
                                conn.commit()
                            st.success(f"✅ Đã xóa dữ liệu ngày {d_str}")
                            time.sleep(1)
                            st.rerun()
                    else: 
                        c_info.info(f"ℹ️ Ngày {d_str} không có dữ liệu.")

                    st.divider()
                    st.markdown("##### 📝 Gán công nhanh")
                    b1, b2, b3 = st.columns([1, 1, 1])
                    
                    # 3. Logic Gán công nhanh (Sửa từ read_sql thành cur.execute)
                    if b1.button("✅ Gán 1 Ngày công", use_container_width=True):
                        with sqlite3.connect("data.db") as conn:
                            cur = conn.cursor()
                            # Xóa dữ liệu cũ trước khi gán mới
                            cur.execute("DELETE FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", (sel_u, f"{d_str}%"))
                            # Chèn giờ vào/ra chuẩn
                            cur.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", 
                                        (sel_u, f"{d_str} 08:00:00", "Vào làm", user))
                            cur.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", 
                                        (sel_u, f"{d_str} 17:30:00", "Ra về", user))
                            conn.commit()
                        st.success("🎯 Đã gán 1 ngày công thành công")
                        time.sleep(1)
                        st.rerun()
                    
                    if b2.button("🌗 Gán 1/2 Ngày công", use_container_width=True):
                        with sqlite3.connect("data.db") as conn:
                            cur = conn.cursor()
                            # Xóa dữ liệu cũ
                            cur.execute("DELETE FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", (sel_u, f"{d_str}%"))
                            # Chèn giờ sáng
                            cur.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", 
                                        (sel_u, f"{d_str} 08:00:00", "Vào làm", user))
                            cur.execute("INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) VALUES (?,?,?,?)", 
                                        (sel_u, f"{d_str} 12:00:00", "Ra về", user))
                            conn.commit()
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
# PHÂN HỆ 2: GIAO HÀNG - LẮP ĐẶT (FULL HOÀN CHỈNH)
# ==============================================================================
elif menu == "📦 Giao hàng - Lắp đặt":
    # 1. PHÂN QUYỀN TABS
    # Manager, Admin, System Admin có 3 tabs (bao gồm Duyệt đơn)
    # Các chức danh còn lại có 2 tabs (không có Duyệt đơn)
    if role in ["Admin", "System Admin", "Manager"]:
        tabs = st.tabs(["📸 Chấm công lắp đặt", "📋 Duyệt đơn", "📈 Báo cáo lắp đặt"])
    elif chuc_danh in ["KTV Lắp đặt", "Lắp đặt", "Giao nhận", "Quản lý"] or role == "User":
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

        # --- PHẦN PHÂN QUYỀN CHỌN NHÂN VIÊN ---
        target_user = user
        is_management = role in ["Manager", "Admin", "System Admin"]
        
        if is_management:
            with sqlite3.connect("data.db") as conn:
                # LỌC: Chỉ lấy những người có quyền 'User' hoặc 'Manager' (Bỏ qua Admin và System Admin)
                if role == "System Admin":
                    # System Admin có thể chấm công thay cho Admin, Manager và User
                    # Nhưng theo yêu cầu mới: SysAdmin/Admin không cần chấm công -> Chỉ hiện Manager và User
                    df_nv_list = pd.read_sql("SELECT username, ho_ten FROM quan_tri_vien WHERE role IN ('Manager', 'User') AND username IS NOT NULL", conn)
                elif role == "Admin":
                    # Admin chấm công thay cho Manager và User
                    df_nv_list = pd.read_sql("SELECT username, ho_ten FROM quan_tri_vien WHERE role IN ('Manager', 'User') AND username IS NOT NULL", conn)
                else: # Manager
                    # Manager chỉ chấm công thay cho User
                    df_nv_list = pd.read_sql("SELECT username, ho_ten FROM quan_tri_vien WHERE role = 'User' AND username IS NOT NULL", conn)
            
            if not df_nv_list.empty:
                df_nv_list['display'] = df_nv_list['ho_ten'] + " (" + df_nv_list['username'] + ")"
                
                if role in ["System Admin", "Admin"]:
                    # Đối với Admin/SysAdmin: Danh sách chỉ gồm nhân viên cấp dưới (không có tên mình)
                    options = df_nv_list['display'].tolist()
                    sel_nv_display = st.selectbox("🎯 Chấm công lắp đặt cho nhân viên:", options)
                    target_user = df_nv_list[df_nv_list['display'] == sel_nv_display]['username'].values[0]
                else:
                    # Đối với Manager: Có thể "Tự chấm công" hoặc chấm cho "User"
                    options = ["Tự chấm công"] + df_nv_list['display'].tolist()
                    sel_nv_display = st.selectbox("🎯 Chấm công lắp đặt thay cho:", options)
                    if sel_nv_display != "Tự chấm công":
                        target_user = df_nv_list[df_nv_list['display'] == sel_nv_display]['username'].values[0]
                    else:
                        target_user = user

        if "f_up_key" not in st.session_state: st.session_state["f_up_key"] = 0
        uploaded_file = st.file_uploader("🖼️ Ảnh hóa đơn *", type=["jpg", "png", "jpeg"], key=f"up_{st.session_state['f_up_key']}")
        
        with st.form("form_lap_dat", clear_on_submit=True):
            c1, c2 = st.columns(2)
            so_hd_in = c1.text_input("📝 Số hóa đơn *", placeholder="VD: HD12345")
            quang_duong = c2.number_input("🛣️ Quãng đường (km) *", min_value=0, step=1)
            
            st.write("---")
            st.markdown("**📦 Số lượng thiết bị lắp đặt:**")
            m1, m2 = st.columns(2)
            combo_may_lon = m1.number_input("🤖 Máy lớn (200k/máy)", min_value=0, step=1)
            combo_may_nho = m2.number_input("📦 Máy nhỏ / Vật tư", min_value=0, step=1)
            
            noi_dung = st.text_area("📍 Địa chỉ / Ghi chú *", height=100)     
            
            if st.form_submit_button("🚀 GỬI YÊU CẦU DUYỆT ĐƠN", use_container_width=True):
                if not uploaded_file or not so_hd_in or not noi_dung:
                    st.error("❌ Yêu cầu đầy đủ ảnh hoá đơn, số hoá đơn và địa chỉ!")              
                elif combo_may_lon == 0 and combo_may_nho == 0:
                    st.error("❌ Vui lòng nhập ít nhất 1 loại máy!")
                else:
                    so_hd = so_hd_in.upper().strip()
                    
                    # --- LOGIC TÍNH TOÁN ĐA TẦNG ---
                    if quang_duong <= 50:
                        don_gia_km = 30000 if quang_duong < 20 else \
                                     50000 if quang_duong <= 30 else \
                                     70000 if quang_duong <= 40 else 80000
                    else:
                        don_gia_km = 80000 + (quang_duong - 50) * 5000

                    tien_may_lon = combo_may_lon * 200000
                    tien_may_nho = combo_may_nho * don_gia_km
                    tong_tien = tien_may_lon + tien_may_nho
                    
                    tong_combo = combo_may_lon + combo_may_nho
                    noi_dung_final = f"{noi_dung} | (Máy lớn: {combo_may_lon}, Máy nhỏ(hoặc vật tư #): {combo_may_nho})"
                    
                    if not os.path.exists("saved_images"): os.makedirs("saved_images")
                    img_path = f"saved_images/{so_hd}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
                    
                    try:
                        # 1. Lưu file ảnh vật lý
                        with open(img_path, "wb") as f: 
                            f.write(uploaded_file.getbuffer())

                        # 2. Ghi vào Database (Sửa từ read_sql thành cursor.execute)
                        cur = conn.cursor()
                        cur.execute("""
                            INSERT INTO cham_cong 
                            (ten, thoi_gian, so_hoa_don, noi_dung, quang_duong, combo, thanh_tien, hinh_anh, trang_thai) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            target_user, 
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                            so_hd, 
                            noi_dung_final, 
                            quang_duong, 
                            tong_combo, 
                            tong_tien, 
                            img_path, 
                            'Chờ duyệt'
                        ))
                        
                        # 3. Quan trọng: Xác nhận lưu dữ liệu
                        conn.commit()
                            
                        st.success(f"✅ Đã gửi đơn! (Tổng tiền: {tong_tien:,.0f} VNĐ)")
                        st.session_state["f_up_key"] += 1
                        time.sleep(1)
                        st.rerun()

                    except sqlite3.IntegrityError:
                        # Nếu trùng số hóa đơn, xóa ảnh đã lưu để tránh rác bộ nhớ
                        if os.path.exists(img_path): 
                            os.remove(img_path)
                        st.error(f"❌ Số hóa đơn **{so_hd}** đã tồn tại!")
                    except Exception as e:
                        if os.path.exists(img_path): 
                            os.remove(img_path)
                        st.error(f"❌ Lỗi: {e}")

   # --- TAB 2: DUYỆT ĐƠN (CHỈ ADMIN/MANAGER) ---
    if role in ["Admin", "System Admin", "Manager"]:
        with tabs[1]:
            st.markdown("#### 📋 Danh sách đơn chờ duyệt")
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
                            
                            # --- PHÂN QUYỀN THAO TÁC NÚT BẤM ---
                            if role in ["Admin","System Admin"]:
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
                            else:
                                # Nếu là Manager
                                st.info("ℹ️ Bạn chỉ có quyền xem thông tin đơn này. Quyền duyệt thuộc về Kế toán.")
                                
                        with cr:
                            if r["hinh_anh"] and os.path.exists(r["hinh_anh"]):
                                st.image(r["hinh_anh"], caption=f"Ảnh đối soát HĐ {r['so_hoa_don']}", use_container_width=True)
                            else:
                                st.warning("⚠️ Không tìm thấy hình ảnh.")

    # --- TAB 3 (TAB CUỐI): BÁO CÁO LẮP ĐẶT ---
    with tabs[-1]:
        conn = get_conn()
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
            if role in ["Admin", "System Admin", "Manager"]:
                df_all = df_raw.copy()
            else:
                df_all = df_raw[df_raw["username"] == user].copy()

            if df_all.empty:
                st.info("ℹ️ Bạn chưa có đơn hàng nào.")
            else:
                if role in ["Admin", "System Admin", "Manager"]:
                    st.markdown("### 📈 Tổng quan")
                    df_ok = df_all[df_all["Trạng thái"] == "Đã duyệt"]
                    if not df_ok.empty:
                        stats = df_ok.groupby("Tên").agg(So_don=("Số HĐ", "count"), Doanh_thu=("Thành tiền", "sum")).reset_index()
                        c1, c2 = st.columns(2)
                        with c1: st.plotly_chart(px.bar(stats, x="Tên", y="So_don", title="Đơn thành công", text_auto=True), use_container_width=True)
                        with c2: st.plotly_chart(px.pie(stats, values="Doanh_thu", names="Tên", title="Doanh thu"), use_container_width=True)
                    st.divider()

                st.subheader("📄 Chi tiết đơn")
                col_f1, col_f2, col_f3 = st.columns(3)
                
                # --- PHẦN LOGIC MỚI: BỘ LỌC THỜI GIAN ---
                if role in ["Admin", "System Admin"]:
                    # Tạo danh sách 12 tháng gần nhất
                    curr_date = date.today()
                    month_opts = []
                    for i in range(12):
                        m_date = (curr_date.replace(day=1) - pd.DateOffset(months=i))
                        month_opts.append(m_date.strftime("%m/%Y"))
                    
                    sel_month = col_f1.selectbox("📅 Chọn tháng báo cáo", month_opts)
                    
                    # Chuyển đổi tháng chọn thành dải ngày để mask
                    sel_dt = datetime.strptime(sel_month, "%m/%Y")
                    start_d = sel_dt.date().replace(day=1)
                    import calendar
                    last_day = calendar.monthrange(sel_dt.year, sel_dt.month)[1]
                    end_d = sel_dt.date().replace(day=last_day)
                    d_range = [start_d, end_d]
                else:
                    # User thường vẫn chọn dải ngày tự do
                    d_range = col_f1.date_input("📅 Khoảng thời gian", value=[date.today().replace(day=1), date.today()])

                nv_opts = ["Tất cả"] + sorted(df_all["Tên"].astype(str).unique().tolist())
                sel_nv = col_f2.selectbox("👤 Nhân viên", nv_opts, disabled=(role not in ["Admin", "System Admin", "Manager"]))
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
                        
                        # --- XỬ LÝ XUẤT EXCEL CHI TIẾT THEO MẪU CẬP NHẬT ---
                        if not df_display.empty:
                            out = io.BytesIO()
                            
                            # 1. Chuẩn bị dữ liệu bảng chính
                            df_export = df_display.sort_values("Thời Gian").copy()
                            df_export.insert(0, 'STT', range(1, len(df_export) + 1))
                            
                            # Yêu cầu 1: Cột ngày hiển thị dd/mm/yyyy
                            df_export['Ngày'] = df_export['Thời Gian'].dt.strftime('%d/%m/%Y')
                            
                            # YÊU CẦU MỚI: Tách cột Máy và Km riêng biệt
                            df_export['Máy'] = df_export['combo'].fillna("")
                            df_export['Km_Số'] = df_export['Km'].apply(lambda x: f"{int(x)} Km" if x > 0 else "")

                            # Mapping các cột đúng theo form mới (đã tách Máy và Km)
                            df_main = df_export[['STT', 'Ngày', 'Địa chỉ', 'Tên', 'Máy', 'Km_Số', 'Lý do', 'Trạng thái']]
                            df_main.columns = ['STT', 'Ngày', 'Địa chỉ', 'Nhân viên', 'Máy', 'Km', 'Ghi chú', 'Tình trạng']

                            # 2. Chuẩn bị dữ liệu bảng phụ (Chỉ tính đơn Đã duyệt)
                            df_approved = df_display[df_display['Trạng thái'] == 'Đã duyệt'].copy()
                            if not df_approved.empty:
                                df_summary = df_approved.groupby("Tên").agg(
                                    Tong_Don=("Số HĐ", "count"),
                                    Tong_Cong=("Thành tiền", "sum") 
                                ).reset_index()
                            else:
                                df_summary = pd.DataFrame(columns=['TÊN', 'Tổng ĐƠN', 'Tổng CÔNG'])
                                
                            df_summary.columns = ['TÊN', 'Tổng ĐƠN', 'Tổng CÔNG']
                            total_row = pd.DataFrame([['Tổng', df_summary['Tổng ĐƠN'].sum(), df_summary['Tổng CÔNG'].sum()]], 
                                                    columns=['TÊN', 'Tổng ĐƠN', 'Tổng CÔNG'])
                            df_summary = pd.concat([df_summary, total_row], ignore_index=True)

                            with pd.ExcelWriter(out, engine="xlsxwriter") as writer:
                                df_main.to_excel(writer, index=False, sheet_name="BaoCao", startrow=3)
                                wb = writer.book
                                ws = writer.sheets['BaoCao']
                                
                                # --- FORMATS ---
                                title_fmt = wb.add_format({'bold': True, 'font_size': 14, 'align': 'center', 'valign': 'vcenter', 'bg_color': '#92D050', 'border': 1})
                                header_fmt = wb.add_format({'bold': True, 'align': 'center', 'valign': 'vcenter', 'bg_color': '#00B050', 'font_color': 'white', 'border': 1})
                                cell_fmt = wb.add_format({'border': 1, 'valign': 'vcenter'})
                                center_fmt = wb.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter'})
                                note_box_fmt = wb.add_format({'border': 1, 'bg_color': '#EBF1DE', 'text_wrap': True, 'align': 'center', 'valign': 'vcenter', 'font_size': 10})
                                status_fmt = wb.add_format({'border': 1, 'align': 'center', 'bold': True})

                                # --- VẼ BẢNG CHÍNH ---
                                label = sel_month if role in ["Admin", "System Admin"] else f"{d_range[0]} - {d_range[1]}"
                                # Gộp ô tiêu đề từ A đến H (vì có thêm 1 cột do tách Máy/Km)
                                ws.merge_range('A1:H2', f'BẢNG CHẤM CÔNG GIAO HÀNG - LẮP ĐẶT THÁNG {label}', title_fmt)
                                
                                for col_num, value in enumerate(df_main.columns.values):
                                    ws.write(3, col_num, value, header_fmt)
                                
                                ws.set_column('A:A', 5, center_fmt)    # STT
                                ws.set_column('B:B', 12, center_fmt)   # Ngày
                                ws.set_column('C:C', 30, cell_fmt)     # Địa chỉ (đã thu hẹp)
                                ws.set_column('D:D', 25, center_fmt)   # Nhân viên (đã mở rộng)
                                ws.set_column('E:E', 15, center_fmt)   # Cột Máy
                                ws.set_column('F:F', 10, center_fmt)   # Cột Km
                                ws.set_column('G:G', 20, cell_fmt)     # Ghi chú
                                ws.set_column('H:H', 12, status_fmt)   # Tình trạng

                                # --- VẼ GHI CHÚ CÁCH TÍNH TIỀN (Phía trên bảng phụ) ---
                                summary_start_col = 10 # Dời sang cột K để không đè bảng chính đã tách cột
                                note_text = (
                                    "Phụ cấp 30k/ máy đối với đơn đi từ 20km trở xuống\n"
                                    "Phụ cấp 50k/ máy đối với đơn từ 21km – 30km hoặc máy ép nhiệt khí nén.\n"
                                    "Phụ cấp 70k/ máy đối với đơn từ 31 – 40km\n"
                                    "Phụ cấp 80k/ máy đối với đơn từ 41 – 50km. Đối với mỗi km kế tiếp từ 51km +\n"
                                    "5k/1km vượt mức tính\n"
                                    "Đối với các máy khổ lớn hoặc đơn tính sẽ tính theo thỏa thuận."
                                )
                                ws.merge_range(4, summary_start_col, 9, summary_start_col + 2, note_text, note_box_fmt)

                                # --- VẼ BẢNG PHỤ TỔNG QUÁT ---
                                summary_row_header = 11
                                ws.merge_range(summary_row_header, summary_start_col, summary_row_header, summary_start_col + 2, "TỔNG HỢP CÔNG ĐÃ DUYỆT", header_fmt)
                                
                                for col_num, value in enumerate(df_summary.columns.values):
                                    ws.write(summary_row_header + 1, summary_start_col + col_num, value, header_fmt)
                                    
                                for row_num, row_data in enumerate(df_summary.values):
                                    fmt = title_fmt if row_num == len(df_summary) - 1 else center_fmt
                                    for col_num, cell_value in enumerate(row_data):
                                        ws.write(summary_row_header + 2 + row_num, summary_start_col + col_num, cell_value, fmt)
                                
                                # Định dạng cột cho bảng phụ (Tên nhân viên rộng 25)
                                ws.set_column(summary_start_col, summary_start_col, 25) 
                                ws.set_column(summary_start_col + 1, summary_start_col + 2, 15)

                            c_exp.download_button("📥 Tải Excel Báo Cáo", out.getvalue(), f"Bao_Cao_{label.replace('/','_')}.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

                        # --- 3. XỬ LÝ DỮ LIỆU TRƯỚC KHI HIỂN THỊ ---
                        if not df_display.empty:
                            # Tạo bản sao để tránh lỗi SettingWithCopyWarning
                            df_temp = df_display.copy()
                            
                            # 1. Chèn cột STT vào đầu bảng
                            if 'STT' not in df_temp.columns:
                                df_temp.insert(0, 'STT', range(1, len(df_temp) + 1))
                            
                            # 2. Đảm bảo Thành tiền là kiểu số để định dạng %d hoạt động
                            df_temp['Thành tiền'] = pd.to_numeric(df_temp['Thành tiền'], errors='coerce')

                            # --- 3. XỬ LÝ DỮ LIỆU TRƯỚC KHI HIỂN THỊ ---
                            if not df_display.empty:
                                # Tạo bản sao để xử lý
                                df_temp = df_display.copy()
                                
                                # 1. Chèn cột STT vào đầu bảng
                                if 'STT' not in df_temp.columns:
                                    df_temp.insert(0, 'STT', range(1, len(df_temp) + 1))
                                
                                # 2. GỘP CỘT: Địa chỉ - Km - Máy thành cột "Chi tiết lắp đặt"
                                # Đảm bảo các giá trị được chuyển về chuỗi để cộng chuỗi
                                df_temp['Chi tiết lắp đặt'] = (
                                    df_temp['Địa chỉ'].astype(str) + " - " + 
                                    df_temp['Km'].astype(str) + "km - " + 
                                    df_temp['combo'].astype(str) + " máy"
                                )
                                
                                # 3. Ép kiểu Thành tiền về dạng số để định dạng %d hoạt động
                                df_temp['Thành tiền'] = pd.to_numeric(df_temp['Thành tiền'], errors='coerce')

                                # --- 3. HIỂN THỊ BẢNG TRÊN GIAO DIỆN APP ---
                                st.markdown("### 📊 Chi tiết danh sách đơn hàng")
                                
                                st.dataframe(
                                    df_temp, 
                                    use_container_width=True, 
                                    hide_index=True,
                                    # Cập nhật column_order: Thay 3 cột bằng 1 cột gộp
                                    column_order=(
                                        "STT", "Tên", "Thời Gian", "Số HĐ", "Chi tiết lắp đặt", 
                                        "Thành tiền", "Trạng thái", "Lý do", "username"
                                    ),
                                    column_config={
                                        "STT": st.column_config.NumberColumn("STT", width="small"),
                                        "Tên": st.column_config.TextColumn("Nhân viên", width="medium"),
                                        "Thời Gian": st.column_config.DatetimeColumn("Thời gian", format="DD/MM/YYYY HH:mm", width="small"),
                                        "Số HĐ": st.column_config.TextColumn("Số HĐ", width="small"),
                                        "Chi tiết lắp đặt": st.column_config.TextColumn("Địa chỉ - Km - Máy", width="medium"),
                                        "Thành tiền": st.column_config.NumberColumn(
                                            "Thành tiền", 
                                            format="%d VNĐ", 
                                            width="small"
                                        ),
                                        "Trạng thái": st.column_config.TextColumn("Trạng thái", width="small"),
                                        "Lý do": st.column_config.TextColumn("Ghi chú / Lý do", width="medium"),
                                        "username": st.column_config.TextColumn("Người thao tác", width="small"),
                                        # Ẩn các cột gốc đã gộp và id
                                        "id": None,
                                        "Địa chỉ": None,
                                        "Km": None,
                                        "combo": None
                                    }
                                )
                            else:
                                st.info("ℹ️ Hiện chưa có dữ liệu báo cáo trong tháng này.")

                        # --- 3. QUẢN LÝ ĐƠN HÀNG (SỬA/XÓA/HỦY) ---
                        st.divider()

                        # --- DÀNH CHO USER: SỬA HOẶC XÓA ĐƠN ---
                        if role not in ["Admin", "System Admin", "Manager"]:
                            with st.expander("🛠️ Cập nhật thông tin đơn", expanded=False):
                                st.markdown("""
                                **📌 Hướng dẫn trạng thái đơn hàng:**
                                - 🟡 **Chờ duyệt:** Đơn đã gửi, đang chờ Admin kiểm tra. Bạn có thể **Sửa** hoặc **Xóa**.
                                - 🔴 **Từ chối:** Đơn sai thông tin. Vui lòng xem lý do và **cập nhật lại**(Không được phép xoá).
                                - 🟢 **Đã duyệt:** Đơn hợp lệ, đã chốt tiền công. **Không thể chỉnh sửa, admin có thể đảo ngược trạng thái**.
                                ---
                                """, unsafe_allow_html=True)
                                # Lọc danh sách đơn: Cho phép sửa 'Chờ duyệt' và 'Từ chối'
                                df_edit = df_display[df_display["Trạng thái"].isin(["Chờ duyệt", "Từ chối"])]
                                
                                if df_edit.empty:
                                    st.info("ℹ️ Bạn không có đơn hàng nào ở trạng thái Chờ duyệt hoặc Từ chối.")
                                else:
                                    # Tạo nhãn hiển thị kèm trạng thái để user dễ phân biệt
                                    df_edit['label'] = df_edit['Số HĐ'] + " (" + df_edit['Trạng thái'] + ")"
                                    sel_label = st.selectbox("🎯 Chọn đơn hàng cần thao tác:", df_edit["label"].tolist())
                                    sel_hd_edit = sel_label.split(" (")[0]
                                    
                                    row_data = df_edit[df_edit["Số HĐ"] == sel_hd_edit].iloc[0]
                                    row_id = int(row_data["id"])
                                    current_status = row_data["Trạng thái"]

                                    # --- NÚT XÓA ĐƠN (Chỉ cho đơn Chờ duyệt) ---
                                    if current_status == "Chờ duyệt":
                                        if st.button("🗑️ XOÁ ĐƠN NÀY", use_container_width=True, type="secondary"):
                                            try:
                                                with sqlite3.connect("data.db") as conn:
                                                    # Xóa ảnh vật lý trước
                                                    img_to_del = row_data.get('hinh_anh')
                                                    if img_to_del and os.path.exists(img_to_del):
                                                        os.remove(img_to_del)
                                                    
                                                    cur = conn.cursor()
                                                    cur.execute("DELETE FROM cham_cong WHERE id = ? AND trang_thai = 'Chờ duyệt'", (row_id,))
                                                    conn.commit()
                                                st.success("✅ Đã xóa đơn thành công!")
                                                time.sleep(1)
                                                st.rerun()
                                            except Exception as e:
                                                st.error(f"❌ Không thể xóa: {e}")
                                    else:
                                        st.caption("⚠️ Bạn không thể xoá đơn bị từ chối, nhưng có thể cập nhật lại để được duyệt.")

                                    st.write("---")
                                    # --- FORM CẬP NHẬT ---
                                    with st.form(key=f"edit_form_{row_id}", clear_on_submit=True):
                                        st.markdown(f"**📝 Hiệu chỉnh thông tin đơn: {sel_hd_edit}**")
                                        
                                        # Hiển thị ảnh cũ
                                        if 'hinh_anh' in row_data and row_data['hinh_anh'] and os.path.exists(row_data['hinh_anh']):
                                            st.image(row_data['hinh_anh'], width=150, caption="Ảnh hiện tại")
                                        
                                        n_uploaded_file = st.file_uploader("🆕 Đổi ảnh hóa đơn mới (Nếu cần)", type=["jpg", "png", "jpeg"])
                                        
                                        c1, c2 = st.columns(2)
                                        n_hd_in = c1.text_input("📝 Số hóa đơn *", value=str(row_data['Số HĐ']))
                                        # Giả định lấy giá trị cũ từ nội dung hoặc query thêm nếu cần. Ở đây dùng mặc định từ bảng hiển thị.
                                        n_quang_duong = c2.number_input("🛣️ Quãng đường (km) *", min_value=0, step=1, value=20) 
                                        
                                        m1, m2 = st.columns(2)
                                        n_may_lon = m1.number_input("🤖 Máy lớn", min_value=0, step=1, value=0)
                                        n_may_nho = m2.number_input("📦 Máy nhỏ / Vật tư", min_value=0, step=1, value=1)
                                        
                                        n_noi_dung = st.text_area("📍 Địa chỉ / Ghi chú mới *", value=str(row_data['Địa chỉ']), height=80)
                                        
                                        if st.form_submit_button("💾 XÁC NHẬN CẬP NHẬT & GỬI DUYỆT LẠI", use_container_width=True):
                                            # Logic tính tiền (Mẫu)
                                            n_don_gia_km = 30000 if n_quang_duong <= 20 else 50000 if n_quang_duong <= 30 else 70000 if n_quang_duong <= 40 else 80000
                                            if n_quang_duong > 50: n_don_gia_km += (n_quang_duong - 50) * 5000
                                            
                                            n_tong_tien = (n_may_lon * 200000) + (n_may_nho * n_don_gia_km)
                                            n_tong_combo = n_may_lon + n_may_nho
                                            n_noi_dung_final = f"{n_noi_dung} | (Lớn: {n_may_lon}, Nhỏ: {n_may_nho})"
                                            
                                            try:
                                                with sqlite3.connect("data.db") as conn:
                                                    cur = conn.cursor()
                                                    # Sau khi sửa, trạng thái LUÔN quay về 'Chờ duyệt'
                                                    cur.execute("""
                                                        UPDATE cham_cong 
                                                        SET so_hoa_don = ?, noi_dung = ?, quang_duong = ?, combo = ?, 
                                                            thanh_tien = ?, trang_thai = 'Chờ duyệt'
                                                        WHERE id = ?
                                                    """, (n_hd_in.upper().strip(), n_noi_dung_final, n_quang_duong, 
                                                        n_tong_combo, n_tong_tien, row_id))
                                                    conn.commit()
                                                st.success("✅ Đã cập nhật và gửi duyệt lại!")
                                                time.sleep(1)
                                                st.rerun()
                                            except Exception as e:
                                                st.error(f"❌ Lỗi: {e}")

                        # --- DÀNH CHO ADMIN: ĐẢO NGƯỢC TRẠNG THÁI ---
                        if role in ["Admin", "System Admin"]:
                            with st.expander("🔄 Quản lý trạng thái (Hủy duyệt đơn)", expanded=False):
                                st.warning("⚠️ **Lưu ý:** Thao tác này sẽ đưa đơn hàng từ 'Đã duyệt' về lại 'Chờ duyệt' để xử lý lại.")
                                
                                # Admin chỉ xử lý đơn Đã duyệt
                                df_undo = df_display[df_display["Trạng thái"] == "Đã duyệt"]
                                
                                if df_undo.empty:
                                    st.info("ℹ️ Không có đơn nào đã duyệt để đảo ngược.")
                                else:
                                    sel_undo = st.selectbox("⏪ Chọn Số HĐ muốn đưa về chờ duyệt:", df_undo["Số HĐ"].tolist(), key="undo_select")
                                    row_id_undo = int(df_undo[df_undo["Số HĐ"] == sel_undo]["id"].iloc[0])
                                    
                                    # Bổ sung ô nhập lý do đảo ngược
                                    reason_undo = st.text_input("📝 Lý do đưa về chờ duyệt:", placeholder="Ví dụ: Cần kiểm tra lại thực tế số km...")
                                    
                                    if st.button("⏪ ĐẢO NGƯỢC VỀ CHỜ DUYỆT", use_container_width=True, type="primary"):
                                        if not reason_undo:
                                            st.error("❌ Vui lòng nhập lý do để nhân viên biết cần điều chỉnh gì!")
                                        else:
                                            try:
                                                with sqlite3.connect("data.db") as conn:
                                                    cur = conn.cursor()
                                                    # Cập nhật trạng thái và chèn lý do vào cột 'ly_do' (hoặc 'ghi_chu')
                                                    # Ở đây giả định cột lưu lý do của bạn tên là 'ly_do'
                                                    cur.execute("""
                                                        UPDATE cham_cong 
                                                        SET trang_thai = 'Chờ duyệt', 
                                                            ghi_chu_duyet = ? 
                                                        WHERE id = ?
                                                    """, (f"ADMIN HỦY DUYỆT: {reason_undo}", row_id_undo))
                                                    conn.commit()
                                                
                                                st.success(f"✅ Đã chuyển đơn {sel_undo} về trạng thái Chờ duyệt!")
                                                time.sleep(1)
                                                st.rerun()
                                            except Exception as e:
                                                st.error(f"❌ Lỗi: {e}")
# ==============================================================================
# PHÂN HỆ 3: QUẢN TRỊ HỆ THỐNG
# ==============================================================================
elif menu == "⚙️ Quản trị hệ thống":
    # 1. LOGIC CHIA TAB THEO QUYỀN (Phải nằm trong khối elif menu)
    if role == "System Admin":
        list_tabs = ["👥 Nhân sự", "🛠️ Quản trị tài khoản", "🔐 Đổi mật khẩu"]
    elif role in ["Admin", "Manager"]:
        list_tabs = ["👥 Nhân sự", "🔐 Đổi mật khẩu"]
    else: # Role là User
        list_tabs = ["🔐 Đổi mật khẩu"]
    
    tabs = st.tabs(list_tabs)

    # ---------------------------------------------------------
    # TAB: QUẢN LÝ NHÂN SỰ (👥)
    # ---------------------------------------------------------
    if "👥 Nhân sự" in list_tabs:
        idx_ns = list_tabs.index("👥 Nhân sự")
        with tabs[idx_ns]:
            st.subheader("👥 Danh sách nhân sự")
            
            # 1. Lấy dữ liệu với tiêu đề tiếng Việt ngay từ đầu
            with sqlite3.connect("data.db") as conn:
                df_users = pd.read_sql("SELECT * FROM quan_tri_vien", con=conn)
            
            if df_users.empty:
                st.info("Chưa có dữ liệu nhân sự.")
            else:
                # 2. XỬ LÝ HIỂN THỊ BẢNG
                df_users_display = df_users.copy()
                # Thêm cột STT
                df_users_display.insert(0, 'STT', range(1, len(df_users_display) + 1))
                
                st.dataframe(
                    df_users_display,
                    use_container_width=True,
                    hide_index=True,
                    # Sắp xếp thứ tự hiển thị tiếng Việt
                    column_order=("STT", "ho_ten", "chuc_danh", "role", "so_dien_thoai", "ngay_sinh", "dia_chi"),
                    column_config={
                        "STT": st.column_config.NumberColumn("STT", width="small"),
                        "ho_ten": st.column_config.TextColumn("Họ tên", width="medium"),
                        "chuc_danh": st.column_config.TextColumn("Chức danh", width="medium"),
                        "role": st.column_config.TextColumn("Quyền hệ thống", width="small"),
                        "so_dien_thoai": st.column_config.TextColumn("Số điện thoại", width="medium"),
                        "ngay_sinh": st.column_config.DateColumn("Ngày sinh", format="DD/MM/YYYY"),
                        "dia_chi": st.column_config.TextColumn("Địa chỉ", width="large"),
                        "username": None, # Ẩn cột username hệ thống
                        "password": None  # Tuyệt đối ẩn mật khẩu
                    }
                )

                st.divider()
                st.markdown("#### 🛠️ Cập nhật thông tin nhân sự")

                # 3. LOGIC PHÂN QUYỀN CHỌN NHÂN VIÊN
                if role == "System Admin":
                    df_filter = df_users.copy()
                elif role == "Admin":
                    df_filter = df_users[df_users['role'].isin(['Manager', 'User'])].copy()
                elif role == "Manager":
                    df_filter = df_users[df_users['role'] == 'User'].copy()
                else:
                    df_filter = pd.DataFrame()

                if df_filter.empty:
                    st.warning("🔒 Bạn không có quyền cập nhật nhân sự cấp cao hơn.")
                else:
                    df_filter['display_name'] = df_filter['ho_ten'] + " (" + df_filter['chuc_danh'] + ")"
                    selected_display = st.selectbox("🎯 Chọn nhân viên để cập nhật:", options=df_filter['display_name'].tolist())
                    
                    target_u = df_filter[df_filter['display_name'] == selected_display]['username'].values[0]
                    row = df_users[df_users['username'] == target_u].iloc[0]
                    
                    # Chỉ System Admin mới được đổi Quyền và Chức danh
                    is_locked = (role != "System Admin")

                    # 4. FORM CẬP NHẬT THÔNG TIN
                    with st.form(key=f"edit_user_form_{target_u}"):
                        st.caption(f"Đang hiệu chỉnh tài khoản: {target_u}")
                        c1, c2 = st.columns(2)
                        
                        with c1:
                            new_name = st.text_input("👤 Họ và tên", value=str(row['ho_ten']))
                            new_phone = st.text_input("📞 Số điện thoại", value=str(row['so_dien_thoai']))
                            new_addr = st.text_area("📍 Địa chỉ", value=str(row['dia_chi'] if row['dia_chi'] else ""), height=155)
                        
                        with c2:
                            current_cd = str(row['chuc_danh'])
                            if "list_chuc_danh" not in st.session_state:
                                st.session_state["list_chuc_danh"] = ["KTV Lắp đặt", "Giao nhận", "Quản lý", "Văn phòng"]
                            
                            if current_cd not in st.session_state["list_chuc_danh"]:
                                st.session_state["list_chuc_danh"].append(current_cd)
                                
                            new_cd = st.selectbox("💼 Chức danh", st.session_state["list_chuc_danh"], 
                                                index=st.session_state["list_chuc_danh"].index(current_cd),
                                                disabled=is_locked)
                            
                            r_list = ["User", "Manager", "Admin", "System Admin"]
                            curr_r_idx = r_list.index(row['role']) if row['role'] in r_list else 0
                            new_role = st.selectbox("🔑 Quyền hệ thống", r_list, index=curr_r_idx, disabled=is_locked)
                            
                            new_pass = st.text_input("🔐 Mật khẩu mới (Bỏ trống nếu không đổi)", type="password")
                            
                            # Xử lý ngày sinh
                            val_birth = date.today()
                            if 'ngay_sinh' in row and row['ngay_sinh'] and str(row['ngay_sinh']) != 'None':
                                try: val_birth = pd.to_datetime(row['ngay_sinh']).date()
                                except: pass
                            new_birth = st.date_input("📅 Ngày sinh", value=val_birth)

                        if st.form_submit_button("💾 XÁC NHẬN CẬP NHẬT", use_container_width=True):
                            try:
                                with sqlite3.connect("data.db") as conn:
                                    cur = conn.cursor()
                                    if new_pass.strip():
                                        cur.execute("""UPDATE quan_tri_vien 
                                                    SET ho_ten=?, so_dien_thoai=?, dia_chi=?, ngay_sinh=?, password=?, chuc_danh=?, role=?
                                                    WHERE username=?""",
                                                    (new_name, new_phone, new_addr, new_birth.strftime("%Y-%m-%d"), hash_password(new_pass), new_cd, new_role, target_u))
                                    else:
                                        cur.execute("""UPDATE quan_tri_vien 
                                                    SET ho_ten=?, so_dien_thoai=?, dia_chi=?, ngay_sinh=?, chuc_danh=?, role=?
                                                    WHERE username=?""",
                                                    (new_name, new_phone, new_addr, new_birth.strftime("%Y-%m-%d"), new_cd, new_role, target_u))
                                    conn.commit()
                                st.success(f"✅ Đã cập nhật thông tin cho {new_name} thành công!")
                                time.sleep(1)
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Lỗi: {e}")

    # ---------------------------------------------------------
    # TAB 2: QUẢN TRỊ TÀI KHOẢN (Chỉ dành cho System Admin)
    # ---------------------------------------------------------
    if "🛠️ Quản trị tài khoản" in list_tabs:
        idx_qt = list_tabs.index("🛠️ Quản trị tài khoản")
        with tabs[idx_qt]:
            with st.expander("📂 Quản lý danh mục Chức danh"):
                col_a, col_b = st.columns([3, 1], vertical_alignment="bottom")
                
                with col_a:
                    new_cd_input = st.text_input("Nhập chức danh mới:", key="new_cd_add", placeholder="Vd: Thiết Kế")
                
                with col_b:
                    if st.button("➕ Thêm", use_container_width=True, type="secondary"):
                        if new_cd_input:
                            clean_name = new_cd_input.strip()
                            if clean_name not in st.session_state["list_chuc_danh"]:
                                st.session_state["list_chuc_danh"].append(clean_name)
                                st.success(f"Đã thêm '{clean_name}'")
                                time.sleep(0.5); st.rerun()
                            else:
                                st.warning("Chức danh này đã tồn tại!")
                        else:
                            st.error("Vui lòng nhập tên!")

                st.write("**Danh sách hiện tại:**")
                st.caption(", ".join([f"{i}" for i in st.session_state["list_chuc_danh"]]))

            # --- 2. TẠO TÀI KHOẢN MỚI ---
            with st.expander("➕ Tạo tài khoản nhân sự mới", expanded=False):
                with st.form("add_user_full_fixed", clear_on_submit=True): 
                    c1, c2, c3 = st.columns(3)
                    n_u = c1.text_input("Username*").lower().strip()
                    n_p = c2.text_input("Mật khẩu*", type="password")
                    n_r = c3.selectbox("Quyền", ["User", "Manager", "Admin", "System Admin"])
                    n_ten = st.text_input("Họ và tên nhân viên*")
                    
                    c4, c5 = st.columns(2)
                    n_cd = c4.selectbox("Chức danh", st.session_state["list_chuc_danh"])
                    n_phone = c5.text_input("Số điện thoại")
                    
                    submit_create = st.form_submit_button("🚀 TẠO TÀI KHOẢN", use_container_width=True)
                    
                    if submit_create:
                        if not n_u or not n_p or not n_ten:
                            st.error("❌ Thiếu thông tin bắt buộc!")
                        else:
                            try:
                                # 1. Kiểm tra tài khoản đã tồn tại chưa (Dùng pd.read_sql đúng cú pháp)
                                check = pd.read_sql(
                                    "SELECT username FROM quan_tri_vien WHERE username = ?", 
                                    con=conn, 
                                    params=(n_u,)
                                )
                                
                                if not check.empty:
                                    st.error(f"❌ Tài khoản {n_u} đã tồn tại!")
                                else:
                                    # 2. Thực hiện thêm tài khoản mới bằng Cursor (Không dùng read_sql để INSERT)
                                    cur = conn.cursor()
                                    cur.execute("""
                                        INSERT INTO quan_tri_vien (username, password, role, ho_ten, chuc_danh, so_dien_thoai) 
                                        VALUES (?, ?, ?, ?, ?, ?)
                                    """, (n_u, hash_password(n_p), n_r, n_ten, n_cd, n_phone))
                                    
                                    # Xác nhận thay đổi vào Database
                                    conn.commit()
                                    
                                    st.success("✅ Tạo tài khoản thành công!")
                                    time.sleep(1)
                                    st.rerun()
                            except Exception as e: 
                                st.error(f"Lỗi: {e}")

                        st.divider()

            # --- 3. XÓA TÀI KHOẢN (CÓ CƠ CHẾ BẢO VỆ SYSADMIN) ---
            with st.expander("🗑️ Quản lý xóa tài khoản"):
                st.warning("⚠️ **Cảnh báo:** Hành động xóa tài khoản sẽ gỡ bỏ hoàn toàn quyền truy cập.")
                
                with sqlite3.connect("data.db") as conn:
                    df_to_del = pd.read_sql("SELECT username, ho_ten, chuc_danh, role FROM quan_tri_vien WHERE username != ?", conn, params=(user,))
                    count_sysadmin = pd.read_sql("SELECT COUNT(*) as total FROM quan_tri_vien WHERE role = 'System Admin'", conn).iloc[0]['total']
                
                if df_to_del.empty:
                    st.info("📭 Không có tài khoản nào khác để xóa.")
                else:
                    c1, c2 = st.columns([1, 1])
                    with c1:
                        df_to_del['display'] = df_to_del['ho_ten'] + " (" + df_to_del['username'] + ")"
                        u_del_display = st.selectbox("🎯 Chọn tài khoản cần loại bỏ:", options=df_to_del['display'].tolist())
                        u_selected = df_to_del[df_to_del['display'] == u_del_display].iloc[0]
                    with c2:
                        st.markdown("##### 📋 Thông tin đối soát")
                        st.markdown(f"* **Username:** `{u_selected['username']}`\n* **Quyền:** `{u_selected['role']}`")

                    st.divider()
                    confirm_del = st.checkbox(f"Xác nhận xóa tài khoản: **{u_selected['username']}**")
                    
                    if st.button("🔥 THỰC HIỆN XÓA", type="primary", disabled=not confirm_del, use_container_width=True):
                        if u_selected['role'] == 'System Admin' and count_sysadmin <= 1:
                            st.error("❌ Không thể xóa! Hệ thống phải có ít nhất 1 tài khoản System Admin.")
                        else:
                            try:
                                with sqlite3.connect("data.db") as conn:
                                    conn.execute("DELETE FROM quan_tri_vien WHERE username=?", (u_selected['username'],))
                                st.success(f"💥 Đã xóa tài khoản {u_selected['username']}!"); time.sleep(1); st.rerun()
                            except Exception as e: st.error(f"Lỗi: {e}")

            # --- 4. BẢO TRÌ HỆ THỐNG ---
            st.subheader("🔑 Bảo trì hệ thống")           
            with st.expander("💾 Sao lưu và Phục hồi Hệ thống"):
                st.info("💡 **Lưu ý:** Việc phục hồi sẽ ghi đè hoàn toàn dữ liệu hiện tại.")
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("##### 📥 Xuất dữ liệu")
                    if os.path.exists("data.db"):
                        with open("data.db", "rb") as f:
                            st.download_button("Tải bản sao lưu (.db)", data=f, file_name=f"backup_{datetime.now().strftime('%d%m%Y')}.db", use_container_width=True)
                with c2:
                    st.markdown("##### 📤 Phục hồi dữ liệu")
                    if "restore_key" not in st.session_state: st.session_state["restore_key"] = 1000
                    uploaded_db = st.file_uploader("Chọn tệp backup", type=["db"], key=f"up_{st.session_state['restore_key']}")
                    if uploaded_db and st.button("🔄 Xác nhận Phục hồi", use_container_width=True):
                        with open("data.db", "wb") as f: f.write(uploaded_db.getbuffer())
                        st.session_state["restore_key"] += 1 
                        st.success("✅ Thành công!"); time.sleep(2); st.rerun()

            # --- 5. RESET DATABASE ---
            with st.expander("🔥 Dọn dẹp dữ liệu"):
                confirm_reset = st.checkbox("Tôi muốn xóa toàn bộ dữ liệu nghiệp vụ.")
                if st.button("🗑️ RESET DATABASE", type="primary", disabled=not confirm_reset, use_container_width=True):
                    try:
                        with sqlite3.connect("data.db") as conn:
                            conn.execute("DELETE FROM cham_cong") 
                            conn.execute("DELETE FROM cham_cong_di_lam")
                            conn.execute("DELETE FROM quan_tri_vien WHERE role NOT IN ('System Admin')")
                        st.success("💥 Đã dọn dẹp!"); time.sleep(1); st.rerun()
                    except Exception as e: st.error(f"Lỗi: {e}")         

   
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
