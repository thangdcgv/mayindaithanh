import streamlit as st
from supabase import create_client, Client
import pandas as pd
import sqlite3
from datetime import datetime, date
import os
import hashlib
import time
import io
import re
import base64
from PIL import Image
from pathlib import Path
import plotly.express as px
from streamlit_cookies_manager import EncryptedCookieManager

# ==============================================================================
# 1. CẤU HÌNH HỆ THỐNG (Lệnh đầu tiên)
# ==============================================================================
st.set_page_config(page_title="Đại Thành - Ứng Dụng Nội Bộ", layout="wide")
url = st.secrets["SUPABASE_URL"]
key = st.secrets["SUPABASE_KEY"]

# ==============================================================================
# 2. CÁC HÀM BỔ TRỢ VÀ DATABASE
# ==============================================================================
@st.cache_resource
def get_supabase() -> Client:
    return create_client(url, key)

supabase = get_supabase()
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

DB_PATH = os.getenv("DB_PATH", "data/app.db")

def get_conn():
    """Tạo kết nối DB với persistent volume"""
    return sqlite3.connect(
        DB_PATH,
        check_same_thread=False,
        timeout=30
    )



# ==============================================================================
# 3. QUẢN LÝ ĐĂNG NHẬP & COOKIES
# ==============================================================================
cookies = EncryptedCookieManager(
    prefix="daithanh/",
    password="0931334450Th@ngnv@12"
)

if not cookies.ready():
    st.stop()
# 2. HÀM KIỂM TRA ĐĂNG NHẬP (Thay thế cho SQLite)
def check_login_supabase(u, p):
    try:
        import hashlib
        # Đảm bảo dùng đúng thuật toán SHA-256
        pw_hashed = hashlib.sha256(p.encode()).hexdigest()
        
        # Dùng dấu "*" để lấy TOÀN BỘ cột, tránh thiếu chuc_danh
        response = supabase.table("quan_tri_vien")\
            .select("*")\
            .eq("username", u)\
            .eq("password", pw_hashed)\
            .execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
        return None
    except Exception as e:
        st.error(f"Lỗi kết nối: {e}")
        return None

def check_login_by_username(u_in):
    """
    Kiểm tra tự động đăng nhập qua Cookie bằng Supabase.
    """
    try:
        # Truy vấn bảng quan_tri_vien lấy thông tin dựa trên username từ Cookie
        response = supabase.table("quan_tri_vien") \
            .select("role, username, chuc_danh, ho_ten") \
            .eq("username", u_in) \
            .execute()
        
        # Nếu có dữ liệu trả về, lấy phần tử đầu tiên (là một dict)
        if response.data and len(response.data) > 0:
            return response.data[0]
        return None
    except Exception as e:
        st.error(f"Lỗi truy vấn Cookie từ Supabase: {e}")
        return None

# Kiểm tra tự động đăng nhập từ Cookie
if not st.session_state.get("authenticated"):
    saved_user = cookies.get("saved_user")
    if saved_user:
    # Truy vấn thông tin từ Supabase dựa trên username lưu trong Cookie
        res = check_login_by_username(saved_user) 
        
        if res:
            # THAY ĐỔI: Sử dụng Key (tên cột) vì Supabase trả về dạng Dictionary
            st.session_state.update({
                "authenticated": True,
                "role": res.get('role'),         # Thay cho res[0]
                "username": res.get('username'), # Thay cho res[1]
                "chuc_danh": res.get('chuc_danh'),# Thay cho res[2]
                "ho_ten": res.get('ho_ten')       # Thay cho res[3]
            })
            st.rerun()

# ==============================================================================
# 4. GIAO DIỆN CHỨC NĂNG
# ==============================================================================
def login_logic():
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.markdown("<h3 style='text-align: center;'>🔐 Đăng nhập hệ thống</h3>", unsafe_allow_html=True)
        with st.form("login_form_main"):
            u_in = st.text_input("Tên tài khoản").lower().strip()
            p_in = st.text_input("Mật khẩu", type="password")
            remember_me = st.checkbox("Ghi nhớ đăng nhập (30 ngày)")
            submit = st.form_submit_button("ĐĂNG NHẬP", use_container_width=True)

            if submit:
                import hashlib
                # 1. Xem mã băm máy tính tạo ra từ mật khẩu bạn vừa nhập
                pw_hashed_local = hashlib.sha256(p_in.encode()).hexdigest()
                
                # 2. Gọi hàm kiểm tra
                res = check_login_supabase(u_in, p_in)
                
                if res:
                    st.session_state.update({
                        "authenticated": True, 
                        "role": res.get('role'),
                        "username": res.get('username'),
                        "chuc_danh": res.get('chuc_danh'),
                        "ho_ten": res.get('ho_ten')
                    })
                    st.success(f"✅ Chào mừng {res.get('ho_ten')}!")
                    st.rerun()
                else:
                    # --- KHU VỰC HIỂN THỊ LỖI HỆ THỐNG ---
                    st.error("❌ Đăng nhập thất bại")
                    with st.expander("Xem chi tiết lỗi hệ thống (Debug)"):
                        # Kiểm tra xem User có tồn tại không
                        check_user = supabase.table("quan_tri_vien").select("password").eq("username", u_in).execute()
                        
                        if not check_user.data:
                            st.warning(f"Lỗi: Không tìm thấy username '{u_in}' trong bảng quan_tri_vien trên Supabase.")
                        else:
                            db_password = check_user.data[0].get("password")
                            st.info(f"Mã băm máy tính tạo ra: {pw_hashed_local}")
                            st.info(f"Mã băm đang lưu trên DB: {db_password}")
                            
                            if pw_hashed_local != db_password:
                                st.warning("Kết luận: Mật khẩu sai vì hai chuỗi mã băm trên không khớp nhau từng ký tự.")

def logout():
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    if "saved_user" in cookies:
        cookies.delete("saved_user")
    cookies.save()
    st.rerun()

def read_sql(query, params=()):
    with get_conn() as conn:
        return pd.read_sql(query, conn, params=params)

# ==============================================================================
# 1. HÀM HỆ THỐNG & XỬ LÝ DỮ LIỆU (ĐÃ TỐI ƯU CHO COOKIES)
# ==============================================================================

@st.cache_data
def load_logo_base64():
    """Cache ảnh logo để không phải đọc file mỗi lần rerun"""
    if os.path.exists("LOGO.png"):
        with open("LOGO.png", "rb") as f:
            return base64.b64encode(f.read()).decode()
    return None

def hash_password(pw: str):
    """Băm mật khẩu bảo mật"""
    return hashlib.sha256(pw.encode()).hexdigest()


def process_image_to_blob(uploaded_file):
    """Chuyển đổi và nén ảnh để lưu trữ BLOB tối ưu"""
    if uploaded_file is not None:
        try:
            img = Image.open(uploaded_file)
            if img.mode in ("RGBA", "P"): 
                img = img.convert("RGB")
            
            buf = io.BytesIO()
            # Giảm quality xuống 70 giúp DB nhẹ hơn, load ảnh nhanh hơn qua Cookie
            img.save(buf, format="JPEG", quality=70, optimize=True) 
            return buf.getvalue() 
        except Exception as e:
            st.error(f"❌ Lỗi xử lý ảnh: {e}")
            return None
    return None

# ==============================================================================
# 2. BÁO CÁO CHẤM CÔNG (ĐÃ FIX LỖI CACHE GIỮA CÁC TÀI KHOẢN)
# ==============================================================================

def get_attendance_report(target_username, filter_month=None):
    """Hàm tính toán công - Lọc chính xác theo Username từ Cookie"""
    query = "SELECT thoi_gian, trang_thai_lam, ghi_chu FROM cham_cong_di_lam WHERE username=?"
    params = [target_username]
    if filter_month:
        query += " AND thoi_gian LIKE ?"
        params.append(f"{filter_month}%")
    query += " ORDER BY thoi_gian DESC"
    
    # Sử dụng kết nối ổn định
    with get_conn() as conn:
        df = pd.read_sql(query, conn, params=params)
        
    if df.empty: return pd.DataFrame()
    
    # --- Logic tính toán giữ nguyên theo code của bạn ---
    df['thoi_gian'] = pd.to_datetime(df['thoi_gian'])
    df['ngay'] = df['thoi_gian'].dt.date
    summary = []
    
    for date_val, group in df.groupby('ngay', sort=False):
        # 1. Xử lý nghỉ
        if any(group['trang_thai_lam'].str.contains("Nghỉ")):
            status_row = group[group['trang_thai_lam'].str.contains("Nghỉ")].iloc[0]
            loai_cong = status_row['trang_thai_lam']
            summary.append({
                "Ngày": date_val.strftime("%d/%m/%Y"), # Sửa hiển thị sang d/m/Y cho thân thiện
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
                loai_cong = "Không tính công"; ghi_chu_hien_thi = "Chấm công sai"
            elif 3.5 <= tong_gio < 7: 
                loai_cong = "1/2 ngày"; ghi_chu_hien_thi = "Nửa ngày"
            elif tong_gio >= 7: 
                loai_cong = "Ngày"; ghi_chu_hien_thi = "Một ngày"
                
        elif pd.notnull(v_time) and pd.isnull(r_time):
            loai_cong = "Đang làm"; ghi_chu_hien_thi = "Chưa kết thúc"

        db_note = group['ghi_chu'].dropna().unique()
        final_note = db_note[0] if len(db_note) > 0 and db_note[0] != "" else ghi_chu_hien_thi       
        
        summary.append({
            "Ngày": date_val.strftime("%d/%m/%Y"), # Hiển thị chuẩn VN
            "Giờ vào làm": v_time.strftime("%H:%M:%S") if pd.notnull(v_time) else "--:--",
            "Kết thúc làm": r_time.strftime("%H:%M:%S") if pd.notnull(r_time) else "--:--",
            "Tổng giờ": f"{tong_gio}h",
            "Loại công": loai_cong,
            "Ghi chú": final_note
        })
        
    res = pd.DataFrame(summary)
    if not res.empty: res.insert(0, 'STT', range(1, len(res) + 1))
    return res

# CẢI TIẾN QUAN TRỌNG: Cache theo Username để không bị lẫn lộn dữ liệu khi dùng chung máy
@st.cache_data(ttl=300)
def get_attendance_report_cached(current_user, month=None):
    """Cache tách biệt hoàn toàn theo từng UserID"""
    return get_attendance_report(current_user, month)

# ==============================================================================
# 2. CẤU HÌNH GIAO DIỆN & AUTH (ĐÃ TÍCH HỢP COOKIES)
# ==============================================================================

# --- 2. KHỞI TẠO SESSION STATE ---
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""
if "role" not in st.session_state:
    st.session_state["role"] = ""
if "ho_ten" not in st.session_state:
    st.session_state["ho_ten"] = ""
if "chuc_danh" not in st.session_state:
    st.session_state["chuc_danh"] = ""

# --- 3. LOGIC TỰ ĐỘNG ĐĂNG NHẬP TỪ COOKIES ---
if not st.session_state.get("authenticated"):
    # Đổi từ "saved_user" thành "remember_user" cho khớp với lúc lưu
    saved_user = cookies.get("remember_user") 
    
    if saved_user:
        # Truy vấn Supabase (hàm này trả về Dictionary)
        res = check_login_by_username(saved_user)
        
        if res:
            # Sửa từ Index (res[0]) sang Key (res.get('...'))
            st.session_state.update({
                "authenticated": True,
                "role": res.get("role"),         # Thay cho res[0]
                "username": res.get("username"), # Thay cho res[1]
                "chuc_danh": res.get("chuc_danh"), # Thay cho res[2]
                "ho_ten": res.get("ho_ten")       # Thay cho res[3]
            })
            st.rerun()

# --- 4. CSS CUSTOM (Giữ nguyên của bạn) ---
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
            remember_me = st.checkbox("Ghi nhớ đăng nhập (30 ngày)") # Bổ sung checkbox
            
            if st.form_submit_button("ĐĂNG NHẬP", use_container_width=True):
                # Gọi hàm kiểm tra tài khoản qua Supabase
                res = check_login_supabase(u_in, p_in)
                
                if res:
                    # 1. Gán Session State (Sửa từ Index sang Key của Dictionary)
                    st.session_state["authenticated"] = True
                    st.session_state["role"] = res.get("role")         # Thay cho res[0]
                    st.session_state["username"] = res.get("username") # Thay cho res[1]
                    st.session_state["chuc_danh"] = res.get("chuc_danh") # Thay cho res[2]
                    st.session_state["ho_ten"] = res.get("ho_ten")     # Thay cho res[3]
                    
                    # 2. LƯU COOKIE (Đảm bảo dùng đúng key và giá trị username)
                    if remember_me:
                        # Sử dụng key 'remember_user' như bạn yêu cầu
                        cookies["remember_user"] = res.get("username")
                        cookies.save() # Ghi vào trình duyệt
                    
                    st.success(f"✅ Chào mừng {res.get('ho_ten')} đã quay lại!")
                    time.sleep(1) # Chờ 1 giây để user thấy thông báo thành công
                    st.rerun()
                else: 
                    st.error("❌ Sai tài khoản hoặc mật khẩu")
    st.stop()

# ==============================================================================
# 3. GIAO DIỆN CHÍNH (SIDEBAR & MENU)
# ==============================================================================

# Lấy thông tin từ session_state (đã được nạp từ login hoặc cookie)
role = st.session_state.get("role", "N/A")
user = st.session_state.get("username", "N/A")
ho_ten = st.session_state.get("ho_ten", "Nhân viên")
chuc_danh = st.session_state.get("chuc_danh", "N/A")

with st.sidebar:
    # Hiển thị thông tin nhân viên chuyên nghiệp hơn
    st.markdown(f"### 👤 Chào: {ho_ten}")
    st.info(f"🎭 **Quyền:** {role}")
    st.caption(f"💼 **Chức danh:** {chuc_danh}")
    
    # NÚT ĐĂNG XUẤT: Cập nhật logic để xóa triệt để
    if st.button("🚪 Đăng xuất", use_container_width=True, type="secondary"):
        # 1. Xóa Cookie lưu trên trình duyệt (Khớp với tên ở dòng 111 trong file của bạn)
        if "remember_user" in cookies:
            cookies.delete("remember_user")
        
        # 2. Lưu trạng thái cookie ngay lập tức
        cookies.save()
        
        # 3. Xóa sạch Session State
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        
        st.success("Đang đăng xuất...")
        time.sleep(0.5)
        st.rerun()

    st.divider()

    
    # MENU CHỨC NĂNG
    st.markdown("### 🛠️ MENU CHỨC NĂNG")
    
    # Chỉ hiện "Quản trị hệ thống" cho Admin/System Admin
    menu_options = ["📦 Giao hàng - Lắp đặt", "🕒 Chấm công đi làm"]
    if role in ["Admin", "System Admin"]:
        menu_options.append("⚙️ Quản trị hệ thống")
    
    menu = st.radio(
        "Chọn mục làm việc:", 
        options=menu_options,
        label_visibility="collapsed"
    )

# Khởi tạo danh sách chức danh nếu chưa có
if "list_chuc_danh" not in st.session_state:
    st.session_state["list_chuc_danh"] = [
        "Hệ thống", "Kế toán", "KTV Lắp đặt", 
        "Quản lý", "Giao nhận", "Kinh doanh", "Nhân viên"
    ]
# ==============================================================================
# PHÂN HỆ 1: CHẤM CÔNG ĐI LÀM
# ==============================================================================
# ==============================================================================
# PHÂN HỆ 1: CHẤM CÔNG ĐI LÀM (ĐÃ TỐI ƯU CHO COOKIES)
# ==============================================================================
if menu == "🕒 Chấm công đi làm":
    # Sử dụng thông tin trực tiếp từ Session State (Đã nạp từ Cookie/Login)
    role = st.session_state.get("role")
    user = st.session_state.get("username")
    ho_ten = st.session_state.get("ho_ten")

    if role in ["Admin", "System Admin"]:
        tabs = st.tabs(["📍 Chấm công", "🛠️ Quản lý & Sửa công", "📊 Báo cáo chấm công"])
    else:
        tabs = st.tabs(["📍 Chấm công"])

    # --- TAB 1: DÀNH CHO NHÂN VIÊN ---
    with tabs[0]:
        # Không cần truy vấn SQL lấy ho_ten nữa vì đã có trong Session
        if role == "System Admin":
            st.info("💡 Sếp trả lương cho nhân viên là công đức vô lượng rồi, không cần chấm công.")
        else:
            st.markdown(f"##### ⏰ Chấm công: {ho_ten}")
            
            # Sử dụng múi giờ Việt Nam để tránh lệch giờ khi server đặt ở nước ngoài
            now = datetime.now()
            today_str = now.strftime("%Y-%m-%d")
            current_month = now.strftime("%Y-%m") # Định dạng YYYY-MM để dùng cho LIKE
            display_month = now.strftime("%m/%Y")

            # Mở kết nối tập trung
            with get_conn() as conn:
                # 1. Kiểm tra trạng thái hôm nay
                df_today = pd.read_sql(
                    "SELECT trang_thai_lam FROM cham_cong_di_lam WHERE username = ? AND thoi_gian LIKE ?", 
                    conn, params=(user, f"{today_str}%")
                )
                
                has_in = any(df_today['trang_thai_lam'] == "Vào làm")
                has_out = any(df_today['trang_thai_lam'] == "Ra về")
                has_off = any(df_today['trang_thai_lam'].str.contains("Nghỉ"))

                c_left, c_right = st.columns([1, 2.2])
                with c_left:
                    col_in, col_out = st.columns(2)

                    # --- NÚT VÀO LÀM ---
                    if col_in.button("📍 VÀO LÀM", use_container_width=True, type="primary", 
                                     disabled=(has_in or has_off), key="btn_in"):                       
                        try:
                            cur = conn.cursor()
                            cur.execute("""
                                INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) 
                                VALUES (?,?,?,?)
                            """, (user, now.strftime("%Y-%m-%d %H:%M:%S"), "Vào làm", user))
                            conn.commit()
                            st.toast("✅ Đã ghi nhận giờ vào")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Lỗi: {e}")

                    # --- NÚT RA VỀ ---
                    if col_out.button("🏁 RA VỀ", use_container_width=True, 
                                      disabled=(not has_in or has_out or has_off), key="btn_out"):
                        try:
                            cur = conn.cursor()
                            cur.execute("""
                                INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) 
                                VALUES (?,?,?,?)
                            """, (user, now.strftime("%Y-%m-%d %H:%M:%S"), "Ra về", user))
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
                            type_off = st.selectbox("Loại nghỉ", ["Có phép", "Không phép"])
                            reason_off = st.text_input("Lý do nghỉ", placeholder="Nhập lý do...")
                            
                            if st.button("Xác nhận nghỉ", use_container_width=True):
                                if not reason_off: 
                                    st.error("Vui lòng nhập lý do")
                                else:
                                    cur = conn.cursor()
                                    cur.execute("""
                                        INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, ghi_chu, nguoi_thao_tac) 
                                        VALUES (?,?,?,?,?)
                                    """, (user, now.strftime("%Y-%m-%d %H:%M:%S"), f"Nghỉ {type_off}", reason_off, user))
                                    conn.commit()
                                    st.success("Đã gửi đăng ký nghỉ")
                                    time.sleep(1)
                                    st.rerun()

                    show_detail = st.button("📊 Chi tiết chấm công cá nhân", use_container_width=True)

                with c_right:
                    # Truyền USERNAME từ session vào hàm cache
                    df_quick = get_attendance_report_cached(user)
                    if not df_quick.empty:
                        st.caption("Ngày làm việc gần nhất")
                        st.dataframe(df_quick.head(3), use_container_width=True, hide_index=True)

                if show_detail:
                    @st.dialog("Bảng chi tiết chấm công cá nhân", width="large")
                    def show_month_detail_dialog():
                        st.subheader(f"📅 Tháng {display_month}")
                        # Dùng hàm report lấy theo user từ session
                        df_detail = get_attendance_report(user, current_month)
                        
                        if not df_detail.empty:
                            # --- Logic hiển thị metric (giữ nguyên) ---
                            st.dataframe(df_detail, use_container_width=True, hide_index=True)
                        else: 
                            st.write("Chưa có dữ liệu trong tháng này.")
                    show_month_detail_dialog()
                else:
                    st.warning("⚠️ Tài khoản chưa được liên kết thông tin nhân sự.")

        # --- TAB 2: QUẢN LÝ & SỬA CÔNG (ADMIN) ---
    if role in ["Admin", "System Admin"]:
        with tabs[1]:
            st.markdown("#### 🛠️ Điều chỉnh công nhân viên")
            
            # Lấy thông tin Admin hiện tại từ session (do Cookie nạp vào)
            current_admin = st.session_state.get("username")
            
            # 1. Lấy danh sách nhân viên
            with get_conn() as conn:
                query_nv = "SELECT username, ho_ten FROM quan_tri_vien WHERE role != 'System Admin'"
                # Admin không được tự sửa công của chính mình (đảm bảo tính khách quan)
                if role == "Admin": 
                    query_nv += f" AND username != '{current_admin}'"
                
                list_nv = pd.read_sql(query_nv, con=conn)

            if not list_nv.empty:
                # Tạo label hiển thị
                list_nv['label'] = list_nv['ho_ten'] + " (" + list_nv['username'] + ")"
                label_to_user = dict(zip(list_nv['label'], list_nv['username']))
                
                cl1, cl2 = st.columns(2)
                sel_label = cl1.selectbox("👤 Chọn nhân viên", options=list_nv['label'].tolist(), key="mgr_sel_user")
                sel_u = label_to_user.get(sel_label)
                sel_d = cl2.date_input("📅 Ngày điều chỉnh", datetime.now(), key="mgr_sel_date")
                d_str = sel_d.strftime("%Y-%m-%d")

                # 2. Kiểm tra dữ liệu hiện có
                with get_conn() as conn:
                    df_check = pd.read_sql(
                        "SELECT thoi_gian, trang_thai_lam, nguoi_thao_tac FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", 
                        con=conn, 
                        params=(sel_u, f"{d_str}%")
                    )

                c_info, c_action = st.columns([2, 1])
                if not df_check.empty:
                    c_info.caption(f"Dữ liệu hiện tại của {sel_u}")
                    c_info.dataframe(df_check, use_container_width=True, hide_index=True)
                    
                    if c_action.button("🔥 Reset ngày này", use_container_width=True, help="Xóa toàn bộ công ngày này của NV"):
                        with get_conn() as conn: 
                            cur = conn.cursor()
                            cur.execute("DELETE FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", (sel_u, f"{d_str}%"))
                            conn.commit()
                        st.toast(f"✅ Đã xóa dữ liệu ngày {d_str}")
                        time.sleep(0.5)
                        st.rerun()
                else: 
                    c_info.info(f"ℹ️ Ngày {d_str} không có dữ liệu.")

                st.divider()
                st.markdown("##### 📝 Gán công nhanh")
                st.caption("Lưu ý: Thao tác này sẽ xóa dữ liệu cũ của ngày được chọn trước khi gán mới.")
                b1, b2, b3 = st.columns([1, 1, 1])
                
                # 3. Logic Gán công nhanh
                # current_admin đóng vai trò là 'nguoi_thao_tac' để lưu vết
                if b1.button("✅ Gán 1 Ngày công", use_container_width=True, type="primary"):
                    with get_conn() as conn:
                        cur = conn.cursor()
                        cur.execute("DELETE FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", (sel_u, f"{d_str}%"))
                        cur.execute("""INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) 
                                    VALUES (?,?,?,?)""", (sel_u, f"{d_str} 08:00:00", "Vào làm", current_admin))
                        cur.execute("""INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) 
                                    VALUES (?,?,?,?)""", (sel_u, f"{d_str} 17:30:00", "Ra về", current_admin))
                        conn.commit()
                    st.success(f"🎯 Đã gán 1 ngày công cho {sel_u}")
                    time.sleep(1)
                    st.rerun()
                
                if b2.button("🌗 Gán 1/2 Ngày công", use_container_width=True):
                    with get_conn() as conn:
                        cur = conn.cursor()
                        cur.execute("DELETE FROM cham_cong_di_lam WHERE username=? AND thoi_gian LIKE ?", (sel_u, f"{d_str}%"))
                        cur.execute("""INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) 
                                    VALUES (?,?,?,?)""", (sel_u, f"{d_str} 08:00:00", "Vào làm", current_admin))
                        cur.execute("""INSERT INTO cham_cong_di_lam (username, thoi_gian, trang_thai_lam, nguoi_thao_tac) 
                                    VALUES (?,?,?,?)""", (sel_u, f"{d_str} 12:00:00", "Ra về", current_admin))
                        conn.commit()
                    st.success(f"🎯 Đã gán 1/2 ngày công cho {sel_u}")
                    time.sleep(1)
                    st.rerun()

        # --- TAB 3: BÁO CÁO TỔNG HỢP (ADMIN) ---
    if role in ["Admin", "System Admin"]:
        with tabs[2]:
            st.markdown("#### 📊 Báo cáo chấm công nhân viên")
            col_f1, col_f2 = st.columns(2)
            
            # 1. Lấy danh sách nhân viên bằng kết nối an toàn
            with get_conn() as conn:
                df_users = pd.read_sql("SELECT username, ho_ten FROM quan_tri_vien WHERE role != 'System Admin'", conn)
            
            if not df_users.empty:
                df_users['label'] = df_users['ho_ten'] + " (" + df_users['username'] + ")"
                user_dict = dict(zip(df_users['label'], df_users['username']))
                
                # Chọn nhân viên
                selected_label = col_f1.selectbox("👤 Chọn nhân viên báo cáo", options=df_users['label'].tolist())
                target_user_rpt = user_dict.get(selected_label)
                
                # Chọn thời gian
                c_month, c_year = col_f2.columns(2)
                now_dt = datetime.now()
                sel_m = c_month.selectbox("📅 Tháng", range(1, 13), index=now_dt.month - 1)
                sel_y = c_year.selectbox("📅 Năm", range(now_dt.year - 2, now_dt.year + 1), index=2)
                
                # Định dạng chuỗi tìm kiếm khớp với DB (YYYY-MM)
                month_str = f"{sel_y}-{sel_m:02d}"
                
                # Gọi hàm báo cáo (Hàm này đã được tối ưu ở các phần trước)
                df_report = get_attendance_report(target_user_rpt, month_str)
                
                if not df_report.empty:
                    # Tính toán tổng hợp
                    # Lưu ý: Dùng .str.contains an toàn hơn với dữ liệu có thể có khoảng trắng
                    total_full = len(df_report[df_report['Loại công'].str.contains("Ngày", na=False)])
                    total_half = len(df_report[df_report['Loại công'].str.contains("1/2", na=False)])
                    
                    # Hiển thị số liệu tổng quát
                    m1, m2 = st.columns(2)
                    m1.metric(f"Tổng công tháng {sel_m}/{sel_y}", f"{total_full + (total_half * 0.5)} công")
                    m2.caption(f"Nhân viên: {selected_label}")
                    
                    # Hiển thị bảng dữ liệu
                    st.dataframe(df_report, use_container_width=True, hide_index=True)
                    
                    # --- XỬ LÝ XUẤT EXCEL ---
                    output = io.BytesIO()
                    # Sử dụng XlsxWriter để format bảng Excel chuyên nghiệp hơn
                    with pd.ExcelWriter(output, engine='xlsxwriter') as writer: 
                        df_report.to_excel(writer, index=False, sheet_name='BaoCao')
                        
                        # Tối ưu: Tự động căn chỉnh độ rộng cột trong file Excel
                        workbook  = writer.book
                        worksheet = writer.sheets['BaoCao']
                        header_format = workbook.add_format({'bold': True, 'bg_color': '#D7E4BC', 'border': 1})
                        for col_num, value in enumerate(df_report.columns.values):
                            worksheet.write(0, col_num, value, header_format)
                            worksheet.set_column(col_num, col_num, 15)

                    st.download_button(
                        label="📥 Tải báo cáo Excel",
                        data=output.getvalue(),
                        file_name=f"ChamCong_{target_user_rpt}_{month_str}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True
                    )
                else: 
                    st.info(f"ℹ️ Không có dữ liệu chấm công của **{target_user_rpt}** trong tháng {sel_m}/{sel_y}")

# ==============================================================================
# PHÂN HỆ 2: GIAO HÀNG - LẮP ĐẶT (ĐÃ TỐI ƯU CHO COOKIES)
# ==============================================================================
elif menu == "📦 Giao hàng - Lắp đặt":
    # Lấy thông tin từ session_state (đã nạp từ Cookie)
    role = st.session_state.get("role", "User")
    chuc_danh = st.session_state.get("chuc_danh", "N/A")
    user_hien_tai = st.session_state.get("username")

    # 1. PHÂN QUYỀN TABS
    # Gom nhóm logic để dễ quản lý
    is_manager = role in ["Admin", "System Admin", "Manager"] or chuc_danh == "Quản lý"
    
    if is_manager:
        tabs = st.tabs(["📸 Chấm công lắp đặt", "📋 Duyệt đơn", "📈 Báo cáo lắp đặt"])
    else:
        # Nhân viên kỹ thuật/giao nhận chỉ thấy 2 tab
        tabs = st.tabs(["📸 Chấm công lắp đặt", "📈 Báo cáo lắp đặt"])

    # 2. HÀM CẬP NHẬT TRẠNG THÁI (Cải tiến để ghi vết người duyệt)
    def quick_update_status(record_id, new_status, reason=""):
        try:
            with get_conn() as conn: # Dùng get_conn() đã có timeout
                # Bổ sung ghi chú ai là người duyệt vào nội dung ghi chú
                full_reason = f"[{user_hien_tai}] {reason}" if reason else f"Duyệt bởi: {user_hien_tai}"
                conn.execute(
                    "UPDATE cham_cong SET trang_thai = ?, ghi_chu_duyet = ? WHERE id = ?", 
                    (new_status, full_reason, record_id)
                )
                conn.commit()
            return True
        except Exception as e:
            st.error(f"Lỗi cập nhật: {e}")
            return False

    # --- TAB 1: GỬI ĐƠN LẮP ĐẶT (TỐI ƯU CHO COOKIE) ---
    with tabs[0]:
        # Lấy trực tiếp từ Session State đã nạp bởi Cookie Manager
        user = st.session_state.get("username")
        role = st.session_state.get("role")
        ho_ten_sender = st.session_state.get("ho_ten", user)

        # --- PHẦN PHÂN QUYỀN CHỌN NHÂN VIÊN ---
        target_user = user # Mặc định là chính mình
        is_management = role in ["Manager", "Admin", "System Admin"]
        
        if is_management:
            with get_conn() as conn:
                if role == "System Admin":
                    df_nv_list = pd.read_sql("SELECT username, ho_ten FROM quan_tri_vien WHERE role IN ('Manager', 'User')", conn)
                elif role == "Admin":
                    df_nv_list = pd.read_sql("SELECT username, ho_ten FROM quan_tri_vien WHERE role IN ('Manager', 'User')", conn)
                else: # Manager
                    df_nv_list = pd.read_sql("SELECT username, ho_ten FROM quan_tri_vien WHERE role = 'User'", conn)
            
            if not df_nv_list.empty:
                df_nv_list['display'] = df_nv_list['ho_ten'] + " (" + df_nv_list['username'] + ")"
                if role in ["System Admin", "Admin"]:
                    options = df_nv_list['display'].tolist()
                    sel_nv_display = st.selectbox("🎯 Chấm công lắp đặt cho nhân viên:", options)
                    target_user = df_nv_list[df_nv_list['display'] == sel_nv_display]['username'].values[0]
                else:
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
            noi_dung = noi_dung.title().strip()
            
            if st.form_submit_button("🚀 GỬI YÊU CẦU DUYỆT ĐƠN", use_container_width=True):
                if not uploaded_file or not so_hd_in or not noi_dung:
                    st.error("❌ Yêu cầu đầy đủ ảnh hoá đơn, số hoá đơn và địa chỉ!")              
                elif combo_may_lon == 0 and combo_may_nho == 0:
                    st.error("❌ Vui lòng nhập ít nhất 1 loại máy!")
                else:
                    so_hd = so_hd_in.strip().upper()
                    final_hd = f"HD{so_hd}" if not so_hd.startswith("HD") else so_hd
                    
                    # --- LOGIC TÍNH TOÁN ---
                    if quang_duong <= 50:
                        don_gia_km = 30000 if quang_duong < 20 else 50000 if quang_duong <= 30 else 70000 if quang_duong <= 40 else 80000
                    else:
                        don_gia_km = 80000 + (quang_duong - 50) * 5000
                        
                    tong_tien = (combo_may_lon * 200000) + (combo_may_nho * don_gia_km)
                    tong_combo = combo_may_lon + combo_may_nho
                    noi_dung_final = f"{noi_dung} | (Máy lớn: {combo_may_lon}, Máy nhỏ: {combo_may_nho})"
                    
                    # --- XỬ LÝ ẢNH & LƯU DB ---
                    try:
                        blob_data = process_image_to_blob(uploaded_file) # Sử dụng hàm đã tối ưu ở phần trước

                        with get_conn() as conn:
                            cur = conn.cursor()
                            # LƯU Ý: Cập nhật tên cột "ten" thành "username" nếu bạn đã đổi DB, 
                            # hoặc lưu target_user vào cột "ten" để đồng bộ với Cookie.
                            cur.execute("""
                                INSERT INTO cham_cong 
                                (username, ten, thoi_gian, so_hoa_don, noi_dung, quang_duong, combo, thanh_tien, hinh_anh, trang_thai) 
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                target_user,       # Lưu username để lọc báo cáo chính xác
                                ho_ten_sender,     # Lưu họ tên để hiển thị nhanh
                                datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                                final_hd, 
                                noi_dung_final, 
                                quang_duong, 
                                tong_combo, 
                                tong_tien, 
                                blob_data, 
                                'Chờ duyệt'
                            ))
                            conn.commit()
                                
                        st.success(f"✅ Gửi đơn thành công cho nhân viên: {ho_ten_sender}")
                        st.session_state["f_up_key"] += 1
                        time.sleep(1)
                        st.rerun()

                    except sqlite3.IntegrityError:
                        st.error(f"❌ Số hóa đơn **{final_hd}** đã tồn tại!")
                    except Exception as e:
                        st.error(f"❌ Lỗi hệ thống: {e}")

    # --- TAB 2: DUYỆT ĐƠN (CHỈ ADMIN/MANAGER) ---
    if role in ["Admin", "System Admin", "Manager"]:
        with tabs[1]:
            st.markdown("#### 📋 Danh sách đơn chờ duyệt")
            
            # 1. Sử dụng get_conn() để tránh lock database khi load ảnh BLOB
            with get_conn() as conn:
                # JOIN qua cột username để lấy ho_ten chính xác của nhân viên
                df_p = pd.read_sql("""
                    SELECT c.*, q.ho_ten 
                    FROM cham_cong c 
                    LEFT JOIN quan_tri_vien q ON c.username = q.username 
                    WHERE c.trang_thai='Chờ duyệt' 
                    ORDER BY c.thoi_gian DESC
                """, conn)

            if df_p.empty:
                st.info("📭 Hiện tại không có đơn nào đang chờ xử lý.")
            else:
                # Đếm số lượng đơn để Admin dễ nắm bắt
                st.caption(f"Đang có {len(df_p)} đơn cần xử lý")
                
                for _, r in df_p.iterrows():
                    # Xử lý hiển thị thời gian
                    try:
                        dt_obj = datetime.strptime(r['thoi_gian'], "%Y-%m-%d %H:%M:%S")
                        thoi_gian_hien_thi = dt_obj.strftime("%d/%m/%Y %H:%M")
                    except:
                        thoi_gian_hien_thi = r['thoi_gian']

                    # Tiêu đề expander hiển thị đầy đủ thông tin tóm tắt
                    with st.expander(f"📦 HĐ: {r['so_hoa_don']} — 👤 {r['ho_ten']} — 🕒 {thoi_gian_hien_thi}"):
                        cl, cr = st.columns([1.5, 1])
                        with cl:
                            st.write(f"**📍 Nội dung/Địa chỉ:** {r['noi_dung']}")
                            st.markdown(f"🛣️ **Quãng đường:** `{r['quang_duong']} km` | 📦 **Tổng máy:** `{r['combo']}`")
                            st.markdown(f"#### 💰 Thành tiền: `{r['thanh_tien']:,.0f}` VNĐ")
                            st.divider()
                            
                            # --- LOGIC THAO TÁC DUYỆT ĐƠN ---
                            # Kiểm tra quyền duyệt (Admin hoặc Manager có quyền duyệt)
                            if role in ["Admin", "System Admin"]:
                                b1, b2 = st.columns(2)
                                
                                # Nút DUYỆT
                                if b1.button("✅ DUYỆT", key=f"ap_{r['id']}", use_container_width=True, type="primary"):
                                    if quick_update_status(r["id"], "Đã duyệt", "Thông tin chính xác"):
                                        st.toast(f"✅ Đã duyệt đơn {r['so_hoa_don']}")
                                        time.sleep(0.5)
                                        st.rerun()
                                        
                                # Nút TỪ CHỐI với Popover để nhập lý do
                                with b2:
                                    with st.popover("❌ TỪ CHỐI", use_container_width=True):
                                        reason = st.text_area("Lý do từ chối:", key=f"txt_{r['id']}", placeholder="Ví dụ: Sai số hóa đơn, Ảnh mờ...")
                                        if st.button("Xác nhận từ chối đơn", key=f"conf_{r['id']}", use_container_width=True, type="secondary"):
                                            if not reason.strip():
                                                st.error("Bắt buộc phải có lý do từ chối!")
                                            else:
                                                if quick_update_status(r["id"], "Từ chối", reason):
                                                    st.toast(f"❌ Đã từ chối đơn {r['so_hoa_don']}")
                                                    time.sleep(0.5)
                                                    st.rerun()
                            else:
                                # Phân quyền cho Manager (Chỉ xem, không được duyệt tiền)
                                st.info("ℹ️ Quản lý chỉ có quyền xem nội dung. Kế toán/Admin sẽ thực hiện bước duyệt đơn cuối cùng.")
                                
                        with cr:
                            if r["hinh_anh"]:
                                # Tạo một nút bấm để mở Modal
                                if st.button(f"🔍 Xem ảnh", key=f"view_{r['id']}"):
                                    @st.dialog("Chi tiết hóa đơn", width="large") # Modal kích thước lớn
                                    def show_image(img_data):
                                        st.image(img_data, use_container_width=True)
                                        if st.button("Đóng"):
                                            st.rerun()
                                    
                                    show_image(r["hinh_anh"])
                            else:
                                st.warning("Không có ảnh")          

    # --- TAB 3: BÁO CÁO LẮP ĐẶT (TỔI ƯU CHO COOKIE & HIỆU SUẤT) ---
    with tabs[-1]:
        # Lấy thông tin từ Session (đã nạp bởi Cookie Manager)
        user_hien_tai = st.session_state.get("username")
        role = st.session_state.get("role")
        
        with get_conn() as conn:
            # CHỈNH SỬA: Không SELECT cột hinh_anh ở đây để báo cáo chạy cực nhanh
            # CHỈNH SỬA: JOIN dựa trên c.username thay vì c.ten
            query = """
                SELECT c.id, q.ho_ten AS 'Tên', c.username AS 'username', 
                    c.thoi_gian AS 'Thời Gian', 
                    c.so_hoa_don AS 'Số HĐ', c.noi_dung AS 'Địa chỉ', 
                    c.quang_duong AS 'Km', c.combo,
                    c.thanh_tien AS 'Thành tiền', c.trang_thai AS 'Trạng thái', 
                    c.ghi_chu_duyet AS 'Lý do'
                FROM cham_cong AS c 
                LEFT JOIN quan_tri_vien AS q ON c.username = q.username
            """
            df_raw = pd.read_sql(query, conn)

        if df_raw.empty:
            # df_raw['Người gửi'] = df_raw['ho_ten'].fillna(df_raw['username'])
            st.info("📭 Chưa có dữ liệu đơn hàng nào trong hệ thống.")
        else:
            # Chuyển đổi thời gian an toàn
            df_raw["Thời Gian"] = pd.to_datetime(df_raw["Thời Gian"], errors='coerce')
            df_raw = df_raw.dropna(subset=["Thời Gian"])

            # PHÂN QUYỀN HIỂN THỊ DỮ LIỆU
            # Admin/Manager xem tất cả, User chỉ xem đơn của chính mình (lấy từ Cookie)
            if role in ["Admin", "System Admin", "Manager"]:
                df_all = df_raw.copy()
            else:
                df_all = df_raw[df_raw["username"] == user_hien_tai].copy()

            if df_all.empty:
                st.info("ℹ️ Bạn chưa có dữ liệu đơn hàng nào được ghi nhận.")
            else:
                # GIAO DIỆN TỔNG QUAN (DÀNH CHO QUẢN LÝ)
                if role in ["Admin", "System Admin", "Manager"]:
                    st.markdown("### 📈 Biểu đồ tổng quan")
                    
                    # Chỉ tính toán trên các đơn đã được duyệt thành công
                    df_ok = df_all[df_all["Trạng thái"] == "Đã duyệt"]
                    
                    if not df_ok.empty:
                        stats = df_ok.groupby("Tên").agg(
                            So_don=("Số HĐ", "count"), 
                            Doanh_thu=("Thành tiền", "sum")
                        ).reset_index()
                        
                        c1, c2 = st.columns(2)
                        with c1:
                            fig_bar = px.bar(stats, x="Tên", y="So_don", 
                                            title="Số đơn đã duyệt theo NV", 
                                            text_auto=True, color="Tên")
                            st.plotly_chart(fig_bar, use_container_width=True)
                            
                        with c2:
                            fig_pie = px.pie(stats, values="Doanh_thu", names="Tên", 
                                            title="Tỷ lệ doanh thu lắp đặt",
                                            hole=0.4) # Biểu đồ dạng Donut cho hiện đại
                            st.plotly_chart(fig_pie, use_container_width=True)
                    else:
                        st.warning("Chưa có đơn hàng nào được chuyển trạng thái 'Đã duyệt'.")
                    
                    st.divider()

                # --- 4. BÁO CÁO CHI TIẾT (ĐÃ TỐI ƯU CHO COOKIE) ---
                with st.expander("📊 Tra cứu chi tiết và Xuất báo cáo đơn hàng", expanded=False):
                    col_f1, col_f2, col_f3 = st.columns(3)
                    
                    # Lấy thông tin từ Session đã nạp bởi Cookie
                    current_role = st.session_state.get("role")
                    current_user = st.session_state.get("username")
                    current_ho_ten = st.session_state.get("ho_ten")

                    # --- PHẦN LOGIC: BỘ LỌC THỜI GIAN ---
                    if current_role in ["Admin", "System Admin"]:
                        # Admin chọn theo tháng cố định
                        curr_date = date.today()
                        month_opts = []
                        for i in range(12):
                            m_date = (curr_date.replace(day=1) - pd.DateOffset(months=i))
                            month_opts.append(m_date.strftime("%m/%Y"))
                        
                        sel_month = col_f1.selectbox("📅 Chọn tháng báo cáo", month_opts)
                        
                        sel_dt = datetime.strptime(sel_month, "%m/%Y")
                        start_d = sel_dt.date().replace(day=1)
                        import calendar
                        last_day = calendar.monthrange(sel_dt.year, sel_dt.month)[1]
                        end_d = sel_dt.date().replace(day=last_day)
                        d_range = [start_d, end_d]
                    else:
                        # Nhân viên/Manager chọn dải ngày tự do
                        d_range = col_f1.date_input("📅 Khoảng thời gian", 
                                                    value=[date.today().replace(day=1), date.today()], 
                                                    format="DD/MM/YYYY")

                    # Bộ lọc nhân viên: Nếu là User thì bị khóa chỉ được xem chính mình
                    nv_opts = ["Tất cả"] + sorted(df_all["Tên"].astype(str).unique().tolist())
                    
                    # Mặc định chọn chính mình nếu là User
                    default_nv_idx = 0
                    if current_role not in ["Admin", "System Admin", "Manager"] and current_ho_ten in nv_opts:
                        default_nv_idx = nv_opts.index(current_ho_ten)

                    sel_nv = col_f2.selectbox("👤 Nhân viên", nv_opts, 
                                            index=default_nv_idx,
                                            disabled=(current_role not in ["Admin", "System Admin", "Manager"]))
                    
                    sel_tt = col_f3.selectbox("📌 Trạng thái", ["Tất cả", "Chờ duyệt", "Đã duyệt", "Từ chối"])

                    # Chỉ xử lý khi dải ngày hợp lệ (đã chọn đủ start và end)
                    if isinstance(d_range, list) and len(d_range) == 2:
                        mask = (df_all["Thời Gian"].dt.date >= d_range[0]) & (df_all["Thời Gian"].dt.date <= d_range[1])
                        if sel_nv != "Tất cả": 
                            mask &= df_all["Tên"] == sel_nv
                        if sel_tt != "Tất cả": 
                            mask &= df_all["Trạng thái"] == sel_tt
                        
                        df_display = df_all[mask].sort_values("Thời Gian", ascending=False)
                        
                        if df_display.empty:
                            st.info("🔍 Không có dữ liệu phù hợp với bộ lọc.")
                        else:
                            c_met, c_exp = st.columns([2, 1])
                            rev_sum = df_display[df_display["Trạng thái"] == "Đã duyệt"]["Thành tiền"].sum()
                            c_met.metric("💰 Tổng thu nhập đã duyệt", f"{rev_sum:,.0f} VNĐ")
                            
                            # Hiển thị bảng dữ liệu xem trước
                            st.dataframe(df_display.drop(columns=['username'], errors='ignore'), use_container_width=True, hide_index=True)

                            # --- XỬ LÝ XUẤT EXCEL CHI TIẾT THEO MẪU ---
                            out = io.BytesIO()
                            df_export = df_display.sort_values("Thời Gian").copy()
                            df_export.insert(0, 'STT', range(1, len(df_export) + 1))
                            df_export['Ngày'] = df_export['Thời Gian'].dt.strftime('%d/%m/%Y')
                            df_export['Máy'] = df_export['combo'].fillna(0).astype(int)
                            df_export['Km_Số'] = df_export['Km'].apply(lambda x: f"{int(x)} Km" if x > 0 else "")

                            # Chuẩn bị bảng chính
                            df_main = df_export[['STT', 'Ngày', 'Địa chỉ', 'Tên', 'Máy', 'Km_Số', 'Lý do', 'Trạng thái']]
                            df_main.columns = ['STT', 'Ngày', 'Địa chỉ', 'Nhân viên', 'Số Máy', 'Km', 'Ghi chú duyệt', 'Tình trạng']

                            # Chuẩn bị bảng tổng hợp (Summary)
                            df_approved = df_display[df_display['Trạng thái'] == 'Đã duyệt'].copy()
                            if not df_approved.empty:
                                df_summary = df_approved.groupby("Tên").agg(
                                    Tong_Don=("Số HĐ", "count"),
                                    Tong_Cong=("Thành tiền", "sum") 
                                ).reset_index()
                            else:
                                df_summary = pd.DataFrame(columns=['TÊN', 'Tổng ĐƠN', 'Tổng CÔNG'])
                                
                            df_summary.columns = ['TÊN', 'Tổng ĐƠN', 'Tổng CÔNG']
                            if not df_summary.empty:
                                total_row = pd.DataFrame([['TỔNG CỘNG', df_summary['Tổng ĐƠN'].sum(), df_summary['Tổng CÔNG'].sum()]], 
                                                        columns=['TÊN', 'Tổng ĐƠN', 'Tổng CÔNG'])
                                df_summary = pd.concat([df_summary, total_row], ignore_index=True)

                            # Ghi file Excel
                            with pd.ExcelWriter(out, engine="xlsxwriter") as writer:
                                df_main.to_excel(writer, index=False, sheet_name="BaoCao", startrow=3)
                                wb = writer.book
                                ws = writer.sheets['BaoCao']
                                
                                # --- FORMATS (Đã tối ưu màu sắc hiển thị) ---
                                title_fmt = wb.add_format({'bold': True, 'font_size': 14, 'align': 'center', 'valign': 'vcenter', 'bg_color': '#C6EFCE', 'border': 1})
                                header_fmt = wb.add_format({'bold': True, 'align': 'center', 'valign': 'vcenter', 'bg_color': '#2E75B6', 'font_color': 'white', 'border': 1})
                                cell_fmt = wb.add_format({'border': 1, 'valign': 'vcenter'})
                                center_fmt = wb.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter'})
                                note_box_fmt = wb.add_format({'border': 1, 'bg_color': '#F2F2F2', 'text_wrap': True, 'align': 'left', 'valign': 'vcenter', 'font_size': 9})
                                
                                label_time = sel_month if current_role in ["Admin", "System Admin"] else f"{d_range[0].strftime('%d/%m')} - {d_range[1].strftime('%d/%m/%Y')}"
                                ws.merge_range('A1:H2', f'BẢNG TỔNG HỢP CÔNG LẮP ĐẶT - {label_time}', title_fmt)
                                
                                # Format cột
                                ws.set_column('A:A', 5, center_fmt)
                                ws.set_column('B:B', 12, center_fmt)
                                ws.set_column('C:C', 35, cell_fmt)
                                ws.set_column('D:D', 20, cell_fmt)
                                ws.set_column('E:F', 10, center_fmt)
                                ws.set_column('G:G', 20, cell_fmt)
                                ws.set_column('H:H', 15, center_fmt)

                                # Ghi bảng tổng hợp bên cạnh
                                summary_start_col = 10
                                ws.write(3, summary_start_col, "TỔNG HỢP CHI PHÍ", title_fmt)
                                df_summary.to_excel(writer, index=False, sheet_name="BaoCao", startrow=4, startcol=summary_start_col)

                            c_exp.download_button(
                                label="📥 Tải Excel Báo Cáo", 
                                data=out.getvalue(), 
                                file_name=f"Bao_Cao_Lap_Dat_{current_user}_{date.today()}.xlsx", 
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                use_container_width=True
                            )

                            # --- 3. HIỂN THỊ BẢNG TRÊN GIAO DIỆN (TỐI ƯU CHO COOKIE & DATA_EDITOR) ---
                            df_temp = df_display.copy()

                            # Xóa các cột nặng/không cần thiết trước khi render để app chạy mượt hơn
                            if 'hinh_anh' in df_temp.columns:
                                df_temp = df_temp.drop(columns=['hinh_anh'])

                            # 1. THÊM CỘT CHỌN (Chỉ dành cho System Admin)
                            if role == "System Admin":
                                # Khởi tạo mặc định False cho cột Chọn
                                df_temp.insert(0, "Chọn", False)

                            # 2. THÊM CỘT STT
                            if 'STT' not in df_temp.columns:
                                stt_pos = 1 if role == "System Admin" else 0
                                df_temp.insert(stt_pos, 'STT', range(1, len(df_temp) + 1))

                            # 3. CHUẨN HÓA DỮ LIỆU HIỂN THỊ
                            df_temp['Chi tiết lắp đặt'] = (
                                df_temp['Địa chỉ'].astype(str) + " - " + 
                                df_temp['Km'].astype(str) + "km - " + 
                                df_temp['combo'].astype(str) + " máy"
                            )
                            df_temp['Thành tiền'] = pd.to_numeric(df_temp['Thành tiền'], errors='coerce')

                            # --- 4. LOGIC PHÂN TRANG (Tối ưu để không bị lỗi khi lọc dữ liệu) ---
                            rows_per_page = 10
                            total_rows = len(df_temp)
                            total_pages = max((total_rows // rows_per_page) + (1 if total_rows % rows_per_page > 0 else 0), 1)

                            # Sử dụng key riêng cho phân hệ lắp đặt để không trùng với chấm công
                            if 'page_lap_dat' not in st.session_state:
                                st.session_state.page_lap_dat = 1

                            # Kiểm tra nếu trang hiện tại vượt quá tổng số trang do bộ lọc (filter) thay đổi
                            if st.session_state.page_lap_dat > total_pages:
                                st.session_state.page_lap_dat = 1

                            if total_rows > 0:
                                st.markdown(f"###### *Danh sách đơn hàng (Tổng: {total_rows} đơn)")
                                
                                # GIAO DIỆN CHUYỂN TRANG
                                if total_pages > 1:
                                    col_nav1, col_nav2, col_nav3 = st.columns([1, 2, 1])
                                    with col_nav1:
                                        if st.button("⬅️ Trước", use_container_width=True, disabled=(st.session_state.page_lap_dat == 1)):
                                            st.session_state.page_lap_dat -= 1
                                            st.rerun()
                                    with col_nav2:
                                        st.markdown(f"<p style='text-align:center; color:grey;'>Trang {st.session_state.page_lap_dat} / {total_pages}</p>", unsafe_allow_html=True)
                                    with col_nav3:
                                        if st.button("Sau ➡️", use_container_width=True, disabled=(st.session_state.page_lap_dat == total_pages)):
                                            st.session_state.page_lap_dat += 1
                                            st.rerun()
                                            
                                    page_num = st.session_state.page_lap_dat
                                else:
                                    page_num = 1
                                
                                start_idx = (page_num - 1) * rows_per_page
                                end_idx = start_idx + rows_per_page
                                df_page = df_temp.iloc[start_idx:end_idx]

                                # --- 5. HIỂN THỊ BẢNG VỚI DATA_EDITOR ---
                                base_order = ["STT", "Tên", "Thời Gian", "Số HĐ", "Chi tiết lắp đặt", "Thành tiền", "Trạng thái", "Lý do", "username"]
                                final_order = (["Chọn"] + base_order) if role == "System Admin" else base_order

                                edited_df = st.data_editor(
                                    df_page, 
                                    use_container_width=True, 
                                    hide_index=True,
                                    column_order=final_order,
                                    column_config={
                                        "Chọn": st.column_config.CheckboxColumn("Chọn", default=False),
                                        "STT": st.column_config.NumberColumn("STT", width="small"),
                                        "Thành tiền": st.column_config.NumberColumn("Thành tiền", format="%d VNĐ"),
                                        "Thời Gian": st.column_config.DatetimeColumn("Thời gian", format="DD/MM/YYYY HH:mm"),
                                        "Trạng thái": st.column_config.TextColumn("Trạng thái", width="small"),
                                        "username": st.column_config.TextColumn("Người tạo", width="small"),
                                        "id": None, "Địa chỉ": None, "Km": None, "combo": None, "ghi_chu_duyet": None # Ẩn cột ID và các cột rác
                                    },
                                    disabled=[c for c in df_page.columns if c != "Chọn"]
                                )

                                # --- 6. NÚT XOÁ (Dành cho System Admin) ---
                                if role == "System Admin":
                                    # Tìm ID các dòng được chọn
                                    selected_ids = edited_df[edited_df["Chọn"] == True]["id"].tolist()
                                    if selected_ids:
                                        st.warning(f"🔔 Đang chọn {len(selected_ids)} mục để xử lý.")
                                        if st.button("🔥 XÁC NHẬN XÓA VĨNH VIỄN", type="primary", use_container_width=True):
                                            try:
                                                with get_conn() as conn: # Dùng hàm get_conn có timeout để an toàn
                                                    cur = conn.cursor()
                                                    placeholders = ','.join(['?'] * len(selected_ids))
                                                    cur.execute(f"DELETE FROM cham_cong WHERE id IN ({placeholders})", selected_ids)
                                                    conn.commit()
                                                
                                                st.success("✅ Đã xóa dữ liệu thành công!")
                                                time.sleep(0.5)
                                                st.rerun()
                                            except Exception as e:
                                                st.error(f"❌ Lỗi: {e}")
                                    else:
                                        st.caption("💡 *Mẹo: Tích chọn ô ở cột đầu tiên để thực hiện xóa hàng loạt đơn hàng.*")
                            else:
                                st.info("ℹ️ Hiện chưa có dữ liệu báo cáo nào.")

                # --- 3. QUẢN LÝ ĐƠN HÀNG (SỬA/XÓA/HỦY) ---
                st.divider()

                # Lấy thông tin từ Cookie/Session
                user_login = st.session_state.get("username")
                role_login = st.session_state.get("role")

                # --- DÀNH CHO USER & MANAGER: SỬA HOẶC XÓA ĐƠN CỦA CHÍNH MÌNH ---
                if role_login in ["User", "Manager"]:
                    with st.expander("🛠️ Cập nhật thông tin đơn", expanded=False):
                        st.markdown("""
                        **📌 Hướng dẫn trạng thái đơn hàng:**
                        - 🟡 **Chờ duyệt:** Đơn đã gửi. Bạn có thể **Sửa** hoặc **Xóa**.
                        - 🔴 **Từ chối:** Đơn sai thông tin. Vui lòng **cập nhật lại**.
                        - 🟢 **Đã duyệt:** Đơn hợp lệ. **Không thể chỉnh sửa**.
                        """)
                            
                        # Lọc chính xác đơn của người dùng đang đăng nhập qua Cookie
                        df_edit = df_all[
                            (df_all["username"] == user_login) & 
                            (df_all["Trạng thái"].isin(["Chờ duyệt", "Từ chối"]))
                        ].copy()
                        
                        if df_edit.empty:
                            st.info("ℹ️ Bạn không có đơn hàng nào ở trạng thái Chờ duyệt hoặc Từ chối.")
                        else:
                            # Tạo nhãn hiển thị cho selectbox
                            df_edit['label'] = df_edit['Số HĐ'].astype(str) + " (" + df_edit['Trạng thái'] + ")"
                            sel_label = st.selectbox("🎯 Chọn đơn hàng cần thao tác:", df_edit["label"].tolist(), key="sel_edit_order")
                            sel_hd_edit = sel_label.split(" (")[0]
                            
                            row_data = df_edit[df_edit["Số HĐ"] == sel_hd_edit].iloc[0]
                            row_id = int(row_data["id"])
                            current_status = row_data["Trạng thái"]
                            
                            # --- LOGIC TÁCH DỮ LIỆU AN TOÀN (Sửa lỗi tại đây) ---
                            # Sử dụng .get() để tránh KeyError và str() để đảm bảo kiểu dữ liệu chuỗi
                            full_content = str(row_data.get('Địa chỉ', ''))
                            
                            # Kiểm tra xem chuỗi có định dạng máy lớn/nhỏ " | (" không
                            if " | (" in full_content:
                                raw_address = full_content.split(" | (")[0]
                            else:
                                raw_address = full_content
                            
                            # Lấy thông số kỹ thuật (Dùng Km thay vì quang_duong nếu bạn đặt alias trong SQL)
                            val_quang_duong = int(row_data.get('Km', 0))
                            current_may_lon = 0
                            current_may_nho = 0
                            
                            if " | (Máy lớn: " in full_content:
                                try:
                                    # Tách phần máy lớn và máy nhỏ từ chuỗi gộp
                                    parts = full_content.split(" | (")[1].replace(")", "").split(", ")
                                    current_may_lon = int(parts[0].split(": ")[1])
                                    current_may_nho = int(parts[1].split(": ")[1])
                                except Exception:
                                    # Nếu lỗi định dạng, lấy tổng từ cột combo
                                    current_may_nho = int(row_data.get('combo', 0))

                            # Truy vấn lấy ảnh cũ từ DB
                            with get_conn() as conn:
                                cur = conn.cursor()
                                cur.execute("SELECT hinh_anh FROM cham_cong WHERE id = ?", (row_id,))
                                res = cur.fetchone()
                                old_img_blob = res[0] if res else None

                            # --- NÚT XÓA ĐƠN ---
                            if current_status == "Chờ duyệt":
                                if st.button("🗑️ XOÁ ĐƠN NÀY", use_container_width=True, type="secondary"):
                                    try:
                                        with get_conn() as conn:
                                            conn.execute("DELETE FROM cham_cong WHERE id = ? AND username = ? AND trang_thai = 'Chờ duyệt'", (row_id, user_login))
                                            conn.commit()
                                        st.success("✅ Đã xóa đơn thành công!")
                                        time.sleep(0.5)
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"❌ Không thể xóa: {e}")
                            else:
                                # Hiển thị lý do từ chối nếu có
                                ly_do_tu_choi = row_data.get('Lý do', 'Không có lý do cụ thể')
                                st.warning(f"🔴 Đơn bị từ chối. Lý do: **{ly_do_tu_choi}**")

                            st.write("---")
                            # --- FORM CẬP NHẬT ---
                            with st.form(key=f"edit_form_{row_id}", clear_on_submit=False):
                                st.markdown(f"**📝 Hiệu chỉnh đơn: {sel_hd_edit}**")
                                
                                if old_img_blob:
                                    with st.popover("🖼️ Xem ảnh hóa đơn hiện tại", use_container_width=True):
                                        st.image(old_img_blob, use_container_width=True)
                                
                                n_uploaded_file = st.file_uploader("🆕 Thay ảnh hóa đơn mới (Để trống nếu giữ nguyên)", type=["jpg", "png", "jpeg"])
                                
                                c1, c2 = st.columns(2)
                                n_hd_in = c1.text_input("📝 Số hóa đơn *", value=str(row_data.get('Số HĐ', '')))
                                n_quang_duong = c2.number_input("🛣️ Quãng đường (km) *", min_value=0, step=1, value=val_quang_duong)
                                
                                m1, m2 = st.columns(2)
                                n_may_lon = m1.number_input("🤖 Máy lớn", min_value=0, step=1, value=current_may_lon)
                                n_may_nho = m2.number_input("📦 Máy nhỏ / Vật tư", min_value=0, step=1, value=current_may_nho)
                                
                                n_noi_dung = st.text_area("📍 Địa chỉ / Ghi chú mới *", value=raw_address, height=80)
                                
                                if st.form_submit_button("💾 XÁC NHẬN CẬP NHẬT & GỬI DUYỆT LẠI", use_container_width=True, type="primary"):
                                    if not n_hd_in or not n_noi_dung:
                                        st.error("Vui lòng điền đủ Số hóa đơn và Địa chỉ!")
                                    else:
                                        # Tính toán lại đơn giá theo Km (Logic cũ của bạn)
                                        if n_quang_duong <= 50:
                                            n_don_gia_km = 30000 if n_quang_duong < 20 else 50000 if n_quang_duong <= 30 else 70000 if n_quang_duong <= 40 else 80000
                                        else:
                                            n_don_gia_km = 80000 + (n_quang_duong - 50) * 5000
                                        
                                        n_tong_tien = (n_may_lon * 200000) + (n_may_nho * n_don_gia_km)
                                        n_tong_combo = n_may_lon + n_may_nho
                                        n_noi_dung_final = f"{n_noi_dung.title().strip()} | (Máy lớn: {n_may_lon}, Máy nhỏ: {n_may_nho})"
                                        
                                        final_img_blob = old_img_blob 
                                        thoi_gian_cap_nhat = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                                        try:
                                            # Xử lý nén ảnh mới nếu có tải lên
                                            if n_uploaded_file:
                                                from PIL import Image
                                                img_pil = Image.open(n_uploaded_file)
                                                if img_pil.mode in ("RGBA", "P"): 
                                                    img_pil = img_pil.convert("RGB")
                                                img_byte_arr = io.BytesIO()
                                                img_pil.save(img_byte_arr, format='JPEG', quality=70, optimize=True)
                                                final_img_blob = img_byte_arr.getvalue()

                                            with get_conn() as conn:
                                                conn.execute("""
                                                    UPDATE cham_cong 
                                                    SET so_hoa_don = ?, noi_dung = ?, quang_duong = ?, 
                                                        combo = ?, thanh_tien = ?, hinh_anh = ?, 
                                                        trang_thai = 'Chờ duyệt', thoi_gian = ?, ghi_chu_duyet = ''
                                                    WHERE id = ? AND username = ?
                                                """, (
                                                    n_hd_in.upper().strip(), n_noi_dung_final, n_quang_duong, 
                                                    n_tong_combo, n_tong_tien, final_img_blob, 
                                                    thoi_gian_cap_nhat, row_id, user_login
                                                ))
                                                conn.commit()
                                            
                                            st.success("✅ Đã cập nhật và gửi duyệt lại!")
                                            time.sleep(0.5)
                                            st.rerun()
                                        except Exception as e:
                                            st.error(f"❌ Lỗi: {e}")

                # --- DÀNH CHO ADMIN: ĐẢO NGƯỢC TRẠNG THÁI (ĐÃ TỐI ƯU) ---
                if role in ["Admin", "System Admin"]:
                    with st.expander("🔄 Quản lý trạng thái (Hủy duyệt đơn)", expanded=False):
                        st.warning("⚠️ **Lưu ý:** Thao tác này sẽ đưa đơn hàng từ 'Đã duyệt' về lại 'Chờ duyệt' để xử lý lại.")
                        
                        # Chỉ lọc những đơn đã được duyệt trong tập dữ liệu hiện tại
                        df_undo = df_all[df_all["Trạng thái"] == "Đã duyệt"].copy()
                        
                        if df_undo.empty:
                            st.info("ℹ️ Không có đơn nào ở trạng thái 'Đã duyệt' để đảo ngược.")
                        else:
                            # 1. Chọn hóa đơn cần đảo ngược
                            sel_undo = st.selectbox("⏪ Chọn Số HĐ muốn đưa về chờ duyệt:", 
                                                    df_undo["Số HĐ"].tolist(), 
                                                    key="undo_select_box")
                            
                            # 2. Lấy ID đơn hàng
                            row_undo_data = df_undo[df_undo["Số HĐ"] == sel_undo].iloc[0]
                            row_id_undo = int(row_undo_data["id"])
                            
                            # 3. Lấy ảnh trực tiếp từ DB (Vì ở bước Báo cáo ta đã loại bỏ cột hinh_anh để app chạy nhanh)
                            img_blob_undo = None
                            with get_conn() as conn:
                                cur = conn.cursor()
                                cur.execute("SELECT hinh_anh FROM cham_cong WHERE id = ?", (row_id_undo,))
                                res = cur.fetchone()
                                if res:
                                    img_blob_undo = res[0]

                            # Hiển thị ảnh kiểm tra
                            if img_blob_undo:
                                with st.popover(f"🔍 Xem lại ảnh hóa đơn {sel_undo}", use_container_width=True):
                                    if isinstance(img_blob_undo, bytes):
                                        st.image(img_blob_undo, use_container_width=True, caption=f"Ảnh đối soát {sel_undo}")
                                    else:
                                        st.error("Dữ liệu ảnh không đúng định dạng.")
                            else:
                                st.caption("ℹ️ Đơn này không có ảnh đính kèm.")

                            # 4. Nhập lý do và xử lý đảo ngược
                            reason_undo = st.text_input("📝 Lý do đưa về chờ duyệt:", 
                                                        placeholder="Ví dụ: Kế toán yêu cầu kiểm tra lại km...",
                                                        key="reason_undo_input")
                            
                            if st.button("⏪ XÁC NHẬN ĐẢO NGƯỢC", use_container_width=True, type="primary"):
                                if not reason_undo:
                                    st.error("❌ Vui lòng nhập lý do để nhân viên biết cần điều chỉnh gì!")
                                else:
                                    try:
                                        # Lấy tên Admin từ Session (Cookie)
                                        admin_name = st.session_state.get("ho_ten", "Admin")
                                        with get_conn() as conn:
                                            cur = conn.cursor()
                                            cur.execute("""
                                                UPDATE cham_cong 
                                                SET trang_thai = 'Chờ duyệt', 
                                                    ghi_chu_duyet = ? 
                                                WHERE id = ?
                                            """, (f"[{admin_name}] HỦY DUYỆT: {reason_undo}", row_id_undo))
                                            conn.commit()
                                        
                                        st.success(f"✅ Đã chuyển đơn {sel_undo} về trạng thái Chờ duyệt!")
                                        time.sleep(0.5)
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"❌ Lỗi: {e}")
# ==============================================================================
# PHÂN HỆ 3: QUẢN TRỊ HỆ THỐNG
# ==============================================================================

elif menu == "⚙️ Quản trị hệ thống":
    role_login = st.session_state.get("role", "User")
    
    # 1. Xác định danh sách tab dựa trên quyền
    if role_login == "System Admin":
        list_tabs = ["👥 Nhân sự", "🛠️ Quản trị tài khoản", "🔐 Đổi mật khẩu"]
    elif role_login in ["Admin", "Manager"]:
        list_tabs = ["👥 Nhân sự", "🔐 Đổi mật khẩu"]
    else: 
        list_tabs = ["🔐 Đổi mật khẩu"]
    
    # 2. Khởi tạo Tabs
    tabs = st.tabs(list_tabs)

    # 3. Hiển thị nội dung bằng cách duyệt qua list_tabs
    for i, tab_name in enumerate(list_tabs):
        with tabs[i]:
            if tab_name == "👥 Nhân sự":
                st.subheader("Quản lý nhân sự")
                # 1. Lấy dữ liệu (Sử dụng get_conn để an toàn hơn cho hệ thống Cookie)
                with get_conn() as conn:
                    df_users = pd.read_sql("SELECT * FROM quan_tri_vien", con=conn)
                
                if df_users.empty:
                    st.info("Chưa có dữ liệu nhân sự.")
                else:
                    # 2. XỬ LÝ HIỂN THỊ BẢNG
                    df_users_display = df_users.copy()
                    df_users_display.insert(0, 'STT', range(1, len(df_users_display) + 1))
                    
                    st.dataframe(
                        df_users_display,
                        use_container_width=True,
                        hide_index=True,
                        column_order=("STT", "ho_ten", "chuc_danh", "role", "so_dien_thoai", "ngay_sinh", "dia_chi"),
                        column_config={
                            "STT": st.column_config.NumberColumn("STT", width="small"),
                            "ho_ten": st.column_config.TextColumn("Họ tên", width="medium"),
                            "chuc_danh": st.column_config.TextColumn("Chức danh", width="medium"),
                            "role": st.column_config.TextColumn("Quyền hệ thống", width="small"),
                            "so_dien_thoai": st.column_config.TextColumn("Số điện thoại", width="medium"),
                            "ngay_sinh": st.column_config.DateColumn("Ngày sinh", format="DD/MM/YYYY"),
                            "dia_chi": st.column_config.TextColumn("Địa chỉ", width="large"),
                            "username": None, "password": None # Bảo mật tuyệt đối
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
                        # Tạo tên hiển thị sạch sẽ để chọn
                        df_filter['display_name'] = df_filter['ho_ten'].fillna("Chưa có tên") + " (" + df_filter['username'] + ")"
                        selected_display = st.selectbox("🎯 Chọn nhân viên để cập nhật:", 
                                                    options=df_filter['display_name'].tolist(),
                                                    key="sb_edit_user")
                        
                        target_u = df_filter[df_filter['display_name'] == selected_display]['username'].values[0]
                        row = df_users[df_users['username'] == target_u].iloc[0]
                        
                        # Lock quyền nếu không phải System Admin
                        is_locked = (role != "System Admin")

                        # 4. FORM CẬP NHẬT THÔNG TIN
                        with st.form(key=f"edit_user_form_{target_u}", clear_on_submit=False):
                            st.caption(f"🆔 Tài khoản hệ thống: **{target_u}**")
                            c1, c2 = st.columns(2)
                            
                            with c1:
                                new_name = st.text_input("👤 Họ và tên *", value=str(row['ho_ten']))
                                new_phone = st.text_input("📞 Số điện thoại", value=str(row['so_dien_thoai'] if row['so_dien_thoai'] else ""))
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
                                
                                new_pass = st.text_input("🔐 Mật khẩu mới (Để trống nếu không đổi)", type="password", help="Chỉ điền nếu muốn reset mật khẩu cho nhân viên")
                                
                                # Xử lý ngày sinh an toàn
                                val_birth = date.today()
                                if 'ngay_sinh' in row and row['ngay_sinh'] and str(row['ngay_sinh']) != 'None':
                                    try:
                                        val_birth = pd.to_datetime(row['ngay_sinh']).date()
                                    except:
                                        pass
                                new_birth = st.date_input("📅 Ngày sinh", value=val_birth, format="DD/MM/YYYY")

                            if st.form_submit_button("💾 XÁC NHẬN CẬP NHẬT", use_container_width=True, type="primary"):
                                if not new_name:
                                    st.error("❌ Họ và tên không được để trống!")
                                else:
                                    try:
                                        # Chuẩn hóa dữ liệu trước khi lưu
                                        final_name = new_name.strip().title()
                                        final_addr = new_addr.strip()

                                        with get_conn() as conn:
                                            cur = conn.cursor()
                                            if new_pass.strip():
                                                # Nếu có mật khẩu mới, dùng hàm hash
                                                cur.execute("""UPDATE quan_tri_vien 
                                                            SET ho_ten=?, so_dien_thoai=?, dia_chi=?, ngay_sinh=?, password=?, chuc_danh=?, role=?
                                                            WHERE username=?""",
                                                            (final_name, new_phone, final_addr, new_birth.strftime("%Y-%m-%d"), hash_password(new_pass), new_cd, new_role, target_u))
                                            else:
                                                cur.execute("""UPDATE quan_tri_vien 
                                                            SET ho_ten=?, so_dien_thoai=?, dia_chi=?, ngay_sinh=?, chuc_danh=?, role=?
                                                            WHERE username=?""",
                                                            (final_name, new_phone, final_addr, new_birth.strftime("%Y-%m-%d"), new_cd, new_role, target_u))
                                            conn.commit()
                                        
                                        st.success(f"✅ Đã cập nhật thành công nhân sự: {final_name}")
                                        
                                        # Nếu cập nhật chính tài khoản đang login, thông báo cần F5 để Cookie cập nhật
                                        if target_u == role_login:
                                            st.info("💡 Bạn vừa cập nhật thông tin cá nhân. Hãy tải lại trang để thấy thay đổi.")
                                            
                                        time.sleep(1)
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"❌ Lỗi truy vấn: {e}")
            elif tab_name == "🛠️ Quản trị tài khoản":
                st.subheader("Cài đặt hệ thống")
                current_user = st.session_state.get("username", "")
                # --- 1. QUẢN LÝ CHỨC DANH ---
                with st.expander("📂 Quản lý danh mục Chức danh"):
                    col_a, col_b = st.columns([3, 1], vertical_alignment="bottom")
                    
                    with col_a:
                        new_cd_input = st.text_input("Nhập chức danh mới:", key="new_cd_add", placeholder="Vd: Thiết Kế")
                    
                    with col_b:
                        if st.button("➕ Thêm", use_container_width=True, type="secondary"):
                            if new_cd_input:
                                clean_name = new_cd_input.strip()
                                # Khởi tạo list nếu chưa có trong session
                                if "list_chuc_danh" not in st.session_state:
                                    st.session_state["list_chuc_danh"] = ["KTV Lắp đặt", "Giao nhận", "Quản lý", "Văn phòng"]
                                    
                                if clean_name not in st.session_state["list_chuc_danh"]:
                                    st.session_state["list_chuc_danh"].append(clean_name)
                                    st.success(f"Đã thêm '{clean_name}'")
                                    time.sleep(0.5); st.rerun()
                                else:
                                    st.warning("Chức danh này đã tồn tại!")
                            else:
                                st.error("Vui lòng nhập tên!")

                    st.write("**Danh sách hiện tại:**")
                    st.caption(", ".join(st.session_state.get("list_chuc_danh", ["KTV Lắp đặt", "Giao nhận", "Quản lý", "Văn phòng"])))

                # --- 2. TẠO TÀI KHOẢN MỚI ---
                with st.expander("➕ Tạo tài khoản nhân sự mới", expanded=False):
                    with st.form("add_user_full_fixed", clear_on_submit=True): 
                        c1, c2, c3 = st.columns(3)
                        n_u = c1.text_input("Username* (Viết liền không dấu)").lower().strip()
                        n_p = c2.text_input("Mật khẩu*", type="password")
                        n_r = c3.selectbox("Quyền", ["User", "Manager", "Admin", "System Admin"])
                        n_ten = st.text_input("Họ và tên nhân viên*")
                        
                        c4, c5 = st.columns(2)
                        # Lấy danh sách chức danh an toàn từ session
                        available_cd = st.session_state.get("list_chuc_danh", ["KTV Lắp đặt", "Giao nhận", "Quản lý", "Văn phòng"])
                        n_cd = c4.selectbox("Chức danh", available_cd)
                        n_phone = c5.text_input("Số điện thoại")
                        
                        submit_create = st.form_submit_button("🚀 TẠO TÀI KHOẢN", use_container_width=True)
                        
                        if submit_create:
                            if not n_u or not n_p or not n_ten:
                                st.error("❌ Thiếu thông tin bắt buộc!")
                            else:
                                try:
                                    # Sử dụng get_conn() để đảm bảo đồng bộ với hệ thống Cookie
                                    with get_conn() as conn:
                                        # 1. Kiểm tra tài khoản đã tồn tại chưa
                                        check = pd.read_sql("SELECT username FROM quan_tri_vien WHERE username = ?", 
                                                        conn, params=(n_u,))
                                        
                                        if not check.empty:
                                            st.error(f"❌ Tài khoản `{n_u}` đã tồn tại trên hệ thống!")
                                        else:
                                            # 2. Thực hiện thêm tài khoản mới
                                            cur = conn.cursor()
                                            cur.execute("""
                                                INSERT INTO quan_tri_vien (username, password, role, ho_ten, chuc_danh, so_dien_thoai) 
                                                VALUES (?, ?, ?, ?, ?, ?)
                                            """, (n_u, hash_password(n_p), n_r, n_ten.strip().title(), n_cd, n_phone))
                                            conn.commit()
                                            
                                            st.success(f"✅ Đã tạo thành công tài khoản cho {n_ten}!")
                                            time.sleep(1); st.rerun()
                                except Exception as e: 
                                    st.error(f"Lỗi cơ sở dữ liệu: {e}")

                # --- 3. XÓA TÀI KHOẢN (BẢO VỆ COOKIE SESSION) ---
                with st.expander("🗑️ Quản lý xóa tài khoản"):
                    st.warning("⚠️ **Cảnh báo:** Xóa tài khoản sẽ gỡ bỏ hoàn toàn quyền truy cập vào hệ thống.")
                    
                    with get_conn() as conn:
                        # KHÔNG cho phép tự xóa chính mình (đang cầm Cookie login)
                        df_to_del = pd.read_sql("SELECT username, ho_ten, chuc_danh, role FROM quan_tri_vien WHERE username != ?", 
                                            conn, params=(current_user,))
                        # Đếm số lượng System Admin còn lại
                        count_sysadmin = pd.read_sql("SELECT COUNT(*) as total FROM quan_tri_vien WHERE role = 'System Admin'", 
                                                    conn).iloc[0]['total']
                    
                    if df_to_del.empty:
                        st.info("📭 Không có tài khoản nào khác để xóa.")
                    else:
                        c1, c2 = st.columns([1, 1])
                        with c1:
                            df_to_del['display'] = df_to_del['ho_ten'] + " (" + df_to_del['username'] + ")"
                            u_del_display = st.selectbox("🎯 Chọn tài khoản cần loại bỏ:", 
                                                    options=df_to_del['display'].tolist(),
                                                    key="sb_delete_user")
                            u_selected = df_to_del[df_to_del['display'] == u_del_display].iloc[0]
                        with c2:
                            st.markdown("##### 📋 Thông tin đối soát")
                            st.info(f"**Username:** `{u_selected['username']}`  \n**Quyền hạn:** `{u_selected['role']}`")

                        st.divider()
                        confirm_del = st.checkbox(f"Tôi xác nhận muốn xóa vĩnh viễn tài khoản: **{u_selected['username']}**", key="chk_del")
                        
                        if st.button("🔥 THỰC HIỆN XÓA", type="primary", disabled=not confirm_del, use_container_width=True):
                            # Cơ chế bảo vệ: Không để hệ thống mồ côi (luôn phải có ít nhất 1 System Admin)
                            if u_selected['role'] == 'System Admin' and count_sysadmin <= 1:
                                st.error("❌ **Lỗi bảo mật:** Không thể xóa System Admin cuối cùng của hệ thống!")
                            else:
                                try:
                                    with get_conn() as conn:
                                        conn.execute("DELETE FROM quan_tri_vien WHERE username=?", (u_selected['username'],))
                                        conn.commit()
                                    st.success(f"💥 Đã xóa thành công tài khoản: {u_selected['username']}!")
                                    time.sleep(1); st.rerun()
                                except Exception as e: 
                                    st.error(f"Lỗi khi thực hiện xóa: {e}")
        # --- 4. BẢO TRÌ HỆ THỐNG ---
                st.subheader("🔑 Bảo trì hệ thống")           
                with st.expander("💾 Sao lưu và Phục hồi Hệ thống"):
                    st.info("💡 **Lưu ý:** Việc phục hồi sẽ ghi đè hoàn toàn dữ liệu hiện tại.")
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("##### 📥 Xuất dữ liệu")
                        if os.path.exists(DB_PATH):
                            with open(DB_PATH, "rb") as f:
                                st.download_button("Tải bản sao lưu (.db)", data=f, file_name=f"backup_{datetime.now().strftime('%d%m%Y')}.db", use_container_width=True)
                    with c2:
                        st.markdown("##### 📤 Phục hồi dữ liệu")
                        if "restore_key" not in st.session_state: st.session_state["restore_key"] = 1000
                        uploaded_db = st.file_uploader("Chọn tệp backup", type=["db"], key=f"up_{st.session_state['restore_key']}")
                        if uploaded_db and st.button("🔄 Xác nhận Phục hồi", use_container_width=True):
                            with open(DB_PATH, "wb") as f: f.write(uploaded_db.getbuffer())
                            st.session_state["restore_key"] += 1 
                            st.success("✅ Thành công!"); time.sleep(2); st.rerun()

                # --- 5. RESET DATABASE ---
                with st.expander("🔥 Dọn dẹp dữ liệu"):
                    confirm_reset = st.checkbox("Tôi muốn xóa toàn bộ dữ liệu nghiệp vụ.")
                    if st.button("🗑️ RESET DATABASE", type="primary", disabled=not confirm_reset, use_container_width=True):
                        try:
                            with sqlite3.connect(DB_PATH) as conn:
                                conn.execute("DELETE FROM cham_cong") 
                                conn.execute("DELETE FROM cham_cong_di_lam")
                                #---.execute("DELETE FROM quan_tri_vien WHERE role NOT IN ('System Admin')")
                            st.success("💥 Đã dọn dẹp!"); time.sleep(1); st.rerun()
                        except Exception as e: st.error(f"Lỗi: {e}") 

            elif tab_name == "🔐 Đổi mật khẩu":
                st.subheader("Thay đổi mật khẩu")
                st.info("💡 Lưu ý: Sau khi đổi mật khẩu thành công, bạn sẽ cần đăng nhập lại.")
            
                # Lấy username an toàn từ session (được nạp từ Cookie)
                current_user = st.session_state.get("username", "")

                with st.form("change_pass_form_fixed"):
                    p_old = st.text_input("Mật khẩu hiện tại", type="password", help="Nhập mật khẩu bạn đang sử dụng")
                    p_new = st.text_input("Mật khẩu mới", type="password", help="Tối thiểu 4 ký tự")
                    p_conf = st.text_input("Xác nhận mật khẩu mới", type="password")
                    
                    submit_change = st.form_submit_button("💾 CẬP NHẬT MẬT KHẨU", use_container_width=True, type="primary")
                    
                    if submit_change:
                        if not p_old or not p_new:
                            st.error("❌ Vui lòng nhập đầy đủ thông tin")
                        elif p_new != p_conf:
                            st.error("❌ Mật khẩu xác nhận không khớp")
                        elif len(p_new) < 4:
                            st.error("❌ Mật khẩu mới quá ngắn (tối thiểu 4 ký tự)")
                        elif p_old == p_new:
                            st.warning("⚠️ Mật khẩu mới không được trùng với mật khẩu cũ")
                        else:
                            try:
                                # Sử dụng get_conn() đồng bộ
                                with get_conn() as conn:
                                    # Kiểm tra mật khẩu cũ
                                    res = conn.execute("SELECT password FROM quan_tri_vien WHERE username=?", (current_user,)).fetchone()
                                    
                                    if res and res[0] == hash_password(p_old):
                                        # Cập nhật mật khẩu mới
                                        conn.execute("UPDATE quan_tri_vien SET password=? WHERE username=?", 
                                                    (hash_password(p_new), current_user))
                                        conn.commit()
                                        
                                        st.success("✅ Đổi mật khẩu thành công!")
                                        st.balloons()
                                        
                                        # XỬ LÝ COOKIE & SESSION KHI ĐỔI PASS:
                                        # 1. Xóa trạng thái đăng nhập trong Session
                                        st.session_state["authenticated"] = False
                                        
                                        # 2. Quan trọng: Nếu bạn có dùng trình quản lý Cookie (như extra-streamlit-components), 
                                        # bạn nên xóa cookie 'remember_token' hoặc 'password' tại đây.
                                        # Ví dụ: cookie_manager.delete("remember_token")
                                        
                                        time.sleep(2)
                                        # 3. Reload app để quay về màn hình Login
                                        st.rerun()
                                    else:
                                        st.error("❌ Mật khẩu hiện tại không chính xác")
                            except Exception as e:
                                st.error(f"❌ Lỗi hệ thống: {e}")
