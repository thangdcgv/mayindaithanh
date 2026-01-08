import streamlit as st
from supabase import create_client, Client
import pandas as pd
from datetime import datetime, date, timedelta
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

# ==============================================================================
# 2. CÁC HÀM BỔ TRỢ VÀ DATABASE
# ==============================================================================
@st.cache_resource
@st.cache_resource
def get_supabase() -> Client:
    return create_client(
        st.secrets["SUPABASE_URL"],
        st.secrets["SUPABASE_KEY"]
    )
supabase = get_supabase()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
def register_user(username, password):
    supabase.table("users").insert({
        "username": username,
        "password": hash_password(password)
    }).execute()

# ==============================================================================
# 3. QUẢN LÝ ĐĂNG NHẬP & COOKIES
# ==============================================================================
cookies = EncryptedCookieManager(
    prefix="daithanh/",
    password=st.secrets["COOKIE_PASSWORD"]
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
            submit = st.form_submit_button("ĐĂNG NHẬP", use_container_width=True)

            if submit:
                if not u_in or not p_in:
                    st.warning("Vui lòng nhập đầy đủ tài khoản và mật khẩu")
                    return

                res = check_login_supabase(u_in, p_in)

                if res:
                    st.session_state.update({
                        "authenticated": True,
                        "role": res.get("role"),
                        "username": res.get("username"),
                        "chuc_danh": res.get("chuc_danh"),
                        "ho_ten": res.get("ho_ten")
                    })

                    if remember_me:
                        cookies.set(
                            "saved_user",
                            res.get("username"),
                            expires_at=datetime.now() + timedelta(days=30)
                        )
                        cookies.save()

                    st.success(f"✅ Chào mừng {res.get('ho_ten')}")
                    st.rerun()
                else:
                    st.error("❌ Đăng nhập thất bại")


def logout():
    for k in ["authenticated", "role", "username", "chuc_danh", "ho_ten"]:
        st.session_state.pop(k, None)

    if cookies.get("saved_user"):
        cookies.delete("saved_user")
        cookies.save()

    st.rerun()

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
# 2. BÁO CÁO CHẤM CÔNG (SỬ DỤNG SUPABASE - FIX CACHE DỮ LIỆU)
# ==============================================================================

def get_attendance_report(target_username, filter_month=None):
    """Hàm tính toán công - Truy vấn trực tiếp từ Supabase thay vì SQLite"""
    try:
        # 1. Khởi tạo truy vấn từ bảng trên Supabase
        query = supabase.table("cham_cong_di_lam") \
            .select("thoi_gian, trang_thai_lam, ghi_chu") \
            .eq("username", target_username)
        
        # 2. Lọc theo tháng nếu có (Sử dụng lọc chuỗi tương đương LIKE trong SQL)
        if filter_month:
            # Giả định định dạng thoi_gian là YYYY-MM-DD...
            query = query.gte("thoi_gian", f"{filter_month}-01") \
                         .lte("thoi_gian", f"{filter_month}-31")
        
        # 3. Thực thi truy vấn và sắp xếp
        response = query.order("thoi_gian", desc=True).execute()
        
        # Chuyển đổi dữ liệu trả về thành DataFrame
        df = pd.DataFrame(response.data)
        
    except Exception as e:
        st.error(f"Lỗi khi truy vấn báo cáo từ Supabase: {e}")
        return pd.DataFrame()

    if df.empty: 
        return pd.DataFrame()
    
    # --- Logic tính toán giữ nguyên theo code của bạn ---
    df['thoi_gian'] = pd.to_datetime(df['thoi_gian'])
    df['ngay'] = df['thoi_gian'].dt.date
    summary = []
    
    for date_val, group in df.groupby('ngay', sort=False):
        # 1. Xử lý nghỉ
        if any(group['trang_thai_lam'].str.contains("Nghỉ", na=False)):
            status_row = group[group['trang_thai_lam'].str.contains("Nghỉ", na=False)].iloc[0]
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
            "Ngày": date_val.strftime("%d/%m/%Y"), 
            "Giờ vào làm": v_time.strftime("%H:%M:%S") if pd.notnull(v_time) else "--:--",
            "Kết thúc làm": r_time.strftime("%H:%M:%S") if pd.notnull(r_time) else "--:--",
            "Tổng giờ": f"{tong_gio}h",
            "Loại công": loai_cong,
            "Ghi chú": final_note
        })
        
    res = pd.DataFrame(summary)
    if not res.empty: 
        res.insert(0, 'STT', range(1, len(res) + 1))
    return res

# CẢI TIẾN QUAN TRỌNG: Cache tách biệt theo UserID
@st.cache_data(ttl=300)
def get_attendance_report_cached(current_user, month=None):
    """Sử dụng current_user làm key để cache không bị trộn lẫn giữa các tài khoản"""
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
if not st.session_state.get("authenticated", False):
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
                        cookies.set(
                        "saved_user",
                        res.get("username"),
                        expires_at=datetime.now() + timedelta(days=30)
                    )
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
            
            # Sử dụng múi giờ Việt Nam
            now = datetime.now()
            today_str = now.strftime("%Y-%m-%d")
            current_month = now.strftime("%Y-%m") 
            display_month = now.strftime("%m/%Y")

            try:
                # 1. Kiểm tra trạng thái hôm nay trên Supabase thay cho SQLite
                # Sử dụng gte (lớn hơn hoặc bằng) và lt (nhỏ hơn) để lọc chính xác ngày hôm nay
                response = supabase.table("cham_cong_di_lam") \
                    .select("trang_thai_lam") \
                    .eq("username", user) \
                    .gte("thoi_gian", f"{today_str} 00:00:00") \
                    .lte("thoi_gian", f"{today_str} 23:59:59") \
                    .execute()
                
                df_today = pd.DataFrame(response.data)
                
                has_in = False
                has_out = False
                has_off = False

                if not df_today.empty:
                    has_in = any(df_today['trang_thai_lam'] == "Vào làm")
                    has_out = any(df_today['trang_thai_lam'] == "Ra về")
                    has_off = any(df_today['trang_thai_lam'].str.contains("Nghỉ", na=False))

                c_left, c_right = st.columns([1, 2.2])
                with c_left:
                    col_in, col_out = st.columns(2)

                    # --- NÚT VÀO LÀM ---
                    if col_in.button("📍 VÀO LÀM", use_container_width=True, type="primary", 
                                    disabled=(has_in or has_off), key="btn_in"):                       
                        try:
                            data_in = {
                                "username": user,
                                "thoi_gian": now.strftime("%Y-%m-%d %H:%M:%S"),
                                "trang_thai_lam": "Vào làm",
                                "nguoi_thao_tac": user
                            }
                            supabase.table("cham_cong_di_lam").insert(data_in).execute()
                            st.toast("✅ Đã ghi nhận giờ vào")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Lỗi: {e}")

                    # --- NÚT RA VỀ ---
                    if col_out.button("🏁 RA VỀ", use_container_width=True, 
                                    disabled=(not has_in or has_out or has_off), key="btn_out"):
                        try:
                            data_out = {
                                "username": user,
                                "thoi_gian": now.strftime("%Y-%m-%d %H:%M:%S"),
                                "trang_thai_lam": "Ra về",
                                "nguoi_thao_tac": user
                            }
                            supabase.table("cham_cong_di_lam").insert(data_out).execute()
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
                                    try:
                                        data_off = {
                                            "username": user,
                                            "thoi_gian": now.strftime("%Y-%m-%d %H:%M:%S"),
                                            "trang_thai_lam": f"Nghỉ {type_off}",
                                            "ghi_chu": reason_off,
                                            "nguoi_thao_tac": user
                                        }
                                        supabase.table("cham_cong_di_lam").insert(data_off).execute()
                                        st.success("Đã gửi đăng ký nghỉ")
                                        time.sleep(1)
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"Lỗi: {e}")

                    show_detail = st.button("📊 Chi tiết chấm công cá nhân", use_container_width=True)

                with c_right:
                    # Truyền USERNAME từ session vào hàm cache (hàm này bạn đã chuyển sang Supabase ở bước trước)
                    df_quick = get_attendance_report_cached(user)
                    if not df_quick.empty:
                        st.caption("Ngày làm việc gần nhất")
                        st.dataframe(df_quick.head(3), use_container_width=True, hide_index=True)

                if show_detail:
                    @st.dialog("Bảng chi tiết chấm công cá nhân", width="large")
                    def show_month_detail_dialog():
                        st.subheader(f"📅 Tháng {display_month}")
                        # Dùng hàm report lấy theo user từ session (Đã chuyển sang dùng Supabase)
                        df_detail = get_attendance_report(user, current_month)
                        
                        if not df_detail.empty:
                            st.dataframe(df_detail, use_container_width=True, hide_index=True)
                        else: 
                            st.write("Chưa có dữ liệu trong tháng này.")
                    show_month_detail_dialog()
                    
            except Exception as e:
                st.error(f"Lỗi hệ thống khi tải dữ liệu chấm công: {e}")

        # --- TAB 2: QUẢN LÝ & SỬA CÔNG (ADMIN) ---
    if role in ["Admin", "System Admin"]:
        with tabs[1]:
            st.markdown("#### 🛠️ Điều chỉnh công nhân viên")
            # Lấy thông tin Admin hiện tại từ session
            current_admin = st.session_state.get("username")
            
            # 1. Lấy danh sách nhân viên từ Supabase
            try:
                query_nv = supabase.table("quan_tri_vien").select("username, ho_ten").neq("role", "System Admin")
                
                # Admin không được tự sửa công của chính mình
                if role == "Admin": 
                    query_nv = query_nv.neq("username", current_admin)
                
                res_nv = query_nv.execute()
                list_nv = pd.DataFrame(res_nv.data)
            except Exception as e:
                st.error(f"Lỗi tải danh sách NV: {e}")
                list_nv = pd.DataFrame()

            if not list_nv.empty:
                # Tạo label hiển thị
                list_nv['label'] = list_nv['ho_ten'] + " (" + list_nv['username'] + ")"
                label_to_user = dict(zip(list_nv['label'], list_nv['username']))
                
                cl1, cl2 = st.columns(2)
                sel_label = cl1.selectbox("👤 Chọn nhân viên", options=list_nv['label'].tolist(), key="mgr_sel_user")
                sel_u = label_to_user.get(sel_label)
                sel_d = cl2.date_input("📅 Ngày điều chỉnh", datetime.now(), key="mgr_sel_date")
                d_str = sel_d.strftime("%Y-%m-%d")

                # 2. Kiểm tra dữ liệu hiện có trên Supabase
                try:
                    res_check = supabase.table("cham_cong_di_lam") \
                        .select("thoi_gian, trang_thai_lam, nguoi_thao_tac") \
                        .eq("username", sel_u) \
                        .gte("thoi_gian", f"{d_str} 00:00:00") \
                        .lte("thoi_gian", f"{d_str} 23:59:59") \
                        .execute()
                    df_check = pd.DataFrame(res_check.data)
                except Exception as e:
                    st.error(f"Lỗi kiểm tra dữ liệu: {e}")
                    df_check = pd.DataFrame()

                c_info, c_action = st.columns([2, 1])
                if not df_check.empty:
                    c_info.caption(f"Dữ liệu hiện tại của {sel_u}")
                    c_info.dataframe(df_check, use_container_width=True, hide_index=True)
                    
                    if c_action.button("🔥 Reset ngày này", use_container_width=True, help="Xóa toàn bộ công ngày này của NV"):
                        try:
                            supabase.table("cham_cong_di_lam") \
                                .delete() \
                                .eq("username", sel_u) \
                                .gte("thoi_gian", f"{d_str} 00:00:00") \
                                .lte("thoi_gian", f"{d_str} 23:59:59") \
                                .execute()
                            st.toast(f"✅ Đã xóa dữ liệu ngày {d_str}")
                            time.sleep(0.5)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Lỗi khi xóa: {e}")
                else: 
                    c_info.info(f"ℹ️ Ngày {d_str} không có dữ liệu.")

                st.divider()
                st.markdown("##### 📝 Gán công nhanh")
                st.caption("Lưu ý: Thao tác này sẽ xóa dữ liệu cũ của ngày được chọn trước khi gán mới.")
                b1, b2, b3 = st.columns([1, 1, 1])
                
                # 3. Logic Gán công nhanh (Sử dụng bulk insert của Supabase)
                if b1.button("✅ Gán 1 Ngày công", use_container_width=True, type="primary"):
                    try:
                        # Xóa cũ
                        supabase.table("cham_cong_di_lam").delete().eq("username", sel_u) \
                            .gte("thoi_gian", f"{d_str} 00:00:00").lte("thoi_gian", f"{d_str} 23:59:59").execute()
                        
                        # Gán mới
                        new_rows = [
                            {"username": sel_u, "thoi_gian": f"{d_str} 08:00:00", "trang_thai_lam": "Vào làm", "nguoi_thao_tac": current_admin},
                            {"username": sel_u, "thoi_gian": f"{d_str} 17:30:00", "trang_thai_lam": "Ra về", "nguoi_thao_tac": current_admin}
                        ]
                        supabase.table("cham_cong_di_lam").insert(new_rows).execute()
                        
                        st.success(f"🎯 Đã gán 1 ngày công cho {sel_u}")
                        time.sleep(1)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Lỗi: {e}")
                
                if b2.button("🌗 Gán 1/2 Ngày công", use_container_width=True):
                    try:
                        # Xóa cũ
                        supabase.table("cham_cong_di_lam").delete().eq("username", sel_u) \
                            .gte("thoi_gian", f"{d_str} 00:00:00").lte("thoi_gian", f"{d_str} 23:59:59").execute()
                        
                        # Gán mới
                        new_rows = [
                            {"username": sel_u, "thoi_gian": f"{d_str} 08:00:00", "trang_thai_lam": "Vào làm", "nguoi_thao_tac": current_admin},
                            {"username": sel_u, "thoi_gian": f"{d_str} 12:00:00", "trang_thai_lam": "Ra về", "nguoi_thao_tac": current_admin}
                        ]
                        supabase.table("cham_cong_di_lam").insert(new_rows).execute()
                        
                        st.success(f"🎯 Đã gán 1/2 ngày công cho {sel_u}")
                        time.sleep(1)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Lỗi: {e}")

        # --- TAB 3: BÁO CÁO TỔNG HỢP (ADMIN) ---
    if role in ["Admin", "System Admin"]:
        with tabs[2]:
            st.markdown("#### 📊 Báo cáo chấm công nhân viên")
            col_f1, col_f2 = st.columns(2)
            
            # 1. Lấy danh sách nhân viên từ Supabase thay vì SQLite
            try:
                response_users = supabase.table("quan_tri_vien") \
                    .select("username, ho_ten") \
                    .neq("role", "System Admin") \
                    .execute()
                df_users = pd.DataFrame(response_users.data)
            except Exception as e:
                st.error(f"Lỗi truy vấn danh sách nhân viên: {e}")
                df_users = pd.DataFrame()
            
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
                
                # Định dạng chuỗi tìm kiếm khớp với logic hàm báo cáo (YYYY-MM)
                month_str = f"{sel_y}-{sel_m:02d}"
                
                # Gọi hàm báo cáo (Hàm này bạn đã sửa sang dùng Supabase ở phần trước)
                df_report = get_attendance_report(target_user_rpt, month_str)
                
                if not df_report.empty:
                    # Tính toán tổng hợp
                    # Dùng .str.contains an toàn với dữ liệu trả về từ DataFrame
                    total_full = len(df_report[df_report['Loại công'].str.contains("Ngày", na=False)])
                    total_half = len(df_report[df_report['Loại công'].str.contains("1/2", na=False)])
                    
                    # Hiển thị số liệu tổng quát
                    m1, m2 = st.columns(2)
                    m1.metric(f"Tổng công tháng {sel_m}/{sel_y}", f"{total_full + (total_half * 0.5)} công")
                    m2.caption(f"Nhân viên: {selected_label}")
                    
                    # Hiển thị bảng dữ liệu
                    st.dataframe(df_report, use_container_width=True, hide_index=True)
                    
                    # --- XỬ LÝ XUẤT EXCEL (Giữ nguyên cấu trúc logic) ---
                    output = io.BytesIO()
                    with pd.ExcelWriter(output, engine='xlsxwriter') as writer: 
                        df_report.to_excel(writer, index=False, sheet_name='BaoCao')
                        
                        # Cấu hình format file Excel
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

    # 2. HÀM CẬP NHẬT TRẠNG THÁI (SỬ DỤNG SUPABASE)
    def quick_update_status(record_id, new_status, reason=""):
        try:
            # Bổ sung ghi chú ai là người duyệt vào nội dung ghi chú
            # user_hien_tai lấy từ st.session_state.get('username')
            user_hien_tai = st.session_state.get('username', 'Unknown')
            full_reason = f"[{user_hien_tai}] {reason}" if reason else f"Duyệt bởi: {user_hien_tai}"
            
            # Cập nhật trực tiếp lên Supabase
            supabase.table("cham_cong") \
                .update({
                    "trang_thai": new_status,
                    "ghi_chu_duyet": full_reason
                }) \
                .eq("id", record_id) \
                .execute()
                
            return True
        except Exception as e:
            st.error(f"Lỗi cập nhật trên Cloud: {e}")
            return False

    # --- TAB 1: GỬI ĐƠN LẮP ĐẶT (TỐI ƯU CHO COOKIE) ---
    with tabs[0]:
        # Lấy trực tiếp từ Session State đã nạp bởi Cookie Manager
        user = st.session_state.get("username")
        role = st.session_state.get("role")
        ho_ten_sender = st.session_state.get("ho_ten", user)

        # --- PHẦN PHÂN QUYỀN CHỌN NHÂN VIÊN (SUPABASE) ---
        target_user = user # Mặc định là chính mình
        is_management = role in ["Manager", "Admin", "System Admin"]
        
        if is_management:
            try:
                # Truy vấn danh sách nhân viên từ Supabase
                if role in ["System Admin", "Admin"]:
                    response_nv = supabase.table("quan_tri_vien") \
                        .select("username, ho_ten") \
                        .in_("role", ["Manager", "User"]) \
                        .execute()
                else: # Manager
                    response_nv = supabase.table("quan_tri_vien") \
                        .select("username, ho_ten") \
                        .eq("role", "User") \
                        .execute()
                
                df_nv_list = pd.DataFrame(response_nv.data)
            except Exception as e:
                st.error(f"Lỗi tải danh sách nhân viên: {e}")
                df_nv_list = pd.DataFrame()
            
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
                    
                    # --- XỬ LÝ ẢNH & LƯU SUPABASE ---
                    try:
                        # Chuyển ảnh thành Base64 (Chuỗi văn bản) để lưu vào cột text/longtext của Supabase
                        import base64
                        img_bytes = uploaded_file.read()
                        base64_image = base64.b64encode(img_bytes).decode('utf-8')

                        data_insert = {
                            "username": target_user,
                            "ten": ho_ten_sender,
                            "thoi_gian": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "so_hoa_don": final_hd,
                            "noi_dung": noi_dung_final,
                            "quang_duong": int(quang_duong),
                            "combo": int(tong_combo),
                            "thanh_tien": float(tong_tien),
                            "hinh_anh": base64_image, # Lưu dạng chuỗi Base64
                            "trang_thai": 'Chờ duyệt'
                        }

                        # Thực thi chèn dữ liệu vào Supabase
                        response = supabase.table("cham_cong").insert(data_insert).execute()
                        
                        if response.data:
                            st.success(f"✅ Gửi đơn thành công cho nhân viên: {ho_ten_sender}")
                            st.session_state["f_up_key"] += 1
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("❌ Không thể lưu dữ liệu vào Cloud.")

                    except Exception as e:
                        # Xử lý lỗi trùng số hóa đơn (Unique Constraint trong Supabase)
                        err_msg = str(e)
                        if "duplicate key" in err_msg or "already exists" in err_msg:
                            st.error(f"❌ Số hóa đơn **{final_hd}** đã tồn tại trên hệ thống!")
                        else:
                            st.error(f"❌ Lỗi hệ thống: {e}")
    # --- TAB 2: DUYỆT ĐƠN (CHỈ ADMIN/SYSTEM ADMIN/MANAGER) ---
    if role in ["Admin", "System Admin", "Manager"]:
        with tabs[1]:
            st.markdown("#### 📋 Danh sách đơn chờ duyệt")
            
            try:
                # 1. Truy vấn đơn hàng 'Chờ duyệt' và JOIN lấy ho_ten từ bảng quan_tri_vien
                response = supabase.table("cham_cong") \
                    .select("*, quan_tri_vien(ho_ten)") \
                    .eq("trang_thai", "Chờ duyệt") \
                    .order("thoi_gian", ascending=False) \
                    .execute()
                
                df_p = pd.DataFrame(response.data)
                
                # Xử lý lấy ho_ten từ kết quả lồng nhau của Supabase
                if not df_p.empty:
                    df_p['ho_ten_nv'] = df_p['quan_tri_vien'].apply(lambda x: x['ho_ten'] if x else "N/A")
            except Exception as e:
                st.error(f"❌ Lỗi kết nối dữ liệu Cloud: {e}")
                df_p = pd.DataFrame()

            if df_p.empty:
                st.info("📭 Hiện tại không có đơn nào đang chờ duyệt.")
            else:
                # Duyệt qua từng đơn hàng để hiển thị dạng Expander
                for _, r in df_p.iterrows():
                    # Tiêu đề expander hiển thị các thông tin cơ bản
                    expander_title = f"📦 HĐ: {r['so_hoa_don']} — 👤 {r['ho_ten_nv']} — 🕒 {r['thoi_gian']}"
                    
                    with st.expander(expander_title):
                        cl, cr = st.columns([1.5, 1])
                        
                        with cl:
                            # Thông tin chi tiết đơn hàng
                            st.write(f"**📍 Địa chỉ/Ghi chú:** {r['noi_dung']}")
                            st.write(f"🛣️ Quãng đường: **{r['quang_duong']} km** | 📦 Tổng thiết bị: **{r['combo']} máy**")
                            st.markdown(f"#### 💰 Tổng tiền: `{r['thanh_tien']:,.0f}` VNĐ")
                            
                            st.write("---")
                            
                            # --- PHÂN QUYỀN THAO TÁC NÚT BẤM ---
                            # Chỉ Admin/System Admin mới có quyền thay đổi trạng thái đơn
                            if role in ["Admin", "System Admin"]:
                                b1, b2 = st.columns(2)
                                
                                # Nút phê duyệt nhanh
                                if b1.button("✅ DUYỆT ĐƠN", key=f"ap_{r['id']}", use_container_width=True, type="primary"):
                                    if quick_update_status(r["id"], "Đã duyệt", "Thông tin chính xác"):
                                        st.toast(f"✅ Đã duyệt đơn {r['so_hoa_don']}")
                                        time.sleep(0.5)
                                        st.rerun()
                                            
                                # Nút từ chối đơn với lý do cụ thể
                                with b2:
                                    with st.popover("❌ TỪ CHỐI", use_container_width=True):
                                        reason = st.text_area("Nhập lý do từ chối đơn:", key=f"txt_{r['id']}", placeholder="VD: Ảnh mờ, sai số hóa đơn...")
                                        if st.button("Xác nhận từ chối", key=f"conf_{r['id']}", use_container_width=True):
                                            if not reason.strip():
                                                st.error("⚠️ Bạn phải nhập lý do từ chối!")
                                            else:
                                                if quick_update_status(r["id"], "Từ chối", reason.strip()):
                                                    st.toast("🔴 Đã từ chối đơn hàng")
                                                    time.sleep(0.5)
                                                    st.rerun()
                            else:
                                # Nếu là Manager (Chỉ xem, không có quyền duyệt tiền)
                                st.info("ℹ️ Bạn chỉ có quyền giám sát. Quyền Duyệt/Từ chối thuộc về Kế toán.")
                                    
                        with cr:
                            # --- XỬ LÝ HIỂN THỊ ẢNH ĐỐI SOÁT (BASE64) ---
                            if r.get("hinh_anh"):
                                try:
                                    # Chuẩn hóa chuỗi Base64 nếu thiếu tiền tố để hiển thị được trong Streamlit
                                    img_base64 = r["hinh_anh"]
                                    if not img_base64.startswith("data:image"):
                                        img_base64 = f"data:image/jpeg;base64,{img_base64}"
                                    
                                    st.image(img_base64, caption=f"Ảnh hóa đơn {r['so_hoa_don']}", use_container_width=True)
                                except Exception as e:
                                    st.error(f"⚠️ Lỗi hiển thị ảnh: {e}")
                            else:
                                st.warning("⚠️ Đơn này không đính kèm ảnh hóa đơn.")     

    # --- TAB 3: BÁO CÁO LẮP ĐẶT (TỔI ƯU CHO COOKIE & HIỆU SUẤT) ---
    with tabs[-1]:
        # Lấy thông tin từ Session (đã nạp bởi Cookie Manager)
        user_hien_tai = st.session_state.get("username")
        role = st.session_state.get("role")
        
        try:
            # 1. Truy vấn dữ liệu từ Supabase thay vì SQL query thuần
            # Thực hiện JOIN để lấy ho_ten từ bảng quan_tri_vien
            response = supabase.table("cham_cong") \
                .select("*, quan_tri_vien(ho_ten)") \
                .execute()
            
            # Chuyển đổi dữ liệu sang DataFrame và xử lý tên cột khớp với logic cũ
            df_all = pd.DataFrame(response.data)
            if not df_all.empty:
                df_all['Tên'] = df_all['quan_tri_vien'].apply(lambda x: x['ho_ten'] if x else "N/A")
                df_all = df_all.rename(columns={
                    'thoi_gian': 'Thời Gian',
                    'so_hoa_don': 'Số HĐ',
                    'noi_dung': 'Địa chỉ',
                    'quang_duong': 'Km',
                    'thanh_tien': 'Thành tiền',
                    'trang_thai': 'Trạng thái',
                    'ghi_chu_duyet': 'Lý do'
                })
        except Exception as e:
            st.error(f"Lỗi tải dữ liệu: {e}")
            df_all = pd.DataFrame()
            df_raw = pd.DataFrame(response.data)

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
                                                    # Sử dụng phương thức delete() của Supabase với bộ lọc .in_()
                                                    # selected_ids là danh sách các ID bạn đã lấy từ dataframe editor
                                                    supabase.table("cham_cong") \
                                                        .delete() \
                                                        .in_("id", selected_ids) \
                                                        .execute()
                                                    
                                                    st.success(f"✅ Đã xóa thành công {len(selected_ids)} dữ liệu!")
                                                    time.sleep(0.5)
                                                    st.rerun()
                                                except Exception as e:
                                                    # Xử lý lỗi kết nối hoặc quyền hạn từ Supabase
                                                    st.error(f"❌ Lỗi khi xóa trên Cloud: {e}")
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

                                # --- TRUY VẤN LẤY ẢNH CŨ TỪ SUPABASE ---
                                # Lưu ý: Tên biến đổi thành Base64 vì Supabase lưu chuỗi văn bản thay vì Blob
                                old_img_base64 = None
                                try:
                                    response_img = supabase.table("cham_cong") \
                                        .select("hinh_anh") \
                                        .eq("id", row_id) \
                                        .execute()
                                    
                                    if response_img.data:
                                        old_img_base64 = response_img.data[0].get("hinh_anh")
                                except Exception as e:
                                    st.error(f"Lỗi khi lấy ảnh từ Cloud: {e}")

                                # --- NÚT XÓA ĐƠN (SỬ DỤNG SUPABASE) ---
                                if current_status == "Chờ duyệt":
                                    if st.button("🗑️ XOÁ ĐƠN NÀY", use_container_width=True, type="secondary"):
                                        try:
                                            # Xóa trực tiếp bằng phương thức của Supabase
                                            supabase.table("cham_cong") \
                                                .delete() \
                                                .eq("id", row_id) \
                                                .eq("username", user_login) \
                                                .eq("trang_thai", "Chờ duyệt") \
                                                .execute()
                                            
                                            st.success("✅ Đã xóa đơn thành công trên hệ thống Cloud!")
                                            time.sleep(0.5)
                                            st.rerun()
                                        except Exception as e:
                                            st.error(f"❌ Không thể xóa trên Cloud: {e}")
                                else:
                                    # Hiển thị lý do từ chối nếu có (lấy từ dữ liệu row_data nạp từ Supabase trước đó)
                                    ly_do_tu_choi = row_data.get('Lý do', 'Không có lý do cụ thể')
                                    st.warning(f"🔴 Đơn bị từ chối. Lý do: **{ly_do_tu_choi}**")

                                st.write("---")
        # --- FORM CẬP NHẬT (Ví dụ nằm trong một vòng lặp hoặc logic chọn đơn của bạn) ---
        # Giả sử row_id, old_img_blob, val_quang_duong, current_may_lon, current_may_nho, raw_address đã được xác định ở trên
        with st.form(key=f"edit_form_{row_id}", clear_on_submit=False):
            st.markdown(f"**📝 Hiệu chỉnh đơn: {sel_hd_edit}**")
            
            # Sử dụng tên biến đồng nhất: old_img_base64
        if old_img_base64:
            with st.popover("🖼️ Xem ảnh hóa đơn hiện tại", use_container_width=True):
                img_display = old_img_base64
                # Kiểm tra và thêm tiền tố nếu chưa có để hiển thị trên Streamlit
                if isinstance(img_display, str) and not img_display.startswith("data:image"):
                    img_display = f"data:image/jpeg;base64,{img_display}"
                st.image(img_display, use_container_width=True)

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
                # Logic tính toán (Giữ nguyên)
                if n_quang_duong <= 50:
                    n_don_gia_km = 30000 if n_quang_duong < 20 else 50000 if n_quang_duong <= 30 else 70000 if n_quang_duong <= 40 else 80000
                else:
                    n_don_gia_km = 80000 + (n_quang_duong - 50) * 5000
                
                n_tong_tien = (n_may_lon * 200000) + (n_may_nho * n_don_gia_km)
                n_tong_combo = n_may_lon + n_may_nho
                n_noi_dung_final = f"{n_noi_dung.title().strip()} | (Máy lớn: {n_may_lon}, Máy nhỏ: {n_may_nho})"
                
                try:
                    # 1. Xử lý ảnh (Chuyển về Base64 thuần không tiền tố để lưu trữ nhẹ hơn)
                    final_img_data = old_img_base64
                    if n_uploaded_file:
                        img_pil = Image.open(n_uploaded_file)
                        if img_pil.mode in ("RGBA", "P"): 
                            img_pil = img_pil.convert("RGB")
                        
                        img_byte_arr = io.BytesIO()
                        img_pil.save(img_byte_arr, format='JPEG', quality=70, optimize=True)
                        # Lưu Base64 thuần
                        final_img_data = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')

                    # 2. Cập nhật vào Supabase
                    thoi_gian_cap_nhat = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    update_payload = {
                        "so_hoa_don": n_hd_in.upper().strip(),
                        "noi_dung": n_noi_dung_final,
                        "quang_duong": int(n_quang_duong),
                        "combo": int(n_tong_combo),
                        "thanh_tien": float(n_tong_tien),
                        "hinh_anh": final_img_data,
                        "trang_thai": 'Chờ duyệt',
                        "thoi_gian": thoi_gian_cap_nhat,
                        "ghi_chu_duyet": ''
                    }

                    # Thêm eq("username", ...) để bảo mật dữ liệu cấp người dùng
                    supabase.table("cham_cong") \
                        .update(update_payload) \
                        .eq("id", row_id) \
                        .eq("username", user_hien_tai) \
                        .execute()
                    
                    st.success("✅ Đã cập nhật và gửi duyệt lại!")
                    time.sleep(0.5)
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"❌ Lỗi hệ thống: {e}")

        # --- DÀNH CHO ADMIN: ĐẢO NGƯỢC TRẠNG THÁI ---
        if role in ["Admin", "System Admin"]:
            st.divider()
            with st.expander("🔄 Quản lý trạng thái (Hủy duyệt đơn)", expanded=False):
                st.warning("⚠️ **Lưu ý:** Thao tác này đưa đơn về trạng thái 'Chờ duyệt'.")
                
                df_undo = df_all[df_all["Trạng thái"] == "Đã duyệt"].copy()
                
                if df_undo.empty:
                    st.info("ℹ️ Không có đơn nào 'Đã duyệt' để đảo ngược.")
                else:
                    sel_undo = st.selectbox("⏪ Chọn Số HĐ:", df_undo["Số HĐ"].tolist(), key="undo_select_box")
                    row_undo_data = df_undo[df_undo["Số HĐ"] == sel_undo].iloc[0]
                    row_id_undo = int(row_undo_data["id"])
                    
                    # Lấy ảnh trực tiếp từ Supabase (Lấy riêng cột hinh_anh)
                    img_base64_undo = None
                    try:
                        res_undo = supabase.table("cham_cong").select("hinh_anh").eq("id", row_id_undo).execute()
                        if res_undo.data:
                            img_base64_undo = res_undo.data[0].get("hinh_anh")
                    except Exception as e:
                        st.error(f"Lỗi ảnh: {e}")

                    if img_base64_undo:
                        with st.popover(f"🔍 Xem lại ảnh hóa đơn {sel_undo}", use_container_width=True):
                            # Chuẩn hóa Base64 để hiển thị
                            if not img_base64_undo.startswith("data:image"):
                                img_base64_undo = f"data:image/jpeg;base64,{img_base64_undo}"
                            st.image(img_base64_undo, use_container_width=True)
                    
                    reason_undo = st.text_input("📝 Lý do đưa về chờ duyệt:", key="reason_undo_input")
                    
                    if st.button("⏪ XÁC NHẬN ĐẢO NGƯỢC", use_container_width=True, type="primary"):
                        if not reason_undo:
                            st.error("❌ Vui lòng nhập lý do!")
                        else:
                            try:
                                admin_name = st.session_state.get("ho_ten", "Admin")
                                new_note = f"[{admin_name}] HỦY DUYỆT: {reason_undo}"
                                
                                supabase.table("cham_cong") \
                                    .update({"trang_thai": "Chờ duyệt", "ghi_chu_duyet": new_note}) \
                                    .eq("id", row_id_undo) \
                                    .execute()
                                
                                st.success("✅ Đã chuyển đơn về trạng thái Chờ duyệt!")
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
                try:
                    # 1. Lấy dữ liệu từ Supabase thay vì SQLite
                    response = supabase.table("quan_tri_vien").select("*").execute()
                    df_users = pd.DataFrame(response.data)
                except Exception as e:
                    st.error(f"Lỗi kết nối Cloud: {e}")
                    df_users = pd.DataFrame()

                if df_users.empty:
                    st.info("Chưa có dữ liệu nhân sự.")
                else:
                    # 2. XỬ LÝ HIỂN THỊ BẢNG (Giữ nguyên cấu trúc logic của bạn)
                    df_users_display = df_users.copy()
                    
                    # Tạo cột STT
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
                            "username": None, "password": None # Ẩn các cột nhạy cảm
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
                                        # 1. Chuẩn hóa dữ liệu trước khi lưu
                                        final_name = new_name.strip().title()
                                        final_addr = new_addr.strip()
                                        ngay_sinh_str = new_birth.strftime("%Y-%m-%d")

                                        # 2. Chuẩn bị dữ liệu cập nhật (Payload)
                                        update_data = {
                                            "ho_ten": final_name,
                                            "so_dien_thoai": new_phone,
                                            "dia_chi": final_addr,
                                            "ngay_sinh": ngay_sinh_str,
                                            "chuc_danh": new_cd,
                                            "role": new_role
                                        }

                                        # Nếu có nhập mật khẩu mới, mới đưa vào dữ liệu cập nhật
                                        if new_pass.strip():
                                            update_data["password"] = hash_password(new_pass)

                                        # 3. Thực hiện cập nhật lên Supabase Cloud
                                        supabase.table("quan_tri_vien") \
                                            .update(update_data) \
                                            .eq("username", target_u) \
                                            .execute()
                                        
                                        st.success(f"✅ Đã cập nhật thành công nhân sự: {final_name}")
                                        
                                        # Kiểm tra nếu admin đang tự sửa chính mình
                                        if target_u == st.session_state.get("username"):
                                            st.info("💡 Bạn vừa cập nhật thông tin cá nhân. Hãy tải lại trang để thấy thay đổi.")
                                            
                                        time.sleep(1)
                                        st.rerun()

                                    except Exception as e:
                                        st.error(f"❌ Lỗi hệ thống Cloud: {e}")
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
                                    # 1. Kiểm tra tài khoản đã tồn tại chưa trên Supabase
                                    check_response = supabase.table("quan_tri_vien") \
                                        .select("username") \
                                        .eq("username", n_u) \
                                        .execute()
                                    
                                    # Supabase trả về dữ liệu trong thuộc tính .data (dạng list)
                                    if check_response.data:
                                        st.error(f"❌ Tài khoản `{n_u}` đã tồn tại trên hệ thống Cloud!")
                                    else:
                                        # 2. Thực hiện thêm tài khoản mới (INSERT)
                                        new_user_data = {
                                            "username": n_u,
                                            "password": hash_password(n_p),
                                            "role": n_r,
                                            "ho_ten": n_ten.strip().title(),
                                            "chuc_danh": n_cd,
                                            "so_dien_thoai": n_phone
                                        }
                                        
                                        supabase.table("quan_tri_vien") \
                                            .insert(new_user_data) \
                                            .execute()
                                        
                                        st.success(f"✅ Đã tạo thành công tài khoản cho {n_ten} trên hệ thống Cloud!")
                                        time.sleep(1)
                                        st.rerun()

                                except Exception as e:
                                    # Xử lý các lỗi kết nối hoặc lỗi ràng buộc dữ liệu từ Supabase
                                    st.error(f"❌ Lỗi hệ thống Supabase: {e}")

                # --- 3. XÓA TÀI KHOẢN (BẢO VỆ COOKIE SESSION) ---
                with st.expander("🗑️ Quản lý xóa tài khoản"):
                    st.warning("⚠️ **Cảnh báo:** Xóa tài khoản sẽ gỡ bỏ hoàn toàn quyền truy cập vào hệ thống.")
                    
                    try:
                        # 1. Lấy danh sách tài khoản (trừ tài khoản hiện tại)
                        res_users = supabase.table("quan_tri_vien") \
                            .select("username, ho_ten, chuc_danh, role") \
                            .neq("username", current_user) \
                            .execute()
                        
                        df_to_del = pd.DataFrame(res_users.data)

                        # 2. Đếm số lượng System Admin hiện có trên hệ thống
                        res_count = supabase.table("quan_tri_vien") \
                            .select("username", count="exact") \
                            .eq("role", "System Admin") \
                            .execute()
                        
                        count_sysadmin = res_count.count # Lấy tổng số lượng từ thuộc tính count
                        
                    except Exception as e:
                        st.error(f"Lỗi truy vấn Cloud: {e}")
                        df_to_del = pd.DataFrame()
                        count_sysadmin = 0

                    if df_to_del.empty:
                        st.info("📭 Không có tài khoản nào khác để xóa.")
                    else:
                        c1, c2 = st.columns([1, 1])
                        with c1:
                            # Tạo chuỗi hiển thị để chọn
                            df_to_del['display'] = df_to_del['ho_ten'] + " (" + df_to_del['username'] + ")"
                            u_del_display = st.selectbox(
                                "🎯 Chọn tài khoản cần loại bỏ:", 
                                options=df_to_del['display'].tolist(),
                                key="sb_delete_user"
                            )
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
                                    # Thực hiện lệnh DELETE trên Supabase
                                    supabase.table("quan_tri_vien") \
                                        .delete() \
                                        .eq("username", u_selected['username']) \
                                        .execute()
                                    
                                    st.success(f"💥 Đã xóa thành công tài khoản: {u_selected['username']} trên Cloud!")
                                    time.sleep(1)
                                    st.rerun()
                                except Exception as e: 
                                    st.error(f"❌ Lỗi khi thực hiện xóa trên Cloud: {e}")
        # --- 4. BẢO TRÌ HỆ THỐNG ---
                st.subheader("🔑 Bảo trì hệ thống")           
                with st.expander("💾 Sao lưu và Phục hồi Hệ thống"):
                    st.info("💡 **Lưu ý:** Việc phục hồi sẽ ghi đè hoàn toàn dữ liệu hiện tại.")
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("##### 📥 Xuất dữ liệu")
                        # Lấy dữ liệu từ Supabase thay vì đọc file
                        data_response = supabase.table("cham_cong").select("*").execute()
                        if data_response.data:
                            df = pd.DataFrame(data_response.data)
                            # Chuyển DataFrame thành dữ liệu Excel (dùng BytesIO)
                            import io
                            output = io.BytesIO()
                            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                                df.to_excel(writer, index=False, sheet_name='Sheet1')
                            
                            st.download_button(
                                label="Tải báo cáo Excel",
                                data=output.getvalue(),
                                file_name=f"bao_cao_{datetime.now().strftime('%d%m%Y')}.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                use_container_width=True
                            )

                with st.expander("🔥 Dọn dẹp dữ liệu"):
                    st.warning("⚠️ Hành động này sẽ xóa vĩnh viễn dữ liệu trên Cloud Supabase.")
                    confirm_reset = st.checkbox("Tôi xác nhận muốn xóa toàn bộ dữ liệu nghiệp vụ.")
                    
                    if st.button("🗑️ RESET DATABASE", type="primary", disabled=not confirm_reset, use_container_width=True):
                        try:
                            # 1. Xóa dữ liệu bảng chấm công lắp đặt
                            supabase.table("cham_cong").delete().neq("id", 0).execute() 
                            
                            # 2. Xóa dữ liệu bảng chấm công đi làm
                            supabase.table("cham_cong_di_lam").delete().neq("id", 0).execute()
                            
                            # 3. Xóa nhân viên (Trừ tài khoản Quản trị hệ thống)
                            # Giả sử bạn muốn giữ lại các tài khoản có role là 'System Admin'
                            supabase.table("quan_tri_vien").delete().neq("role", "System Admin").execute()
                            
                            st.success("💥 Đã dọn dẹp dữ liệu trên Cloud thành công!"); time.sleep(1); st.rerun()
                        except Exception as e: 
                            st.error(f"Lỗi khi reset dữ liệu trên Supabase: {e}")

            elif tab_name == "🔐 Đổi mật khẩu":
                st.subheader("Thay đổi mật khẩu")
                st.info("💡 Lưu ý: Sau khi đổi mật khẩu thành công, bạn sẽ cần đăng nhập lại.")

                current_user = st.session_state.get("username", "")

                with st.form("change_pass_form_fixed"):
                    p_old = st.text_input("Mật khẩu hiện tại", type="password")
                    p_new = st.text_input("Mật khẩu mới", type="password")
                    p_conf = st.text_input("Xác nhận mật khẩu mới", type="password")
                    
                    submit_change = st.form_submit_button("💾 CẬP NHẬT MẬT KHẨU", use_container_width=True, type="primary")
                    
                    if submit_change:
                        if not p_old or not p_new:
                            st.error("❌ Vui lòng nhập đầy đủ thông tin")
                        elif p_new != p_conf:
                            st.error("❌ Mật khẩu xác nhận không khớp")
                        elif len(p_new) < 4:
                            st.error("❌ Mật khẩu mới quá ngắn (tối thiểu 4 ký tự)")
                        else:
                            try:
                                # 1. Mã hóa mật khẩu cũ để kiểm tra
                                import hashlib
                                pw_old_hashed = hashlib.sha256(p_old.encode()).hexdigest()
                                
                                # 2. Truy vấn lấy mật khẩu hiện tại từ Supabase
                                response = supabase.table("quan_tri_vien") \
                                    .select("password") \
                                    .eq("username", current_user) \
                                    .execute()
                                
                                if response.data and response.data[0].get("password") == pw_old_hashed:
                                    # 3. Mã hóa mật khẩu mới
                                    pw_new_hashed = hashlib.sha256(p_new.encode()).hexdigest()
                                    
                                    # 4. Cập nhật mật khẩu mới lên Cloud
                                    supabase.table("quan_tri_vien") \
                                        .update({"password": pw_new_hashed}) \
                                        .eq("username", current_user) \
                                        .execute()
                                    
                                    st.success("✅ Đổi mật khẩu thành công!")
                                    st.balloons()
                                    
                                    # 5. Xử lý đăng xuất để người dùng login lại với pass mới
                                    st.session_state["authenticated"] = False
                                    if "saved_user" in cookies:
                                        del cookies["saved_user"]
                                        cookies.save()
                                    
                                    time.sleep(2)
                                    st.rerun()
                                else:
                                    st.error("❌ Mật khẩu hiện tại không chính xác")
                            except Exception as e:
                                st.error(f"❌ Lỗi hệ thống Supabase: {e}")
