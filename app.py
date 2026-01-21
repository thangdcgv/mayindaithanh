import streamlit as st
from supabase import create_client, Client
import pandas as pd
from datetime import datetime, date, time, timedelta
import os
import hashlib
import time
import datetime as dt_module 
import io
import base64
from PIL import Image
from pathlib import Path
import plotly.express as px
from streamlit_cookies_manager import EncryptedCookieManager
from streamlit_local_storage import LocalStorage
import calendar 
import pytz
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

st.set_page_config(
    page_title="Đại Thành - Ứng Dụng Nội Bộ",
    layout="wide"
)
# BẮT BUỘC: Khởi tạo biến local_storage
local_storage = LocalStorage()
#========================
#SECTION 2. SUPABASE CLIENT & DB UTILITIES
#========================

@st.cache_resource
def get_supabase() -> Client:   
  return create_client(
        st.secrets["SUPABASE_URL"],
        st.secrets["SUPABASE_KEY"]
    )
supabase = get_supabase()
@st.cache_data(ttl=300)
def load_data(reset_trigger=0):
    six_months_ago = (datetime.now() - timedelta(days=180)).isoformat()

    res = supabase.table("cham_cong") \
        .select("""
            id,
            thoi_gian,
            so_hoa_don,
            noi_dung,
            quang_duong,
            thanh_tien,
            trang_thai,
            ghi_chu_duyet,
            username,
            quan_tri_vien(ho_ten)
        """) \
        .gte("thoi_gian", six_months_ago) \
        .execute()
    return pd.DataFrame(res.data) if res and res.data else pd.DataFrame()
@st.cache_data(ttl=300)
def load_data_nghi(reset_trigger):
    try:
        # 1. Cải tiến Select: Lấy thêm quan_tri_vien(ho_ten) để có cột 'Tên'
        res = supabase.table("dang_ky_nghi")\
            .select("*, quan_tri_vien(ho_ten)")\
            .order("ngay_nghi", desc=True)\
            .execute()
        
        if res and res.data:
            df = pd.DataFrame(res.data)
            
            # 2. Chuyển đổi ngày tháng an toàn (Thêm errors='coerce')
            if 'ngay_nghi' in df.columns:
                df['ngay_nghi'] = pd.to_datetime(df['ngay_nghi'], errors='coerce')
            
            # 3. Lấy tên nhân viên từ bảng liên kết
            if 'quan_tri_vien' in df.columns:
                # Nếu quan_tri_vien là dict (do dùng select liên kết), lấy ho_ten
                df['Tên'] = df['quan_tri_vien'].apply(lambda x: x.get('ho_ten') if isinstance(x, dict) else "N/A")
            else:
                # Phòng trường hợp không join được bảng
                df['Tên'] = "N/A"
                
            return df
            
    except Exception as e:
        st.error(f"Lỗi tải dữ liệu nghỉ: {e}")
        
    return pd.DataFrame()
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
def register_user(username, password):
    supabase.table("users").insert({
        "username": username,
        "password": hash_password(password)
    }).execute()

@st.cache_data
def load_logo_base64(bin_file="LOGO.png"):
    try:
        with open(bin_file, 'rb') as f:
            data = f.read()
        return base64.b64encode(data).decode()
    except Exception:
        return None

def display_logo(logo_path="LOGO.png"):
    # Gọi hàm đã cache ở trên
    b64 = load_logo_base64(logo_path)
    if b64:
        st.markdown(
            f"""
            <div style="text-align: center;">
                <img src="data:image/png;base64,{b64}" width="150">
            </div>
            """,
            unsafe_allow_html=True
        )
#========================
#SECTION 3. COOKIE MANAGER & AUTH CONSTANT
#========================
COOKIE_USER_KEY = "saved_user"

cookies = EncryptedCookieManager(
    prefix="daithanh/",
    password=st.secrets["COOKIE_PASSWORD"]
)



#========================
#SECTION 4. AUTH FUNCTIONS (KHÔNG UI)
#========================

def check_login_supabase(u, p):
    try:
        u_lower = u.lower().strip()  # ép username về chữ thường
        input_hash = hashlib.sha256(p.encode()).hexdigest()
        
        res = supabase.table("quan_tri_vien")\
            .select("*")\
            .eq("username", u_lower)\
            .execute()
        
        if not res.data or len(res.data) == 0:
            return None
        
        user_data = res.data[0]
        stored_pass = user_data.get("password")


        # 1. So sánh hash
        if stored_pass == input_hash:
            return user_data

        # 2. Nếu stored_pass là plain text
        if stored_pass == p:
            try:
                supabase.table("quan_tri_vien")\
                    .update({"password": input_hash})\
                    .eq("username", u_lower)\
                    .execute()
                st.cache_data.clear()
                st.session_state.reset_trigger = st.session_state.get('reset_trigger', 0) + 1
                st.write(f"Đã tự động hash mật khẩu cho user {u_lower}")
            except Exception as e:
                st.error(f"Lỗi cập nhật password: {e}")
            return user_data

        return None
    except Exception as e:
        st.error(f"Lỗi kết nối Supabase: {e}")
        return None

def check_login_by_username(u_in):
    try:
        # Truy vấn bảng quan_tri_vien lấy thông tin dựa trên username từ Cookie
        res = supabase.table("quan_tri_vien") \
            .select("role, username, chuc_danh, ho_ten") \
            .eq("username", u_in) \
            .execute()
        
        # Nếu có dữ liệu trả về, lấy phần tử đầu tiên (là một dict)
        if res.data and len(res.data) > 0:
            return res.data[0]
        return None
    except Exception as e:
        st.error(f"Lỗi truy vấn Cookie từ Supabase: {e}")
        return None
# --- SỬA LẠI SECTION 3 & 6 ---

if not cookies.ready():
    # Trong khi chờ cookie sẵn sàng, vẫn cố gắng đọc LocalStorage vì nó nhanh hơn
    st.info("Đang kiểm tra thông tin đăng nhập...")
    st.stop() 

# Khi cookies đã ready, mới chạy logic auto login
if not st.session_state.get("authenticated", False):
    # 1. Thử lấy từ LocalStorage (Dùng key ngắn gọn)
    saved_user = local_storage.getItem("backup_saved_user")
    
    # 2. Nếu không có, thử lấy từ Cookie
    if saved_user and saved_user in ["None", "null", "undefined", ""]:
        saved_user = cookies.get("saved_user")

    if saved_user and saved_user not in ["None", "null", "undefined", ""]:
        res = check_login_by_username(saved_user)
        if res:
            st.session_state.update({
                "authenticated": True,
                "role": res.get('role'),
                "username": res.get('username'),
                "chuc_danh": res.get('chuc_danh'),
                "ho_ten": res.get('ho_ten')
            })
            st.rerun()
#========================
#SECTION 5. SESSION STATE INIT (DUY NHẤT)
#========================

DEFAULT_SESSION = {
    "authenticated": False,
    "username": "",
    "role": "",
    "chuc_danh": "",
    "ho_ten": "",
    "pending_nghi": None  
}

for k, v in DEFAULT_SESSION.items():
    if k not in st.session_state:
        st.session_state[k] = v

def format_vietnam_time(df):
    # Thiết lập múi giờ
    tz_vn = pytz.timezone('Asia/Ho_Chi_Minh')
    
    # 1. Định dạng Ngày nghỉ (Chỉ lấy ngày/tháng/năm)
    if 'ngay_nghi' in df.columns:
        df['ngay_nghi'] = pd.to_datetime(df['ngay_nghi']).dt.strftime('%d/%m/%Y')
    
    # 2. Định dạng Thời gian tạo đơn (Ngày/Tháng/Năm Giờ:Phút)
    if 'created_at' in df.columns:
        # Chuyển sang datetime -> áp múi giờ UTC -> đổi sang múi giờ VN
        df['created_at'] = pd.to_datetime(df['created_at']).dt.tz_convert(tz_vn)
        df['created_at'] = df['created_at'].dt.strftime('%d/%m/%Y %H:%M')
        
    return df

#Hàm chấm công hàng ngày
@st.cache_data(ttl=600)  # Lưu cache trong 10 phút
def get_today_attendance(username, today_str):
    """
    Hàm kiểm tra trạng thái chấm công của nhân viên trong ngày hôm nay.
    """
    try:
        res = supabase.table("cham_cong_di_lam") \
            .select("trang_thai_lam") \
            .eq("username", username) \
            .gte("thoi_gian", f"{today_str} 00:00:00") \
            .lte("thoi_gian", f"{today_str} 23:59:59") \
            .execute()
        
        return pd.DataFrame(res.data) if res.data else pd.DataFrame()
    except Exception:
        return pd.DataFrame()
#========================
#SECTION 7. LOGIN UI
#========================

def login_logic():
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        # Gọi hàm này ngay trên st.title("Đăng nhập")
        display_logo("LOGO.png")
        st.markdown("<h3 style='text-align: center;'>🔐 Đăng nhập hệ thống</h3>", unsafe_allow_html=True)
        with st.form("login_form_main"):
            u_in = st.text_input("Tên tài khoản").lower().strip()
            p_in = st.text_input("Mật khẩu", type="password")
            
            # --- BỔ SUNG CHECKBOX BỊ THIẾU ---
            remember_me = st.checkbox("Ghi nhớ đăng nhập")
            
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

                    # Bây giờ biến remember_me mới tồn tại để sử dụng
                    if remember_me:
                        # Set thời hạn 30 ngày (Macbook cần thời hạn rõ ràng)
                        expires_at = datetime.now() + timedelta(days=30)
                        cookies["saved_user"] = res.get("username")
                        cookies.save()
                    # 2. Lưu vào LocalStorage (Cho iOS/Dự phòng)
                        local_storage.setItem("backup_saved_user", res.get("username"))
                    st.success(f"✅ Chào mừng {res.get('ho_ten')}")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("❌ Đăng nhập thất bại. Kiểm tra lại tài khoản ")

if not st.session_state.get("authenticated"):
    login_logic()
    st.stop()

# ========================
# SECTION 8. LOGOUT 
# ========================

def logout():
    # Xóa Cookie trước để tránh Section 6 tự log lại
    cookies["saved_user"] = "" 
    cookies.save()
    # 1. Xóa Local Storage (Dành cho iOS/Dự phòng)
    local_storage.deleteItem("backup_saved_user")
    # Xóa Session
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Khởi tạo lại ĐÚNG biến authenticated
    st.session_state.authenticated = False 
    st.session_state.pending_nghi = None 
    
    st.success("Đăng xuất thành công!")
    time.sleep(0.5)
    st.rerun()

#========================
#SECTION 9. SIDEBAR & MENU
#========================

# Lấy thông tin từ session_state (đã được nạp từ login hoặc cookie)
role = st.session_state.get("role", "N/A")
user = st.session_state.get("username", "N/A")
ho_ten = st.session_state.get("ho_ten", "Nhân viên")
chuc_danh = st.session_state.get("chuc_danh", "N/A")

with st.sidebar:
    # ------------------------------
    st.markdown(f"### 👤 Chào: {ho_ten}")
    st.info(f"🎭 **Quyền:** {role}")
    st.caption(f"💼 **Chức danh:** {chuc_danh}")
    
    # NÚT ĐĂNG XUẤT: Cập nhật logic để xóa triệt để
    if st.button("🚪 Đăng xuất", use_container_width=True, type="primary"):
        logout()
        
    st.divider()

    
    # MENU CHỨC NĂNG
    st.markdown("### 🛠️ MENU CHỨC NĂNG")
    
    # Cho phép tất cả mọi người thấy Quản trị hệ thống (để đổi mật khẩu)
    menu_options = ["📦 Giao hàng - Lắp đặt", "🕒 Chấm công đi làm", "⚙️ Quản trị hệ thống"]

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
# Kiểm tra nếu có thông báo đang chờ thì hiển thị nó
if "toast_message" in st.session_state:
    st.toast(st.session_state.toast_message)
    del st.session_state.toast_message # Xóa đi để không hiện lại khi rerun lần sau
#========================
#SECTION 10. HÀM HỆ THỐNG & IMAGE
#========================

@st.cache_data(ttl=300)
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
@st.cache_data(ttl=600) # Cache trong 10 phút
def get_monthly_leave_schedule():
    # Chỉ lấy các cột cần thiết thay vì select("*")
    res_nghi = supabase.table("dang_ky_nghi").select("ho_ten, ngay_nghi, buoi_nghi, trang_thai")\
        .neq("trang_thai", "Bị từ chối").execute()
    if res_nghi.data:
        return pd.DataFrame(res_nghi.data)
    return pd.DataFrame()
#========================
#SECTION 11. BÁO CÁO CHẤM CÔNG
#========================

def get_attendance_report(target_username, filter_month=None):
    try:
        # 1. Khởi tạo truy vấn từ bảng trên Supabase
        query = supabase.table("cham_cong_di_lam") \
            .select("thoi_gian, trang_thai_lam, ghi_chu") \
            .eq("username", target_username)
        
        if filter_month:
            query = query.gte("thoi_gian", f"{filter_month}-01") \
                         .lte("thoi_gian", f"{filter_month}-31T23:59:59")
        
        res = query.order("thoi_gian", desc=True).execute()
        df = pd.DataFrame(res.data)
        
    except Exception as e:
        st.error(f"Lỗi khi truy vấn báo cáo từ Supabase: {e}")
        return pd.DataFrame()

    if df.empty: 
        return pd.DataFrame()
    
    # Định nghĩa múi giờ địa phương
    local_tz = pytz.timezone('Asia/Ho_Chi_Minh')
    
    # Chuyển đổi thoi_gian và đảm bảo có múi giờ
    if 'thoi_gian' in df.columns:
        df['thoi_gian'] = pd.to_datetime(df['thoi_gian'], errors="coerce")

    
    # Ép thoi_gian về múi giờ Việt Nam nếu dữ liệu thô từ DB là UTC
    def localize_time(dt):
        if dt.tzinfo is None:
            return local_tz.localize(dt)
        return dt.astimezone(local_tz)

    df['thoi_gian'] = df['thoi_gian'].apply(localize_time)
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
          # Đầu file hoặc đầu hàm phải có:
            from datetime import datetime, time

            # Đoạn code sửa lại:
            lunch_start = local_tz.localize(datetime.combine(date_val, time(12, 0)))
            lunch_end = local_tz.localize(datetime.combine(date_val, time(13, 30)))
            
            total_seconds = (r_time - v_time).total_seconds()
            
            # Bây giờ cả v_time, r_time và lunch đều là "offset-aware" (có múi giờ)
            overlap_start = max(v_time, lunch_start)
            overlap_end = min(r_time, lunch_end)
            
            lunch_break_seconds = 0
            if overlap_start < overlap_end:
                lunch_break_seconds = (overlap_end - overlap_start).total_seconds()
            
            actual_seconds = total_seconds - lunch_break_seconds
            tong_gio = max(0, round(actual_seconds / 3600, 2))
            
            if tong_gio < 3.5: 
                loai_cong = "Không tính công"; ghi_chu_hien_thi = "Chấm công chưa đủ giờ"
            elif 3.5 <= tong_gio < 7: 
                loai_cong = "1/2 ngày"; ghi_chu_hien_thi = "Nửa ngày công"
            elif tong_gio >= 7: 
                loai_cong = "Ngày"; ghi_chu_hien_thi = "Một ngày công"
                
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

    res_df = pd.DataFrame(summary)
    if not res_df.empty: 
        res_df.insert(0, 'STT', range(1, len(res_df) + 1))
    return res_df
# CẢI TIẾN QUAN TRỌNG: Cache tách biệt theo UserID
@st.cache_data(ttl=300)
def get_attendance_report_cached(current_user, month=None):
    """Sử dụng current_user làm key để cache không bị trộn lẫn giữa các tài khoản"""
    return get_attendance_report(current_user, month)

#Hàm lấy dữ liệu lich sử
def get_grouped_history(data_list):
    if not data_list: return []
    df_h = pd.DataFrame(data_list)
    df_h['ngay_nghi'] = pd.to_datetime(df_h['ngay_nghi'])
    results = []
    for (name, status, reason), group in df_h.groupby(['ho_ten', 'trang_thai', 'ly_do'], sort=False):
        group = group.sort_values('ngay_nghi')
        day_diff = group['ngay_nghi'].diff().dt.days != 1
        g_ids = day_diff.cumsum()
        for _, g in group.groupby(g_ids):
            s_d = g['ngay_nghi'].min().strftime('%d/%m')
            e_d = g['ngay_nghi'].max().strftime('%d/%m')
            results.append({
                "ho_ten": name, 
                "trang_thai": status, 
                "ly_do": reason,
                "range": f"{s_d}" if s_d == e_d else f"{s_d} → {e_d}",
                "count": len(g)
            })
    return results 
# 1. Tách hàm truy vấn và dùng Cache để tăng tốc
@st.cache_data(ttl=600)  # Lưu cache 10 phút
def get_pending_requests(role, username):
    try:
        query = supabase.table("cham_cong") \
            .select("id, so_hoa_don, thoi_gian, noi_dung, quang_duong, combo, thanh_tien, trang_thai, hinh_anh, quan_tri_vien(ho_ten)") \
            .eq("trang_thai", "Chờ duyệt")
        
        if role not in ["Admin", "System Admin", "Manager"]:
            query = query.eq("username", username)
            
        res = query.order("thoi_gian", desc=True).execute()
        return res.data
    except Exception as e:
        st.error(f"❌ Lỗi kết nối Cloud: {e}")
        return []

# 2. Hàm format thời gian (tách riêng để gọn code giao diện)
def format_vn_time(time_str):
    try:
        dt = pd.to_datetime(time_str)
        if dt.tz is None:
            dt = dt.tz_localize('UTC')
        return dt.tz_convert('Asia/Ho_Chi_Minh').strftime('%d/%m/%Y %H:%M')
    except:
        return time_str
# --- 1. TỐI ƯU TRUY VẤN CÓ CACHE ---
@st.cache_data(ttl=600)
def get_employee_list(role):
    try:
        if role in ["System Admin", "Admin"]:
            res = supabase.table("quan_tri_vien").select("username, ho_ten").in_("role", ["Manager", "User"]).execute()
        else: # Manager
            res = supabase.table("quan_tri_vien").select("username, ho_ten").eq("role", "User").execute()
        return res.data
    except Exception as e:
        st.error(f"Lỗi tải danh sách: {e}")
        return []

# --- 2. TỐI ƯU LOGIC TÍNH TIỀN ---
def calculate_total_amount(quang_duong, combo_lon, combo_nho):
    # Tính đơn giá km
    if quang_duong < 20: don_gia = 30000
    elif quang_duong <= 30: don_gia = 50000
    elif quang_duong <= 40: don_gia = 70000
    elif quang_duong <= 50: don_gia = 80000
    else: don_gia = 80000 + (quang_duong - 50) * 5000
    
    total = (combo_lon * 200000) + (combo_nho * don_gia)
    return total  
@st.cache_data(ttl=600)
#Cập nhật cho phần báo cáo chấm công lắp dđặt
def load_data_report(reset_trigger, role, username):
    try:
        # Chỉ lấy các cột cần thiết, bỏ hinh_anh để nhẹ truy vấn [cite: 3]
        query = supabase.table("cham_cong").select(
            "id, thoi_gian, so_hoa_don, noi_dung, quang_duong, combo, thanh_tien, trang_thai, ghi_chu_duyet, username, quan_tri_vien(ho_ten)"
        )
        
        # Phân quyền Server-side: User chỉ lấy đơn của họ 
        if role not in ["Admin", "System Admin", "Manager"]:
            query = query.eq("username", username)
            
        res = query.order("thoi_gian", desc=True).execute() # Mới nhất lên đầu
        return pd.DataFrame(res.data) if res.data else pd.DataFrame()
    except Exception as e:
        st.error(f"Lỗi tải dữ liệu: {e}")
        return pd.DataFrame() 
# PHÂN HỆ 1: CHẤM CÔNG ĐI LÀM (ĐÃ TỐI ƯU CHO COOKIES)
# ==============================================================================
if menu == "🕒 Chấm công đi làm":
    # Sử dụng thông tin trực tiếp từ Session State (Đã nạp từ Cookie/Login)
    role = st.session_state.get("role")
    user = st.session_state.get("username")
    ho_ten = st.session_state.get("ho_ten")


    tabs = st.tabs(["📍 Chấm công", "🛠️ Quản lý & Sửa công", "📊 Báo cáo chấm công", "📅 Đăng ký lịch nghỉ"])
    

    # =========================================================
    # PHÂN QUYỀN CHUNG
    # =========================================================
    ROLE_USER = ["User", "Manager"]
    ROLE_ADMIN = ["Admin"]
    ROLE_SYS = ["System Admin"]

    # =========================================================
    # TAB 1 – NHÂN VIÊN (CHẤM CÔNG)
    # =========================================================
    with tabs[0]:
        if role == "System Admin":
            st.info("💡 Sếp trả lương cho nhân viên là công đức vô lượng rồi, không cần chấm công.")
        else:
            st.markdown(f"##### ⏰ Chấm công: {ho_ten}")
            
            now = datetime.now()
            today_str = now.strftime("%Y-%m-%d")
            display_month = now.strftime("%m/%Y")

            # --- GỌI HÀM CACHE ĐỂ LẤY TRẠNG THÁI ---
            # Chúng ta truyền thêm 1 biến 'reset_trigger' nếu cần làm mới thủ công
            df_today = get_today_attendance(user, today_str)
            
            has_in = any(df_today['trang_thai_lam'] == "Vào làm") if not df_today.empty else False
            has_out = any(df_today['trang_thai_lam'] == "Ra về") if not df_today.empty else False
            has_off = any(df_today['trang_thai_lam'].str.contains("Nghỉ", na=False)) if not df_today.empty else False

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
                        
                        # QUAN TRỌNG: Xóa cache để lần chạy sau load lại dữ liệu mới nhất
                        st.cache_data.clear() 
                        st.session_state.toast_message = "✅ Đã ghi nhận giờ vào"
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
                        
                        st.cache_data.clear() # Xóa cache
                        st.session_state.toast_message = "🏁 Đã ghi nhận giờ ra"
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
                                    
                                    st.cache_data.clear() # Xóa cache
                                    st.session_state.toast_message = "Đã gửi đăng ký nghỉ"
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Lỗi: {e}")

                show_detail = st.button("📊 Chi tiết chấm công cá nhân", use_container_width=True)

            with c_right:
                # Sử dụng lại hàm cache báo cáo bạn đã có
                df_quick = get_attendance_report_cached(user)
                if not df_quick.empty:
                    st.caption("Ngày làm việc gần nhất")
                    st.dataframe(df_quick.head(3), use_container_width=True, hide_index=True)
            

    # =========================================================
    # TAB 2 – ĐIỀU CHỈNH CÔNG (ADMIN + SYSTEM ADMIN)
    # =========================================================
    if role in ROLE_ADMIN + ROLE_SYS:
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
                            st.session_state.toast_message = f"✅ Đã xóa dữ liệu ngày {d_str}"
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
                        
                        st.session_state.toast_message = f"🎯 Đã gán 1 ngày công cho {sel_u}"
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
                        
                        st.session_state.toast_message = f"🎯 Đã gán 1/2 ngày công cho {sel_u}"
                        st.rerun()
                    except Exception as e:
                        st.error(f"Lỗi: {e}")
# --- BƯỚC 1: KHỞI TẠO STATE ĐỂ RESET ---
    if "reset_trigger" not in st.session_state:
        st.session_state.reset_trigger = 0
    if "pending_nghi" not in st.session_state:
        st.session_state.pending_nghi = None
    # ==========================================
    # PHẦN XỬ LÝ XÁC NHẬN GHI ĐÈ (CONFIRMATION)
    # ==========================================

    # Kiểm tra nếu có dữ liệu đang chờ xác nhận từ Session State
    if st.session_state.get("pending_nghi"):
        with st.container(border=True):
            st.warning(f"🔔 **Xác nhận thay đổi:** {st.session_state.pending_nghi['message']}")
            c1, c2 = st.columns(2)
            
            with c1:
                if st.button("✅ Đồng ý ghi đè", use_container_width=True, type="primary"):
                    try:
                        p_data = st.session_state.pending_nghi
                        
                        # 1. Thực hiện Cập nhật các ngày trùng (Chờ duyệt -> Chờ duyệt mới)
                        if p_data.get("to_update"):
                            for item in p_data["to_update"]:
                                supabase.table("dang_ky_nghi")\
                                    .update({
                                        "buoi_nghi": item["buoi_nghi"],
                                        "ly_do": item["ly_do"],
                                        "trang_thai": "Chờ duyệt",
                                        "created_at": "now()" # Cập nhật lại thời gian gửi đơn
                                    })\
                                    .eq("id", item["id"])\
                                    .execute()
                        
                        # 2. Thực hiện Thêm mới các ngày chưa từng có trong lịch
                        if p_data.get("to_insert"):
                            supabase.table("dang_ky_nghi")\
                                .insert(p_data["to_insert"])\
                                .execute()
                        
                        # 3. Dọn dẹp bộ nhớ và làm mới giao diện
                        st.session_state.pending_nghi = None
                        st.session_state.toast_message = "✅ Đã cập nhật và gửi đơn thành công!"
                        st.session_state.reset_trigger = st.session_state.get("reset_trigger", 0) + 1
                        
                        # Xóa cache để lịch sử hiển thị đúng dữ liệu mới nhất
                        st.cache_data.clear()
                        st.rerun()
                        
                    except Exception as e:
                        st.error(f"❌ Lỗi khi thực hiện ghi đè: {e}")
            
            with c2:
                if st.button("❌ Hủy bỏ", use_container_width=True):
                    # Xóa dữ liệu chờ và quay lại trạng thái bình thường
                    st.session_state.pending_nghi = None
                    st.rerun()

    # ==========================================
    # =========================================================
    # TAB 3 – ĐĂNG KÝ LỊCH NGHỈ (TẤT CẢ USER ĐỀU VÀO ĐƯỢC)
    # =========================================================
    with tabs[-1]:
        with st.expander("🔍 Xem lịch nghỉ chi tiết trong tháng", expanded=True):
            # --- KHU VỰC GHI CHÚ (Giữ nguyên theo file của bạn) ---
            st.markdown("""
            <div style="display: flex; gap: 20px; margin-bottom: 10px; font-size: 14px;">
                <span>📌 <b>Ký hiệu:</b></span>
                <span><b>OFF</b>: Ngày</span>
                <span><b>1/2S</b>: Sáng</span>
                <span><b>1/2C</b>: Chiều</span>
                <span><b>( )</b>: Chờ duyệt</span>
            </div>
            <div style="display: flex; gap: 20px; margin-bottom: 20px; font-size: 14px;">
                <span>🎨 <b>Màu sắc:</b></span>
                <span style="color: #ff4b4b;">■ Đỏ: Cả ngày</span>
                <span style="color: #ffa500;">■ Cam: Nửa buổi</span>
            </div>
            """, unsafe_allow_html=True)

            try:
                # Lấy dữ liệu (Giữ nguyên logic truy vấn từ file của bạn)
                res_nghi = supabase.table("dang_ky_nghi").select("*").neq("trang_thai", "Bị từ chối").execute()
                
                if res_nghi.data:
                    df_all = pd.DataFrame(res_nghi.data)
                    df_all['ngay_nghi'] = pd.to_datetime(df_all['ngay_nghi'])
                    
                    today = date.today()
                    curr_month, curr_year = today.month, today.year
                    last_day = calendar.monthrange(curr_year, curr_month)[1]
                    all_days = list(range(1, last_day + 1))
                    
                    # Lọc dữ liệu tháng hiện tại
                    df_month = df_all[(df_all['ngay_nghi'].dt.month == curr_month) & 
                                    (df_all['ngay_nghi'].dt.year == curr_year)].copy()
                    
                    if not df_month.empty:
                        df_month['Ngày'] = df_month['ngay_nghi'].dt.day
                        
                        # --- SỬA ĐÚNG LOGIC NÀY ĐỂ HẾT LỖI AMBIGUOUS ---
                        # Thay vì map trong aggfunc, ta map trực tiếp lên cột trước khi pivot
                        def get_symbol(row):
                            b = row['buoi_nghi']
                            t = row['trang_thai']
                            s = "OFF" if b == "Cả ngày" else ("1/2S" if b == "Sáng" else "1/2C")
                            return f"({s})" if t == "Chờ duyệt" else s

                        # Tạo cột ký hiệu (Logic giống hệt hàm map_symbol của bạn)
                        df_month['Ky_Hieu'] = df_month.apply(get_symbol, axis=1)

                        # Thực hiện Pivot trên cột ký hiệu đã tính sẵn
                        pivot_nghi = df_month.pivot_table(
                            index='ho_ten',
                            columns='Ngày',
                            values='Ky_Hieu',
                            aggfunc='first' # Lấy giá trị đầu tiên nếu trùng ngày
                        )
                        
                        # Đảm bảo đủ các ngày trong tháng (Giữ nguyên logic file cũ)
                        for d in all_days:
                            if d not in pivot_nghi.columns:
                                pivot_nghi[d] = ""
                        
                        pivot_nghi = pivot_nghi[all_days].fillna("")
                        pivot_nghi.index.name = "Họ và Tên"

                        # Styling (Giữ nguyên logic file cũ)
                        def style_leave(val):
                            val_str = str(val)
                            if 'OFF' in val_str: return 'background-color: #ff4b4b; color: white'
                            if '1/2S' in val_str or '1/2C' in val_str: return 'background-color: #ffa500; color: white'
                            return ''

                        st.dataframe(pivot_nghi.style.applymap(style_leave), use_container_width=True)
                    else:
                        st.info("Chưa có dữ liệu nghỉ tháng này.")
                else:
                    st.info("Chưa có dữ liệu đăng ký nghỉ.")
            except Exception as e:
                st.error(f"Lỗi tải lịch: {e}")

        st.divider()

        # 2. KHU VỰC USER – ĐĂNG KÝ + LỊCH SỬ
        if role != "System Admin":
            with st.expander("✨ Đăng ký & Theo dõi lịch nghỉ", expanded=True):
                col_left, col_right = st.columns([2, 3])

                with col_left:
                    st.markdown("#### 📝 Tạo đơn mới")

                    # --- PHẦN 1: TRUY VẤN DỮ LIỆU CŨ ---
                    res_limit = supabase.table("dang_ky_nghi").select("ngay_nghi").eq("username", st.session_state.username).neq("trang_thai", "Bị từ chối").execute()
                    days_used = len(res_limit.data) if res_limit.data else 0

                    # --- PHẦN 2: CHỌN THỜI GIAN (Dùng key động để reset) ---
                    # Khi reset_trigger tăng, key thay đổi -> widget tự động về value=()
                    range_date = st.date_input(
                        "Chọn khoảng thời gian nghỉ", 
                        value=(), 
                        format="DD/MM/YYYY",
                        key=f"range_date_widget_{st.session_state.reset_trigger}"
                    )

                    selected_dates = []
                    num_new_days = 0
                    is_special_auto = False
                    is_urgent = False 

                    if isinstance(range_date, tuple) and len(range_date) == 2:
                        start_date, end_date = range_date
                        curr = start_date
                        while curr <= end_date:
                            if curr.weekday() != 6: 
                                selected_dates.append(curr)
                            curr += timedelta(days=1)
                        
                        num_new_days = len(selected_dates)
                        if num_new_days > 0:
                            if datetime.combine(selected_dates[0], datetime.min.time()) < datetime.now() + timedelta(hours=24):
                                is_urgent = True
                                is_special_auto = True 
                            if (num_new_days > 2) or (days_used + num_new_days > 2):
                                is_special_auto = True

                    # --- PHẦN 3: FORM ĐĂNG KÝ ---
                    # --- LOGIC HIỂN THỊ VÀ FORM ĐĂNG KÝ ---
                    if not range_date or len(range_date) < 2:
                        st.info("👆 Vui lòng chọn ngày bắt đầu và ngày kết thúc.")
                    elif num_new_days == 0:
                        st.error("❌ Khoảng ngày bạn chọn chỉ bao gồm Chủ Nhật. Vui lòng chọn lại.")
                    else:
                        st.success(f"📋 Hệ thống ghi nhận: **{num_new_days} ngày** nghỉ thực tế (Đã trừ các ngày Chủ Nhật).")
                        with st.expander("Xem chi tiết các ngày sẽ đăng ký"):
                            st.write(", ".join([d.strftime('%d/%m/%Y') for d in selected_dates]))

                        # Sử dụng clear_on_submit=True kết hợp với key reset_trigger để làm sạch form tuyệt đối
                        with st.form("form_dang_ky_nghi_vertical", clear_on_submit=True):
                            confirm_boss = False
                            other_reason = ""
                            
                            # Tạo key động dựa trên reset_trigger để ép reset widget khi gửi thành công
                            form_key_suffix = st.session_state.get("reset_trigger", 0)

                            if is_special_auto:
                                if is_urgent:
                                    st.warning("💡 Quy định: Nghỉ gấp cần có sự đồng ý trực tiếp từ cấp trên.")
                                    confirm_boss = st.checkbox("📞 Xác nhận đã liên hệ và được cấp trên đồng ý")
                                else:
                                    st.warning(f"⚠️ **Lưu ý số ngày đã nghỉ {days_used} ngày(gồm cả chờ duyệt))")
                                
                                reason_main = "Khác"
                                other_reason = st.text_area(
                                    "👉 Giải trình lý do chi tiết (Bắt buộc):", 
                                    placeholder="Ví dụ: Nghỉ Tết, việc gia đình quan trọng...",
                                    key=f"special_reason_{form_key_suffix}"
                                )
                            else:
                                reason_main = st.selectbox(
                                    "Lý do nghỉ", 
                                    ["Nghỉ phép", "Việc nhà", "Nghỉ không phép", "Khác"],
                                    key=f"reason_select_{form_key_suffix}"
                                )
                                # Dùng container để tránh việc gán biến rỗng làm mất dữ liệu khi user đổi ý
                                if reason_main == "Khác":
                                    other_reason = st.text_input("Ghi rõ lý do:", key=f"other_reason_text_{form_key_suffix}")

                            session_off = st.selectbox("Buổi nghỉ", ["Cả ngày", "Sáng", "Chiều"], key=f"session_{form_key_suffix}")
                            submit = st.form_submit_button("GỬI ĐƠN", use_container_width=True, type="primary")

                            if submit:
                                # 1. Validation (Kiểm tra lỗi nhập liệu)
                                error_found = False
                                if is_urgent and not confirm_boss:
                                    st.error("❌ Bạn phải tích xác nhận đã liên hệ cấp trên!")
                                    error_found = True
                                elif (is_special_auto or reason_main == "Khác") and not other_reason.strip():
                                    st.error("❌ Bạn bắt buộc phải giải trình lý do!")
                                    error_found = True

                                # 2. Xử lý logic kiểm tra trùng và phân loại
                                if not error_found and selected_dates:
                                    try:
                                        prefix = "[ĐỘT XUẤT]" if is_urgent else "[ĐẶC BIỆT]"
                                        final_reason = f"{prefix} {other_reason.strip()}" if is_special_auto else (other_reason.strip() if reason_main == "Khác" else reason_main)
                                        
                                        # Truy vấn kiểm tra trùng cho cả bản thân và đồng nghiệp
                                        res_check = supabase.table("dang_ky_nghi") \
                                            .select("id, username, ho_ten, nhom, ngay_nghi, trang_thai") \
                                            .neq("trang_thai", "Bị từ chối") \
                                            .gte("ngay_nghi", selected_dates[0].isoformat()) \
                                            .lte("ngay_nghi", selected_dates[-1].isoformat()) \
                                            .execute()

                                        df_check = pd.DataFrame(res_check.data) if res_check.data else pd.DataFrame()
                                        if not df_check.empty:
                                            df_check['ngay_nghi'] = pd.to_datetime(df_check['ngay_nghi']).dt.date

                                        data_to_insert, data_to_update = [], []
                                        error_overlap_colleague = []
                                        days_already_approved = []
                                        days_waiting_approval = []

                                        for curr_day in selected_dates:
                                            current_day_reason = final_reason
                                            if not df_check.empty:
                                                # A. KIỂM TRA TRÙNG LỊCH BẢN THÂN
                                                own_rec = df_check[(df_check['ngay_nghi'] == curr_day) & (df_check['username'] == st.session_state.username)]
                                                if not own_rec.empty:
                                                    status = own_rec.iloc[0]['trang_thai']
                                                    day_str = curr_day.strftime('%d/%m/%Y')
                                                    
                                                    if status == "Đã duyệt":
                                                        days_already_approved.append(day_str)
                                                    else: # Trạng thái "Chờ duyệt"
                                                        days_waiting_approval.append(day_str)
                                                        data_to_update.append({
                                                            "id": own_rec.iloc[0]['id'], 
                                                            "buoi_nghi": session_off, 
                                                            "ly_do": current_day_reason
                                                        })
                                                    continue 
                                                
                                                # B. KIỂM TRA TRÙNG LỊCH ĐỒNG NGHIỆP TRONG NHÓM
                                                col_rec = df_check[(df_check['ngay_nghi'] == curr_day) & (df_check['nhom'] == st.session_state.chuc_danh) & (df_check['username'] != st.session_state.username)]
                                                if not col_rec.empty:
                                                    names = ", ".join(col_rec['ho_ten'].unique())
                                                    error_overlap_colleague.append(f"{curr_day.strftime('%d/%m/%Y')} (trùng: {names})")
                                                    if is_special_auto: 
                                                        current_day_reason += f" [⚠️ TRÙNG: {names}]"

                                            # C. NẾU KHÔNG TRÙNG BẢN THÂN -> CHUẨN BỊ INSERT
                                            data_to_insert.append({
                                                "username": st.session_state.username, 
                                                "ho_ten": st.session_state.ho_ten, 
                                                "nhom": st.session_state.chuc_danh, 
                                                "ngay_nghi": curr_day.isoformat(), 
                                                "buoi_nghi": session_off, 
                                                "ly_do": current_day_reason, 
                                                "trang_thai": "Chờ duyệt"
                                            })

                                        # 3. PHẢN HỒI KẾT QUẢ
                                        # Ưu tiên 1: Chặn nếu trùng ngày ĐÃ DUYỆT
                                        if days_already_approved:
                                            st.error(f"❌ Không thể đăng ký! Các ngày sau đã được duyệt trước đó: {', '.join(days_already_approved)}")
                                        
                                        # Ưu tiên 2: Chặn trùng nhóm (nếu không phải trường hợp đặc biệt)
                                        elif error_overlap_colleague and not is_special_auto:
                                            st.error(f"❌ Trùng lịch nhóm: {', '.join(error_overlap_colleague)}")
                                        
                                        # Ưu tiên 3: Hỏi xác nhận nếu có ngày CHỜ DUYỆT
                                        elif days_waiting_approval:
                                            st.session_state.pending_nghi = {
                                                "message": f"Bạn có đơn đang CHỜ DUYỆT vào ngày {', '.join(days_waiting_approval)}. Bạn có muốn GHI ĐÈ không?",
                                                "to_update": data_to_update, 
                                                "to_insert": data_to_insert
                                            }
                                            st.rerun()
                                        
                                        # Ưu tiên 4: Thực hiện Insert nếu mọi thứ đều mới
                                        else:
                                            if data_to_insert:
                                                supabase.table("dang_ky_nghi").insert(data_to_insert).execute()
                                                st.session_state.toast_message = "✅ Gửi đơn thành công!"
                                                st.session_state.reset_trigger = st.session_state.get("reset_trigger", 0) + 1
                                                st.cache_data.clear() 
                                                st.rerun()
                                            else:
                                                st.warning("⚠️ Không có ngày mới nào để đăng ký.")

                                    except Exception as e:
                                        st.error(f"Lỗi hệ thống: {e}")

                # --- PHÍA BÊN PHẢI: LỊCH SỬ ĐƠN ---
                with col_right:
                    st.markdown("#### 🕒 Lịch sử đơn của bạn")
                    
                    # Gọi hàm display_user_history hoặc viết trực tiếp (Ở đây tôi viết trực tiếp để đồng bộ gom nhóm)
                    res_history = supabase.table("dang_ky_nghi").select("*").eq("username", st.session_state.username).order("ngay_nghi", desc=False).execute()

                    if res_history.data:
                        df_hist = pd.DataFrame(res_history.data)
                        df_hist['ngay_nghi'] = pd.to_datetime(df_hist['ngay_nghi'])
                        
                        # Logic gom nhóm
                        groups = []
                        if not df_hist.empty:
                            current_group = [df_hist.iloc[0]]
                            for i in range(1, len(df_hist)):
                                prev, curr = df_hist.iloc[i-1], df_hist.iloc[i]
                                diff = (curr['ngay_nghi'] - prev['ngay_nghi']).days
                                if diff == 1 and curr['trang_thai'] == prev['trang_thai'] and curr['buoi_nghi'] == prev['buoi_nghi'] and curr['ly_do'] == prev['ly_do']:
                                    current_group.append(curr)
                                else:
                                    groups.append(current_group)
                                    current_group = [curr]
                            groups.append(current_group)

                        for g in reversed(groups):
                            start_g, end_g = g[0]['ngay_nghi'].strftime('%d/%m/%Y'), g[-1]['ngay_nghi'].strftime('%d/%m/%Y')
                            total_days, status, buoi = len(g), g[0]['trang_thai'], g[0]['buoi_nghi']
                            
                            # Màu sắc trạng thái
                            status_colors = {"Chờ duyệt": "#ffa500", "Đã duyệt": "#28a745", "Bị từ chối": "#dc3545"}
                            color = status_colors.get(status, "#666")

                            with st.container(border=True):
                                c1, c2 = st.columns([3, 1])
                                with c1:
                                    st.markdown(f"📅 **{start_g if total_days==1 else f'{start_g} - {end_g}'}**")
                                    st.caption(f"Số lượng: {total_days} ngày ({buoi})")
                                    st.markdown(f"**Lý do:** {g[0]['ly_do']}")
                                    if status == "Bị từ chối" and g[0].get('ly_do_tu_choi'):
                                        st.info(f"💬 Phản hồi: {g[0]['ly_do_tu_choi']}")
                                with c2:
                                    st.markdown(f"<div style='text-align:right; color:{color}; font-weight:bold; margin-top:10px;'>{status}</div>", unsafe_allow_html=True)
                    else:
                        st.info("Bạn chưa có dữ liệu đăng ký.")
    # --- HÀM HELPER ĐỂ TĂNG TỐC LOAD ---
        def display_user_history(username, supabase_client):
            history_res = supabase_client.table("dang_ky_nghi")\
                .select("ngay_nghi, trang_thai, ly_do_tu_choi, buoi_nghi, ly_do")\
                .eq("username", username)\
                .order("ngay_nghi", desc=False).limit(10).execute() # Giới hạn 10 đơn gần nhất để nhanh hơn
            
            if history_res.data:
                for item in history_res.data:
                    # Logic hiển thị gọn nhẹ như container bạn đã làm
                    with st.container(border=True):
                        st.write(f"📅 {item['ngay_nghi']} - **{item['trang_thai']}**")
                        st.caption(f"Lý do: {item['ly_do']}")
        def display_general_history(supabase_client):
        
            history_res = supabase_client.table("dang_ky_nghi")\
                .select("ngay_nghi, ho_ten, trang_thai, ly_do")\
                .order("created_at", desc=False).limit(5).execute()
            
            if history_res.data:
                st.markdown("#### 📢 Hoạt động gần đây (Toàn hệ thống)")

                # 1. Tạo thanh công cụ bộ lọc (Filter bar)
                c_filter1, c_filter2 = st.columns([2, 1])

                with c_filter1:
                    search_name = st.text_input("🔍 Tìm tên nhân viên", placeholder="Nhập tên...", label_visibility="collapsed")

                with c_filter2:
                    filter_status = st.selectbox(
                        "Lọc trạng thái",
                        ["Tất cả", "Chờ duyệt", "Đã duyệt", "Bị từ chối"],
                        label_visibility="collapsed"
                    )

                # 2. Xử lý logic lọc dữ liệu từ history_res.data
                filtered_data = history_res.data

                if search_name:
                    filtered_data = [item for item in filtered_data if search_name.lower() in item['ho_ten'].lower()]

                if filter_status != "Tất cả":
                    filtered_data = [item for item in filtered_data if item['trang_thai'] == filter_status]

                # 3. Hiển thị danh sách đã lọc vào vùng cuộn
                with st.container(height=500, border=False):
                    if not filtered_data:
                        st.info("Không tìm thấy dữ liệu phù hợp.")
                    else:
                        for item in filtered_data:
                            with st.container(border=True):
                                d_str = pd.to_datetime(item['ngay_nghi']).strftime('%d/%m/%Y')
                                # Highlight tên nhân viên nếu đang tìm kiếm
                                st.markdown(f"**{item['ho_ten']}** - 📅 {d_str}")
                                st.caption(f"Trạng thái: {item['trang_thai']} | Lý do: {item['ly_do']}")
            else:
                st.info("Chưa có dữ liệu lịch sử hệ thống.")
        if role == "System Admin":
            # --- PHẦN 3: PHÊ DUYỆT & QUẢN LÝ ---
            with st.expander("🛠️ Phê duyệt & Quản lý đơn nghỉ", expanded=True):
                # 1. Tải dữ liệu và xử lý
                df_raw = load_data_nghi(st.session_state.get('reset_trigger', 0))
                grouped_data = []
                df_display = pd.DataFrame()

                # --- XỬ LÝ DỮ LIỆU (NẾU CÓ) ---
                if not df_raw.empty:
                    df_pending = df_raw[df_raw['trang_thai'] == "Chờ duyệt"].copy()
                    if not df_pending.empty:
                        # Logic gom nhóm ngày (Giữ nguyên)
                        def group_consecutive_days(group):
                            group = group.sort_values('ngay_nghi')
                            day_diff = group['ngay_nghi'].diff().dt.days != 1
                            group_id = day_diff.cumsum()
                            res_groups = []
                            for _, g in group.groupby(group_id):
                                res_groups.append({
                                    "username": g['username'].iloc[0],
                                    "Họ và Tên": g['ho_ten'].iloc[0] if 'ho_ten' in g.columns else "N/A",
                                    "Chức danh": g['nhom'].iloc[0] if 'nhom' in g.columns else "N/A",
                                    "Từ ngày": g['ngay_nghi'].min().strftime('%d/%m/%Y'),
                                    "Đến ngày": g['ngay_nghi'].max().strftime('%d/%m/%Y'),
                                    "Tổng ngày": len(g),
                                    "Buổi nghỉ": g['buoi_nghi'].iloc[0] if 'buoi_nghi' in g.columns else "N/A",
                                    "Lý do đăng ký": g['ly_do'].iloc[0] if 'ly_do' in g.columns else "N/A",
                                    "ids": g['id'].tolist()
                                })
                            return res_groups

                        for _, subgroup in df_pending.groupby(['username', 'ly_do', 'buoi_nghi']):
                            grouped_data.extend(group_consecutive_days(subgroup))
                        df_display = pd.DataFrame(grouped_data)

                # 2. HIỂN THỊ BẢNG (CHỈ KHI CÓ ĐƠN CHỜ DUYỆT)
                selected_indices = [] # Khởi tạo danh sách chọn rỗng
                
                if not df_display.empty:
                    st.write("📌 *Danh sách đơn chờ xử lý (Chọn hàng để thao tác):*")
                    event = st.dataframe(
                        df_display.drop(columns=['ids']), 
                        use_container_width=True,
                        hide_index=True,
                        on_select="rerun",
                        selection_mode="multi-row",
                        key="df_approve_table_v3"
                    )
                    selected_indices = event.selection.rows
                else:
                    st.info("🎉 Hiện không có đơn nào đang chờ duyệt.")

                st.divider()

                # 3. CHIA CỘT (LUÔN THỰC HIỆN BẤT KỂ CÓ ĐƠN HAY KHÔNG)
                col_form, col_history = st.columns([2, 3])

                # --- A. KHỐI FORM XỬ LÝ (BÊN TRÁI) ---
                with col_form:
                    if selected_indices and not df_display.empty:
                        first_selection = df_display.iloc[selected_indices[0]]
                        all_selected_ids = []
                        for idx in selected_indices:
                            all_selected_ids.extend(df_display.iloc[idx]['ids'])

                        st.markdown(f"#### 📝 Xử lý đơn: **{first_selection['Họ và Tên']}**")
                        st.caption(f"Đang chọn {len(all_selected_ids)} ngày nghỉ.")
                        
                        reason_reject = st.text_area("Lý do từ chối (Bắt buộc nếu Từ chối):", 
                                                    placeholder="Nhập lý do...",
                                                    key="reject_area_admin")
                        
                        c1, c2 = st.columns(2)
                        
                        # Logic Nút Duyệt
                        if c1.button("✅ Duyệt", type="primary", use_container_width=True):
                            try:
                                supabase.table("dang_ky_nghi").update({"trang_thai": "Đã duyệt"}).in_("id", all_selected_ids).execute()
                                st.cache_data.clear()
                                st.session_state.reset_trigger = st.session_state.get('reset_trigger', 0) + 1
                                st.rerun()
                            except Exception as e:
                                st.error(f"Lỗi: {e}")

                        # Logic Nút Từ chối
                        if c2.button("❌ Từ chối", use_container_width=True):
                            if not reason_reject.strip():
                                st.error("⚠️ Phải nhập lý do!")
                            else:
                                try:
                                    supabase.table("dang_ky_nghi").update({
                                        "trang_thai": "Bị từ chối", 
                                        "ly_do": f"❌ TỪ CHỐI: {reason_reject.strip()}"
                                    }).in_("id", all_selected_ids).execute()
                                    st.cache_data.clear()
                                    st.session_state.reset_trigger = st.session_state.get('reset_trigger', 0) + 1
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Lỗi: {e}")
                    else:
                        # Hiển thị khi chưa chọn đơn hoặc không có đơn
                        st.info("💡 Chọn đơn ở bảng trên để hiện Form xử lý.")
                        st.caption("Nếu không có đơn chờ, khu vực này sẽ trống.")

                # --- B. KHỐI LỊCH SỬ (BÊN PHẢI) - LUÔN HIỂN THỊ ---
                with col_history:
                    st.markdown("#### 🕒 Nhật ký hoạt động")

                    tab_p, tab_a = st.tabs(["📝 Lịch sử đăng ký", "✅ Lịch sử phê duyệt"])

                    # --- Tab 1: Đơn mới ---
                    with tab_p:
                        # Container có chiều cao cố định -> Tự động cuộn
                        with st.container(height=420, border=False):
                            try:
                                res_p = supabase.table("dang_ky_nghi").select("*").eq("trang_thai", "Chờ duyệt").order("created_at", desc=True).limit(50).execute()
                                p_groups = get_grouped_history(res_p.data)
                                
                                if p_groups:
                                    for item in p_groups:
                                        with st.container(border=True):
                                            st.markdown(f"**{item['ho_ten']}** ({item['count']}n)")
                                            st.markdown(f"📅 {item['range']}")
                                            st.caption(f"💬 {item['ly_do']}")
                                else:
                                    st.caption("Không có đơn đăng ký mới.")
                            except Exception as e: 
                                st.error("Lỗi tải nhật ký.")

                    # --- Tab 2: Lịch sử phê duyệt ---
                    with tab_a:
                        with st.container(height=420, border=False):
                            try:
                                res_a = supabase.table("dang_ky_nghi").select("*").neq("trang_thai", "Chờ duyệt").order("created_at", desc=True).limit(50).execute()
                                a_groups = get_grouped_history(res_a.data)
                                
                                if a_groups:
                                    for item in a_groups:
                                        color = "#28a745" if item['trang_thai'] == "Đã duyệt" else "#dc3545"
                                        icon = "✅" if item['trang_thai'] == "Đã duyệt" else "❌"
                                        with st.container(border=True):
                                            st.markdown(f"**{icon} {item['ho_ten']}** ({item['count']}n)")
                                            st.markdown(f"📅 {item['range']} : <span style='color:{color}; font-weight:bold;'>{item['trang_thai']}</span>", unsafe_allow_html=True)
                                            st.caption(f"📝 {item['ly_do']}")
                                else:
                                    st.caption("Chưa có lịch sử xử lý.")
                            except Exception as e: 
                                st.error("Lỗi tải lịch sử.")

                # --- C. CHI TIẾT LỊCH SỬ CÁ NHÂN (NẾU ĐANG CHỌN) ---
                if selected_indices and not df_display.empty:
                    st.divider()
                    first_selection = df_display.iloc[selected_indices[0]]
                    with st.expander(f"🔍 Toàn bộ lịch sử của {first_selection['Họ và Tên']}", expanded=False):
                        display_user_history(first_selection['username'], supabase)

            
    # =========================================================
    # TAB 4 – BÁO CÁO (ADMIN + SYSTEM ADMIN)
    # =========================================================
    if role in ROLE_ADMIN + ROLE_SYS:
        with tabs[2]:

            st.markdown("#### 📊 Báo cáo chấm công nhân viên")
            col_f1, col_f2 = st.columns(2)
                        
            # 1. Lấy danh sách nhân viên từ Supabase thay vì SQLite
            try:
                responser_users = supabase.table("quan_tri_vien") \
                    .select("username, ho_ten") \
                    .neq("role", "System Admin") \
                    .execute()
                df_users = pd.DataFrame(responser_users.data)
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
                        @st.cache_data
                        #hàm xuất Excel
                        def convert_df_to_excel(df_source):
                            output = io.BytesIO()
                            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                                df_source.to_excel(writer, index=False, sheet_name='BaoCao')
                                # Cấu hình format file Excel
                                workbook  = writer.book
                                worksheet = writer.sheets['BaoCao']
                                header_format = workbook.add_format({'bold': True, 'bg_color': '#D7E4BC', 'border': 1})
                                for col_num, value in enumerate(df_report.columns.values):
                                    worksheet.write(0, col_num, value, header_format)
                                    worksheet.set_column(col_num, col_num, 15)
                            return output.getvalue() 
                        excel_data = convert_df_to_excel(df_display)
                    st.download_button(
                        label="📥 Tải báo cáo Excel",
                        data=output.getvalue(),
                        file_name=f"ChamCong_{target_user_rpt}_{month_str}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True
                    )
                else: 
                    st.info(f"ℹ️ Không có dữ liệu chấm công của **{target_user_rpt}** trong tháng {sel_m}/{sel_y}")

elif menu == "📦 Giao hàng - Lắp đặt":
    # Lấy thông tin từ session_state (đã nạp từ Cookie)
    role = st.session_state.get("role", "User")
    chuc_danh = st.session_state.get("chuc_danh", "N/A")
    user_hien_tai = st.session_state.get("username")

    # 1. PHÂN QUYỀN TABS
    # Gom nhóm logic để dễ quản lý
    tabs = st.tabs(["📸 Chấm công lắp đặt", "📋 Duyệt đơn", "📈 Báo cáo lắp đặt"])

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
                st.cache_data.clear()
                st.session_state.reset_trigger = st.session_state.get('reset_trigger', 0) + 1   
                return True
        except Exception as e:
            st.error(f"Lỗi cập nhật trên Cloud: {e}")
            return False

# --- GIAO DIỆN TAB Chấm công---
    with tabs[0]:
        user = st.session_state.get("username")
        role = st.session_state.get("role")
        
        # Sử dụng hàm cache
        raw_nv = get_employee_list(role)
        df_nv = pd.DataFrame(raw_nv)
        
        target_user = user
        if not df_nv.empty and role in ["Manager", "Admin", "System Admin"]:
            df_nv['display'] = df_nv['ho_ten'] + " (" + df_nv['username'] + ")"
            
            # UI chọn nhân viên
            if role in ["Admin", "System Admin"]:
                sel = st.selectbox("🎯 Chấm công cho:", df_nv['display'])
                target_user = df_nv.loc[df_nv['display'] == sel, 'username'].values[0]
            else:
                sel = st.selectbox("🎯 Chấm công thay cho:", ["Tự chấm công"] + df_nv['display'].tolist())
                if sel != "Tự chấm công":
                    target_user = df_nv.loc[df_nv['display'] == sel, 'username'].values[0]

        # Form nhập liệu
        if "f_up_key" not in st.session_state: st.session_state["f_up_key"] = 0
        uploaded_file = st.file_uploader("🖼️ Ảnh hóa đơn *", type=["jpg", "png", "jpeg"], key=f"up_{st.session_state['f_up_key']}")

        with st.form("form_lap_dat", clear_on_submit=True):
            c1, c2 = st.columns(2)
            so_hd_in = c1.text_input("📝 Số hóa đơn *")
            quang_duong = c2.number_input("🛣️ Quãng đường (km) *", min_value=0)
            
            m1, m2 = st.columns(2)
            c_lon = m1.number_input("🤖 Máy lớn", min_value=0)
            c_nho = m2.number_input("📦 Máy nhỏ/Vật tư", min_value=0)
            
            noi_dung = st.text_area("📍 Địa chỉ / Ghi chú *").title().strip()
            
            submit = st.form_submit_button("🚀 GỬI YÊU CẦU", use_container_width=True)
            
            if submit:
                if not uploaded_file or not so_hd_in or not noi_dung:
                    st.error("❌ Thiếu thông tin bắt buộc!")
                elif c_lon == 0 and c_nho == 0:
                    st.error("❌ Nhập ít nhất 1 loại máy!")
                else:
                    # Xử lý dữ liệu
                    so_hd = so_hd_in.strip().upper()
                    final_hd = so_hd if so_hd.startswith("HD") else f"HD{so_hd}"
                    tong_tien = calculate_total_amount(quang_duong, c_lon, c_nho)
                    
                    try:
                        # Chuyển ảnh (Vẫn giữ Base64 theo yêu cầu cũ nhưng nên cân nhắc Storage)
                        img_base64 = base64.b64encode(uploaded_file.read()).decode()
                        
                        payload = {
                            "username": target_user,
                            "thoi_gian": datetime.now().isoformat(),
                            "so_hoa_don": final_hd,
                            "noi_dung": f"{noi_dung} | (L:{c_lon}, N:{c_nho})",
                            "quang_duong": quang_duong,
                            "combo": c_lon + c_nho,
                            "thanh_tien": tong_tien,
                            "hinh_anh": img_base64,
                            "trang_thai": 'Chờ duyệt'
                        }
                        
                        res = supabase.table("cham_cong").insert(payload).execute()
                        if res.data:
                            st.success("✅ Đã gửi đơn thành công!")
                            st.session_state["f_up_key"] += 1
                            st.cache_data.clear() # Quan trọng: Xóa cache tab danh sách để hiện đơn mới ngay
                            st.rerun()
                    except Exception as e:
                        if "duplicate" in str(e): st.error(f"❌ Số HĐ {final_hd} đã tồn tại!")
                        else: st.error(f"❌ Lỗi: {e}")
# --- TAB 2: DUYỆT ĐƠN (CHỈ ADMIN/SYSTEM ADMIN/MANAGER) ---
if role in ["Admin", "System Admin", "Manager", "User"]:
    with tabs[1]:
        st.markdown("#### 📋 Danh sách đơn chờ duyệt")
        
        data = get_pending_requests(role, user_hien_tai)
        
        if not data:
            st.info("📭 Hiện tại không có đơn nào đang chờ duyệt.")
        else:
            for r in data:
                # Xử lý tên nhân viên từ kết quả join
                ho_ten_nv = r.get('quan_tri_vien', {}).get('ho_ten', 'N/A') if r.get('quan_tri_vien') else "N/A"
                time_display = format_vn_time(r['thoi_gian'])
                
                expander_title = f"📦 HĐ: {r['so_hoa_don']} — 👤 {ho_ten_nv} — 🕒 {time_display}"
                
                with st.expander(expander_title):
                    cl, cr = st.columns([1.5, 1])
                    with cl:
                        st.write(f"**📍 Địa chỉ:** {r['noi_dung']}")
                        st.write(f"🛣️ **{r['quang_duong']} km** | 📦 **{r['combo']} máy**")
                        st.markdown(f"#### 💰 Tổng: `{r['thanh_tien']:,.0f}` VNĐ")
                        st.divider()

                        # Logic phân quyền nút bấm
                        if role in ["Admin", "System Admin"]:
                            b1, b2 = st.columns(2)
                            if b1.button("✅ DUYỆT", key=f"ap_{r['id']}", use_container_width=True, type="primary"):
                                if quick_update_status(r["id"], "Đã duyệt", "Thông tin chính xác"):
                                    st.cache_data.clear() # Xóa cache để load lại data mới
                                    st.rerun()
                                            
                            with b2:
                                with st.popover("❌ TỪ CHỐI", use_container_width=True):
                                    reason = st.text_area("Lý do:", key=f"txt_{r['id']}")
                                    if st.button("Xác nhận", key=f"conf_{r['id']}"):
                                        if reason.strip() and quick_update_status(r["id"], "Từ chối", reason.strip()):
                                            st.cache_data.clear()
                                            st.rerun()
                        else:
                            st.info("⏳ Đang chờ kế toán duyệt" if role == "User" else "ℹ️ Chế độ chỉ xem")

                    with cr:
                        if r.get("hinh_anh"):
                            img_data = r["hinh_anh"]
                            if not img_data.startswith("data:image"):
                                img_data = f"data:image/jpeg;base64,{img_data}"
                            st.image(img_data, use_container_width=True)
                        else:
                            st.warning("Không có ảnh")
# --- TAB 3: BÁO CÁO LẮP ĐẶT  ---
    with tabs[-1]:
        # Lấy thông tin từ Session (đã nạp bởi Cookie Manager)
        # Lấy dữ liệu gốc
        current_u = st.session_state.get("username")
        current_r = st.session_state.get("role")
        user_hien_tai = current_u
        user_login    = current_u
        role = current_r
        role_login = current_r
        row_id = None
        # --- KHỞI TẠO BIẾN TRƯỚC ĐỂ TRÁNH CRASH ---
        df_all = pd.DataFrame() 
        res = None
         
        
        try:
            # 1. Truy vấn dữ liệu từ Supabase
            data = get_pending_requests(current_r, user_hien_tai)
            
            # Kiểm tra nếu có dữ liệu trả về thành công
            if res and res.data:
                # Tạo df_raw để xử lý trung gian
                df_raw = pd.DataFrame(res.data)
                
                # 2. Xử lý lấy 'ho_ten' an toàn từ bảng quan_tri_vien
                if 'quan_tri_vien' in df_raw.columns:
                    df_raw['Tên'] = df_raw['quan_tri_vien'].apply(lambda x: x['ho_ten'] if isinstance(x, dict) else "N/A")
                else:
                    df_raw['Tên'] = "N/A"

                # 3. Đổi tên cột khớp với logic hiển thị của bạn
                df_raw = df_raw.rename(columns={
                    'thoi_gian': 'Thời Gian',
                    'so_hoa_don': 'Số HĐ',
                    'noi_dung': 'Địa chỉ',
                    'quang_duong': 'Km',
                    'thanh_tien': 'Thành tiền',
                    'trang_thai': 'Trạng thái',
                    'ghi_chu_duyet': 'Lý do'
                })

                # 4. Chuyển đổi thời gian an toàn
                df_raw["Thời Gian"] = pd.to_datetime(df_raw["Thời Gian"], errors='coerce')
                df_raw = df_raw.dropna(subset=["Thời Gian"])

                # 5. PHÂN QUYỀN HIỂN THỊ DỮ LIỆU
                if role in ["Admin", "System Admin", "Manager"]:
                    df_all = df_raw.copy()
                else:
                    # Lọc đơn của chính mình dựa trên username trong session
                    if "username" in df_raw.columns:
                        df_all = df_raw[df_raw["username"] == user_hien_tai].copy()
                    else:
                        df_all = pd.DataFrame()

                # 6. KIỂM TRA DỮ LIỆU SAU LỌC
                if df_all.empty:
                    st.info(f"ℹ️ Tài khoản `{user_hien_tai}` chưa có dữ liệu đơn nào.")
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
                                                hole=0.4)
                                st.plotly_chart(fig_pie, use_container_width=True)
                        else:
                            st.warning("Chưa có đơn nào được chuyển trạng thái 'Đã duyệt'.")
                    
                    st.divider()

                    # --- 4. BÁO CÁO CHI TIẾT (ĐÃ TỐI ƯU CHO COOKIE) ---
                    with st.expander("📊 Tra cứu chi tiết và Xuất báo cáo", expanded=False):
                        col_f1, col_f2, col_f3 = st.columns(3)

                        # Lấy thông tin từ Session đã nạp bởi Cookie
                        current_role = st.session_state.get("role")
                        current_user = st.session_state.get("username")
                        current_ho_ten = st.session_state.get("ho_ten")

                        # --- 1. PHẦN DÙNG CHUNG: CHỌN THÁNG (Cho cả Admin và User) ---
                        curr_date = date.today()
                        month_opts = [(curr_date.replace(day=1) - pd.DateOffset(months=i)).strftime("%m/%Y") for i in range(12)]

                        sel_month = col_f1.selectbox("📅 Chọn tháng báo cáo", month_opts)

                        # Tính toán ngày bắt đầu và kết thúc từ tháng đã chọn
                        sel_dt = datetime.strptime(sel_month, "%m/%Y")
                        start_d = sel_dt.date().replace(day=1)
                        last_day = calendar.monthrange(sel_dt.year, sel_dt.month)[1]
                        end_d = sel_dt.date().replace(day=last_day)
                        d_range = [start_d, end_d]

                        # --- 2. PHẦN PHÂN QUYỀN: CHỌN NHÂN VIÊN & TRẠNG THÁI ---
                        if current_role in ["Admin", "System Admin", "Manager"]:
                            # Admin/Manager: Được chọn bất kỳ nhân viên nào
                            nv_opts = ["Tất cả"] + sorted(df_all["Tên"].astype(str).unique().tolist())
                            sel_nv = col_f2.selectbox("👤 Nhân viên", nv_opts, index=0)
                            sel_tt = col_f3.selectbox("📌 Trạng thái", ["Tất cả", "Chờ duyệt", "Đã duyệt", "Từ chối"])
                        else:
                            # User thường: Chỉ được xem chính mình (Cố định giá trị, không cho chọn người khác)
                            sel_nv = current_ho_ten 
                            # Hiển thị thông tin giả lập để user biết họ đang xem đơn của họ
                            col_f2.text_input("👤 Nhân viên", value=current_ho_ten, disabled=True)
                            sel_tt = col_f3.selectbox("📌 Trạng thái", ["Tất cả", "Chờ duyệt", "Đã duyệt", "Từ chối"])

                        # Áp dụng bộ lọc khi hợp lệ
                        if isinstance(d_range, (list, tuple)) and len(d_range) == 2:
                            # 1. THIẾT LẬP MASK (BỘ LỌC) CHUẨN PHÂN QUYỀN
                            mask = (df_all["Thời Gian"].dt.date >= d_range[0]) & (df_all["Thời Gian"].dt.date <= d_range[1])
                            
                            if current_role in ["Admin", "System Admin"]:
                                # Admin: Lọc theo nhân viên được chọn và trạng thái
                                if sel_nv != "Tất cả":
                                    mask &= (df_all["Tên"] == sel_nv)
                                if sel_tt != "Tất cả":
                                    mask &= (df_all["Trạng thái"] == sel_tt)
                            else:
                                # USER THƯỜNG: Bắt buộc chỉ thấy đơn của chính mình
                                mask &= (df_all["username"] == current_user)
                                # Vẫn cho phép User lọc theo trạng thái đơn của họ
                                if sel_tt != "Tất cả":
                                    mask &= (df_all["Trạng thái"] == sel_tt)
                            
                            # 2. TRÍCH XUẤT DỮ LIỆU SAU LỌC
                            df_display = df_all[mask].sort_values("Thời Gian", ascending=False)

                            if df_display.empty:
                                st.info("🔍 Không có dữ liệu phù hợp với bộ lọc.")
                            else:
                                # Tính toán dữ liệu
                                total_count = len(df_display)
                                approved_df = df_display[df_display["Trạng thái"] == "Đã duyệt"]
                                approved_count = len(approved_df)
                                rev_sum = approved_df["Thành tiền"].sum()

                                # CSS để làm đẹp các thẻ chỉ số
                                st.markdown("""
                                    <style>
                                    .stats-container {
                                        display: flex;
                                        align-items: flex-end; /* Căn lề dưới để bằng với nút bấm */
                                        gap: 40px;
                                        padding: 10px 5px;
                                        margin-bottom: -10px; /* Thu hẹp khoảng cách với bảng */
                                        font-family: inherit;
                                    }
                                    
                                    .stat-item {
                                        display: flex;
                                        flex-direction: column;
                                        font-family: inherit;
                                    }

                                    .stat-label {
                                        color: #94a3b8; /* Màu chữ phụ xám xanh */
                                        font-size: 0.8rem;
                                        font-weight: 600;
                                        text-transform: uppercase;
                                        letter-spacing: 0.1em;
                                        margin-bottom: 2px;
                                        font-family: inherit;
                                    }

                                    .stat-value {
                                        color: #ffffff;
                                        font-size: 2rem;
                                        font-weight: 800;
                                        line-height: 1;
                                        text-shadow: 0px 2px 4px rgba(0,0,0,0.3); /* Tạo độ nổi trên nền tối */
                                        font-family: inherit;
                                    }

                                    .currency {
                                        font-size: 0.9rem;
                                        color: #38bdf8; /* Màu xanh Cyan làm điểm nhấn cho tiền tệ */
                                        margin-left: 4px;
                                        font-family: inherit;
                                    }

                                    .count-highlight {
                                        color: #4ade80; /* Màu xanh lá dịu cho số lượng đơn đã duyệt */
                                        font-family: inherit;
                                    }

                                    .count-total {
                                        color: #64748b;
                                        font-size: 1.1rem;
                                        font-weight: 400;
                                        font-family: inherit;
                                    }
                                    </style>
                                """, unsafe_allow_html=True)

                                # Chia cột: Thu nhập | Thống kê | Nút xuất Excel (đẩy về bên phải)
                                col_info, c_exp = st.columns([4, 1.2])

                                with col_info:
                                    # Hiển thị các chỉ số trần (không khung)
                                    st.markdown(f"""
                                        <div class="stats-container">
                                            <div class="stat-item">
                                                <div class="stat-label">💰 Tổng thu nhập(Đã duyệt)</div>
                                                <div class="stat-value">
                                                    {rev_sum:,.0f}<span class="currency">VNĐ</span>
                                                </div>
                                            </div>
                                            <div class="stat-item">
                                                <div class="stat-label">📊 Thống kê đơn</div>
                                                <div class="stat-value">
                                                    <span class="count-highlight">{approved_count}</span><span class="count-total"> / {total_count} đơn</span>
                                                </div>
                                            </div>
                                        </div>
                                    """, unsafe_allow_html=True)
                                
                                # --- XỬ LÝ GIAO DIỆN BẢNG HIỂN THỊ (df_view) ---
                                df_view = df_display.copy()

                                # A. Định dạng múi giờ Việt Nam và Ngày/Tháng/Năm Giờ:Phút (Loại bỏ +00:00)
                                if 'Thời Gian' in df_view.columns:
                                    df_view['Thời Gian'] = pd.to_datetime(df_view['Thời Gian'])
                                    try:
                                        if df_view['Thời Gian'].dt.tz is None:
                                            df_view['Thời Gian'] = df_view['Thời Gian'].dt.tz_localize('UTC').dt.tz_convert('Asia/Ho_Chi_Minh')
                                        else:
                                            df_view['Thời Gian'] = df_view['Thời Gian'].dt.tz_convert('Asia/Ho_Chi_Minh')
                                    except:
                                        df_view['Thời Gian'] = df_view['Thời Gian'] + pd.Timedelta(hours=7)
                                    
                                    # Định dạng chuỗi sạch sẽ để hiển thị
                                    df_view['Thời Gian'] = df_view['Thời Gian'].dt.strftime('%d/%m/%Y %H:%M')

                                # B. Thêm cột STT tự động
                                df_view = df_view.reset_index(drop=True)
                                df_view.insert(0, "STT", range(1, len(df_view) + 1))

                                # C. Đổi tên cột và Lọc cột hiển thị
                                map_names = {
                                    "combo": "Số máy",
                                    "km": "Quãng đường (Km)",
                                    "dia_chi": "Địa chỉ",
                                    "noi_dung": "Địa chỉ"
                                }
                                df_view = df_view.rename(columns=map_names)

                                desired_columns = [
                                    "STT", "Tên", "Thời Gian", "Số HĐ", "Địa chỉ", 
                                    "Quãng đường (Km)", "Số máy", "Thành tiền", "Trạng thái", "Lý do"
                                ]
                                final_cols = [c for c in desired_columns if c in df_view.columns]
                                df_final = df_view[final_cols]

                                # --- 🚀 CẤU HÌNH CỘT VÀ CSS ---
                                column_configuration = {
                                    "Tên": st.column_config.TextColumn("Tên", width="medium"),
                                    "Lý do": st.column_config.TextColumn("Lý do", width="large"),
                                    "Thành tiền": st.column_config.NumberColumn("Thành tiền", format="%d ₫"),
                                }

                                st.markdown("""
                                    <style>
                                        /* Căn giữa STT: Nhắm vào cột 1 (User) và cột 2 (Admin vì cột 1 là checkbox) */
                                        [data-testid="stDataFrame"] td:nth-child(1),
                                        [data-testid="stDataFrame"] td:nth-child(2) {
                                            text-align: center !important;
                                        }
                                    </style>
                                """, unsafe_allow_html=True)

                                scroll_height = 400 
                                is_admin = st.session_state.get("role") == "System Admin"
                                rows_to_delete = pd.DataFrame() # Khởi tạo biến rỗng tránh lỗi

                                # --- HIỂN THỊ DỮ LIỆU ---
                                with st.container(height=scroll_height, border=False):
                                    if is_admin:
                                        df_to_edit = df_final.copy()
                                        df_to_edit.insert(0, "🗑️", False)
                                        
                                        edited_df = st.data_editor(
                                            df_to_edit,
                                            use_container_width=True,
                                            hide_index=True,
                                            column_config=column_configuration,
                                            disabled=[c for c in df_to_edit.columns if c != "🗑️"],
                                            key="editor_delete_table_scroll"
                                        )
                                        rows_to_delete = edited_df[edited_df["🗑️"] == True]
                                    else:
                                        st.dataframe(
                                            df_final, 
                                            use_container_width=True, 
                                            hide_index=True, 
                                            column_config=column_configuration
                                        )

                                # --- 🗑️ LOGIC XÓA TỐI ƯU (BATCH DELETE) ---
                                if is_admin and not rows_to_delete.empty:
                                    st.warning(f"⚠️ Đang chọn {len(rows_to_delete)} đơn để xóa.")
                                    if st.button("🔥 XÁC NHẬN XÓA VĨNH VIỄN", type="primary", use_container_width=True):
                                        try:
                                            list_so_hd = rows_to_delete["Số HĐ"].tolist() 
                                            
                                            # TỐI ƯU: Xóa tất cả trong 1 lần gọi thay vì dùng vòng lặp for
                                            supabase.table("cham_cong").delete().in_("so_hoa_don", list_so_hd).execute()                                                
                                            
                                            st.cache_data.clear() # Xóa cache để dữ liệu bảng cập nhật ngay
                                            st.session_state.reset_trigger = st.session_state.get('reset_trigger', 0) + 1
                                            st.session_state.toast_message = "✅ Đã xóa các đơn được chọn thành công!"
                                            st.rerun()
                                        except Exception as e:
                                            st.error(f"Lỗi khi xóa: {e}")

                                # --- XỬ LÝ XUẤT FILE EXCEL ---
                                out = io.BytesIO()
                                df_export = df_display.sort_values("Thời Gian").copy()
                                
                                # Định dạng ngày cho Excel
                                df_export['Ngày'] = df_export['Thời Gian'].dt.strftime('%d/%m/%Y')
                                df_export.insert(0, 'STT', range(1, len(df_export) + 1))

                                # Xử lý các cột số lượng
                                df_export['Máy'] = df_export['combo'].fillna(0).astype(int) if 'combo' in df_export.columns else 0
                                df_export['Km_Số'] = df_export['Km'].apply(lambda x: f"{int(x)} Km" if x > 0 else "") if 'Km' in df_export.columns else ""

                                # Chuẩn bị Sheet chính
                                df_main = df_export[['STT', 'Ngày', 'Địa chỉ', 'Tên', 'Máy', 'Km_Số', 'Thành tiền', 'Lý do', 'Trạng thái']]
                                df_main.columns = ['STT', 'Ngày', 'Địa chỉ', 'Nhân viên', 'Số Máy', 'Km', 'Thành tiền', 'Ghi chú duyệt', 'Tình trạng']

                                # Chuẩn bị Sheet Summary (Tổng hợp chi phí)
                                df_approved = df_display[df_display['Trạng thái'] == 'Đã duyệt'].copy()
                                if not df_approved.empty:
                                    df_summary = df_approved.groupby("Tên").agg(
                                        Tong_Don=("Số HĐ", "count"),
                                        Tong_Cong=("Thành tiền", "sum") 
                                    ).reset_index()
                                else:
                                    df_summary = pd.DataFrame(columns=['NHÂN VIÊN', 'SỐ ĐƠN', 'THÀNH TIỀN'])
                                
                                df_summary.columns = ['NHÂN VIÊN', 'SỐ ĐƠN', 'THÀNH TIỀN']
                                if not df_summary.empty:
                                    # Tính dòng tổng cộng
                                    total_row = pd.DataFrame(
                                        [['TỔNG CỘNG', df_summary['SỐ ĐƠN'].sum(), df_summary['THÀNH TIỀN'].sum()]], 
                                        columns=['NHÂN VIÊN', 'SỐ ĐƠN', 'THÀNH TIỀN']
                                    )
                                    df_summary = pd.concat([df_summary, total_row], ignore_index=True)

                                # --- XỬ LÝ XUẤT FILE EXCEL HOÀN CHỈNH ---
                                with pd.ExcelWriter(out, engine="xlsxwriter") as writer:
                                    df_main.to_excel(writer, index=False, sheet_name="BaoCao", startrow=3)
                                    
                                    wb = writer.book
                                    ws = writer.sheets['BaoCao']

                                    # --- 1. KHAI BÁO TẤT CẢ FORMATS (Gộp chung 1 chỗ) ---
                                    title_fmt = wb.add_format({'bold': True, 'font_size': 14, 'align': 'center', 'valign': 'vcenter', 'bg_color': '#C6EFCE', 'border': 1})
                                    header_fmt = wb.add_format({'bold': True, 'align': 'center', 'valign': 'vcenter', 'bg_color': '#2E75B6', 'font_color': 'white', 'border': 1})
                                    green_header_fmt = wb.add_format({'bold': True, 'align': 'center', 'valign': 'vcenter', 'bg_color': '#C6EFCE', 'border': 1})
                                    
                                    cell_fmt = wb.add_format({'border': 1, 'valign': 'vcenter'})
                                    center_fmt = wb.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter'})
                                    money_fmt = wb.add_format({'num_format': '#,##0', 'border': 1, 'align': 'right', 'valign': 'vcenter'})
                                    
                                    footer_fmt = wb.add_format({'bold': True, 'bg_color': '#C6EFCE', 'border': 1, 'num_format': '#,##0', 'align': 'right'})
                                    footer_label_fmt = wb.add_format({'bold': True, 'bg_color': '#C6EFCE', 'border': 1, 'align': 'left'})
                                    
                                    note_box_fmt = wb.add_format({'border': 1, 'valign': 'top', 'align': 'left', 'text_wrap': True, 'bg_color': '#C6EFCE', 'font_size': 10})

                                    # --- 2. TIÊU ĐỀ CHÍNH (Đã sửa Merge Range A1:I2) ---
                                    if 'sel_month' not in locals():
                                        sel_month = d_range[0].strftime("%m/%Y")
                                    label_time = sel_month if current_role in ["Admin", "System Admin"] else f"{d_range[0].strftime('%d/%m')} - {d_range[1].strftime('%d/%m/%Y')}"
                                    
                                    ws.merge_range('A1:I2', f'BẢNG TỔNG HỢP CÔNG LẮP ĐẶT - {label_time}', title_fmt)

                                    # --- 3. CĂN CHỈNH CỘT BẢNG CHI TIẾT ---
                                    ws.set_column('A:A', 5, center_fmt)
                                    ws.set_column('B:B', 12, center_fmt)
                                    ws.set_column('C:C', 35, cell_fmt)
                                    ws.set_column('D:D', 20, cell_fmt)
                                    ws.set_column('E:F', 10, center_fmt)
                                    ws.set_column('G:G', 15, money_fmt)
                                    ws.set_column('H:H', 20, cell_fmt)
                                    ws.set_column('I:I', 15, center_fmt)

                                    # --- 4. XỬ LÝ VÙNG TỔNG HỢP (Cột L trở đi) ---
                                    summary_start_col = 11 
                                    
                                    # Xóa trắng vùng cũ để tránh lỗi "đè" chữ
                                    for r in range(3, 25):
                                        for c in range(summary_start_col, summary_start_col + 3):
                                            ws.write(r, c, None)

                                    # Ghi Ghi chú
                                    note_text = ("Ghi chú chính sách phụ cấp:\n"
                                                "- Phụ cấp 30k/ máy đối với đơn đi từ 20km trở xuống\n"
                                                "- Phụ cấp 50k/ máy đối với đơn từ 21km – 30km hoặc máy ép nhiệt khí nén.\n"
                                                "- Phụ cấp 70k/ máy đối với đơn từ 31 – 40km\n"
                                                "- Phụ cấp 80k/ máy đối với đơn từ 41 – 50km. Đối với mỗi km kế tiếp từ 51km +\n"
                                                "tính thêm 5k/1km vượt mức tính\n"
                                                "- Đối với các máy khổ lớn hoặc đơn tính sẽ tính theo thỏa thuận.")
                                    ws.merge_range(3, summary_start_col, 8, summary_start_col + 2, note_text, note_box_fmt)

                                    # Ghi Bảng Tổng Hợp
                                    summary_header_row = 10
                                    ws.write(summary_header_row, summary_start_col, "TÊN", green_header_fmt)
                                    ws.write(summary_header_row, summary_start_col + 1, "TỔNG ĐƠN", green_header_fmt)
                                    ws.write(summary_header_row, summary_start_col + 2, "TỔNG TIỀN", green_header_fmt)

                                    for i, row in enumerate(df_summary.values):
                                        curr_r = summary_header_row + 1 + i
                                        is_last = (i == len(df_summary) - 1)
                                        
                                        if is_last:
                                            ws.write(curr_r, summary_start_col, row[0], footer_label_fmt)
                                            ws.write(curr_r, summary_start_col + 1, row[1], footer_fmt)
                                            ws.write(curr_r, summary_start_col + 2, row[2], footer_fmt)
                                        else:
                                            ws.write(curr_r, summary_start_col, row[0], cell_fmt)
                                            ws.write(curr_r, summary_start_col + 1, row[1], center_fmt)
                                            ws.write(curr_r, summary_start_col + 2, row[2], money_fmt)

                                    ws.set_column(summary_start_col, summary_start_col, 25)
                                    ws.set_column(summary_start_col + 1, summary_start_col + 2, 15)

                                # NÚT TẢI EXCEL
                                with c_exp:
                                    # Căn chỉnh nút Export cho cân đối với chiều cao của các thẻ Metric
                                    st.write("<div style='padding-top: 15px;'></div>", unsafe_allow_html=True)                                  # Code xuất Excel của bạn giữ nguyên
                                    st.download_button(
                                        label="📥 Tải Excel Báo Cáo", 
                                        data=out.getvalue(), 
                                        file_name=f"Bao_Cao_{current_user}.xlsx", 
                                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                        use_container_width=True
                                    )
            else:
                st.info("📭 Chưa có dữ liệu đơn nào trong hệ thống.")
        except Exception as e:
            st.error(f"Lỗi tải dữ liệu: {e}")

        # --- 3. QUẢN LÝ ĐƠN HÀNG (SỬA/XÓA/HỦY) ---

        # --- DÀNH CHO USER & MANAGER: SỬA HOẶC XÓA ĐƠN CỦA CHÍNH MÌNH ---
        if current_r in ["User", "Manager"]:
            with st.expander("🛠️ Cập nhật thông tin đơn", expanded=False):
                st.markdown("""
                **📌 Hướng dẫn trạng thái đơn lắp đặt:**
                - 🟡 **Chờ duyệt:** Đơn đã gửi. Bạn có thể **Sửa** hoặc **Xóa**.
                - 🔴 **Từ chối:** Đơn sai thông tin. Vui lòng **cập nhật lại**.
                - 🟢 **Đã duyệt:** Đơn hợp lệ. **Không thể chỉnh sửa**.
                """)
                    
                # 1. Lọc đơn và đảm bảo kiểu dữ liệu đồng nhất để tránh lỗi lọc
                df_edit = df_all[
                    (df_all["username"] == current_u) & 
                    (df_all["Trạng thái"].isin(["Chờ duyệt", "Từ chối"]))
                ].copy()
                
                if df_edit.empty:
                    st.info("ℹ️ Bạn không có đơn nào ở trạng thái Chờ duyệt hoặc Từ chối.")
                else:
                    # 2. Tạo nhãn (Ép Số HĐ về string để tránh lỗi nối chuỗi)
                    df_edit['label'] = df_edit['Số HĐ'].astype(str) + " (" + df_edit['Trạng thái'] + ")"
                    sel_label = st.selectbox("🎯 Chọn đơn cần thao tác:", df_edit["label"].tolist(), key="sel_edit_order")
                    
                    # Tách lấy Số HĐ và đảm bảo kiểu dữ liệu khi so sánh để tìm row_data
                    sel_hd_edit = sel_label.split(" (")[0]
                    # SỬA LỖI: So sánh đồng nhất kiểu chuỗi
                    mask = df_edit["Số HĐ"].astype(str) == sel_hd_edit
                    if not mask.any():
                        st.error("Không tìm thấy dữ liệu đơn.")
                        st.stop()
                        
                    row_data = df_edit[mask].iloc[0]
                    row_id = row_data["id"] # Bỏ ép kiểu int() để an toàn với Supabase
                    current_status = row_data["Trạng thái"]
                    
                    # --- LOGIC TÁCH DỮ LIỆU AN TOÀN ---
                    full_content = str(row_data.get('Địa chỉ', ''))
                    raw_address = full_content.split(" | (")[0] if " | (" in full_content else full_content
                    
                    # Lấy thông số kỹ thuật
                    try:
                        val_quang_duong = int(float(row_data.get('Km', 0))) # Ép kiểu qua float trước để tránh lỗi nếu là '10.0'
                    except:
                        val_quang_duong = 0
                        
                    current_may_lon = 0
                    current_may_nho = 0
                    
                    if " | (Máy lớn: " in full_content:
                        try:
                            parts = full_content.split(" | (")[1].replace(")", "").split(", ")
                            # SỬA LỖI: Kiểm tra độ dài parts trước khi truy cập index
                            if len(parts) >= 2:
                                current_may_lon = int(parts[0].split(": ")[1])
                                current_may_nho = int(parts[1].split(": ")[1])
                        except:
                            current_may_nho = int(float(row_data.get('combo', 0)))

                    # --- TRUY VẤN LẤY ẢNH ---
                    old_img_base64 = None
                    try:
                        # Dùng biến supabase đã khai báo ở đầu file
                        response_img = supabase.table("cham_cong").select("hinh_anh").eq("id", row_id).execute()
                        if response_img.data:
                            old_img_base64 = response_img.data[0].get("hinh_anh")
                    except Exception as e:
                        st.error(f"Lỗi khi lấy ảnh: {e}")

                    # --- NÚT XÓA ĐƠN ---
                    if current_status == "Chờ duyệt":
                        if st.button("🗑️ XOÁ ĐƠN NÀY", use_container_width=True, type="secondary"):
                            try:
                                supabase.table("cham_cong") \
                                    .delete() \
                                    .eq("id", row_id) \
                                    .eq("username", current_u) \
                                    .eq("trang_thai", "Chờ duyệt") \
                                    .execute()
                                
                                st.session_state.toast_message = "✅ Đã xóa đơn thành công!" 
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Lỗi khi xóa: {e}")
                    else:
                        ly_do_tu_choi = row_data.get('Lý do', 'Không có lý do cụ thể')
                        st.warning(f"🔴 Đơn bị từ chối. Lý do: **{ly_do_tu_choi}**")

                    st.write("---")
                    # --- FORM CẬP NHẬT (Ví dụ nằm trong một vòng lặp hoặc logic chọn đơn của bạn) ---
                    # Giả sử row_id, old_img_blob, val_quang_duong, current_may_lon, current_may_nho, raw_address đã được xác định ở trên
                    

                    with st.form(key=f"edit_form_{row_id}", clear_on_submit=False):
                        st.markdown(f"**📝 Hiệu chỉnh đơn: {sel_hd_edit}**")
                        
                        # 1. Hiển thị ảnh cũ (nếu có) bằng Popover ngay trong Form
                        if old_img_base64:
                            with st.popover("🖼️ Xem ảnh hóa đơn hiện tại", use_container_width=True):
                                if st.button("Tải ảnh xem trước", key=f"load_img_{row_id}"):
                                    res_img = supabase.table("cham_cong").select("hinh_anh").eq("id", row_id).execute()
                                    if res_img.data:
                                        img_data = res_img.data[0].get("hinh_anh")
                                        if not img_data.startswith("data:image"):
                                            img_data = f"data:image/jpeg;base64,{img_data}"
                                        st.image(img_data, use_container_width=True)

                        # 2. Các trường nhập liệu (Bắt buộc nằm trong form để lấy giá trị khi submit)
                        n_uploaded_file = st.file_uploader("🆕 Thay ảnh hóa đơn mới (Để trống nếu giữ nguyên)", type=["jpg", "png", "jpeg"])

                        c1, c2 = st.columns(2)
                        n_hd_in = c1.text_input("📝 Số hóa đơn *", value=str(row_data.get('Số HĐ', '')))
                        n_quang_duong = c2.number_input("🛣️ Quãng đường (km) *", min_value=0, step=1, value=int(val_quang_duong))

                        m1, m2 = st.columns(2)
                        n_may_lon = m1.number_input("🤖 Máy lớn", min_value=0, step=1, value=int(current_may_lon))
                        n_may_nho = m2.number_input("📦 Máy nhỏ / Vật tư", min_value=0, step=1, value=int(current_may_nho))

                        n_noi_dung = st.text_area("📍 Địa chỉ / Ghi chú mới *", value=raw_address, height=80)

                        # 3. Nút xác nhận submit form
                        submit_update = st.form_submit_button("💾 XÁC NHẬN CẬP NHẬT & GỬI DUYỆT LẠI", use_container_width=True, type="primary")

                        if submit_update:
                            if not n_hd_in or not n_noi_dung:
                                st.error("❌ Vui lòng điền đủ Số hóa đơn và Địa chỉ!")
                            else:
                                
                                
                                n_tong_tien = calculate_total_amount(n_quang_duong, n_may_lon, n_may_nho)
                                n_tong_combo = n_may_lon + n_may_nho
                                # Chuẩn hóa tiêu đề địa chỉ
                                n_noi_dung_final = f"{n_noi_dung.title().strip()} | (Máy lớn: {n_may_lon}, Máy nhỏ: {n_may_nho})"

                                try:
                                    final_img_data = old_img_base64
                                    
                                    # Chỉ xử lý nếu có ảnh mới
                                    if n_uploaded_file:
                                        img_pil = Image.open(n_uploaded_file)
                                        
                                        # --- BƯỚC TỐI ƯU THÊM: RESIZE ---
                                        max_size = (1024, 1024)
                                        img_pil.thumbnail(max_size, Image.Resampling.LANCZOS)
                                        
                                        if img_pil.mode in ("RGBA", "P"): 
                                            img_pil = img_pil.convert("RGB")
                                        
                                        img_byte_arr = io.BytesIO()
                                        # Nén JPEG 70% là mức hợp lý để cân bằng giữa chất lượng và dung lượng
                                        img_pil.save(img_byte_arr, format='JPEG', quality=70, optimize=True)
                                        final_img_data = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')

                                    # Payload cập nhật (chỉ gửi ảnh nếu nó thay đổi hoặc cần thiết)
                                    update_payload = {
                                        "so_hoa_don": n_hd_in.upper().strip(),
                                        "noi_dung": n_noi_dung_final,
                                        "quang_duong": int(n_quang_duong),
                                        "combo": int(n_tong_combo),
                                        "thanh_tien": float(n_tong_tien),
                                        "hinh_anh": final_img_data,
                                        "trang_thai": 'Chờ duyệt',
                                        "thoi_gian": datetime.now().isoformat(), # Dùng isoformat thay vì định dạng thủ công
                                        "ghi_chu_duyet": '' 
                                    }

                                    supabase.table("cham_cong") \
                                        .update(update_payload) \
                                        .eq("id", row_id) \
                                        .eq("username", current_u) \
                                        .execute()
                                    
                                    # Làm mới Cache để bảng dữ liệu cập nhật ngay lập tức
                                    st.cache_data.clear()
                                    st.session_state.reset_trigger = st.session_state.get('reset_trigger', 0) + 1
                                    st.rerun()
                                                                    
                                except Exception as e:
                                    st.error(f"❌ Lỗi hệ thống: {e}")

        # --- DÀNH CHO ADMIN: ĐẢO NGƯỢC TRẠNG THÁI ---
        if role in ["Admin", "System Admin"]:
            st.divider()
            with st.expander("🔄 Quản lý trạng thái (Hủy duyệt đơn)", expanded=False):
                st.warning("⚠️ **Lưu ý:** Thao tác này đưa đơn về trạng thái 'Chờ duyệt'.")
                
                # Đảm bảo df_all tồn tại và không rỗng
                if "Trạng thái" in df_all.columns:
                    df_undo = df_all[df_all["Trạng thái"] == "Đã duyệt"].copy()
                else:
                    st.error(f"Thiếu cột 'Trạng thái'. Các cột hiện có: {list(df_all.columns)}")
                    df_undo = pd.DataFrame()

                
                if df_undo.empty:
                    st.info("ℹ️ Không có đơn nào 'Đã duyệt' để đảo ngược.")
                else:
                    # Sửa lỗi lấy danh sách Số HĐ
                    list_hd = df_undo["Số HĐ"].astype(str).tolist()
                    sel_undo = st.selectbox("⏪ Chọn Số HĐ:", list_hd, key="undo_select_box_unique")
                    
                    # Lấy dòng dữ liệu được chọn
                    tmp = df_undo[df_undo["Số HĐ"].astype(str) == sel_undo]
                    if tmp.empty:
                        st.error("Không tìm thấy đơn.")
                        st.stop()
                    row_undo_data = tmp.iloc[0]
                    
                    # SỬA LỖI TẠI ĐÂY: Không ép kiểu int thủ công nếu không chắc chắn
                    row_id_undo = row_undo_data["id"] 
                    
                    # Truy vấn ảnh từ Supabase
                    img_base64_undo = None
                    try:
                        # Chỉ lấy cột hinh_anh để tiết kiệm băng thông
                        res_undo = supabase.table("cham_cong").select("hinh_anh").eq("id", row_id_undo).execute()
                        if res_undo.data:
                            img_base64_undo = res_undo.data[0].get("hinh_anh")
                    except Exception as e:
                        st.error(f"Lỗi truy vấn ảnh: {e}")

                    if img_base64_undo:
                        with st.popover(f"🔍 Xem lại ảnh hóa đơn {sel_undo}", use_container_width=True):
                            # Chuẩn hóa Base64 an toàn
                            if isinstance(img_base64_undo, str):
                                if not img_base64_undo.startswith("data:image"):
                                    # Xử lý trường hợp chuỗi base64 thuần
                                    img_display = f"data:image/jpeg;base64,{img_base64_undo}"
                                else:
                                    img_display = img_base64_undo
                                st.image(img_display, use_container_width=True)
                            else:
                                st.warning("Định dạng ảnh không hợp lệ.")
                    
                    reason_undo = st.text_input("📝 Lý do đưa về chờ duyệt:", key="reason_undo_input")
                    
                    if st.button("⏪ XÁC NHẬN ĐẢO NGƯỢC", use_container_width=True, type="primary"):
                        if not reason_undo.strip():
                            st.error("❌ Vui lòng nhập lý do cụ thể!")
                        else:
                            try:
                                admin_name = st.session_state.get("ho_ten", "Admin")
                                # Thêm thời gian vào ghi chú để dễ theo dõi (Audit Log)
                                time_now = datetime.now().strftime("%H:%M %d/%m")
                                new_note = f"[{time_now} - {admin_name}] HỦY DUYỆT: {reason_undo}"
                                
                                supabase.table("cham_cong") \
                                    .update({
                                        "trang_thai": "Chờ duyệt", 
                                        "ghi_chu_duyet": new_note
                                    }) \
                                    .eq("id", row_id_undo) \
                                    .execute()
                                st.cache_data.clear()
                                st.session_state.reset_trigger = st.session_state.get('reset_trigger', 0) + 1
                                st.session_state.toast_message = "✅ Đã chuyển đơn về trạng thái Chờ duyệt thành công!"
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Lỗi khi cập nhật Cloud: {e}")

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
                    res = supabase.table("quan_tri_vien").select("*").execute()
                    df_users = pd.DataFrame(res.data)
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
                                        st.cache_data.clear()
                                        st.session_state.reset_trigger = st.session_state.get('reset_trigger', 0) + 1
                                        st.success(f"✅ Đã cập nhật thành công nhân sự: {final_name}")
                                        
                                        # Kiểm tra nếu admin đang tự sửa chính mình
                                        if target_u == st.session_state.get("username"):
                                            st.session_state.toast_message = "💡 Bạn vừa cập nhật thông tin cá nhân. Hãy tải lại trang để thấy thay đổi."
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
                                    st.session_state.toast_message = f"Đã thêm '{clean_name}'"
                                    st.rerun()
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
                                        
                                        st.session_state.toast_message = f"✅ Đã tạo thành công tài khoản cho {n_ten} trên hệ thống Cloud!"
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
                            elif u_selected['role'] == 'System Admin' and u_selected['username'] == 'admin':
                                st.error("❌ **Lỗi bảo mật:** Không thể xóa tài khoản của người phát triển hệ thống!")
                            else:
                                try:
                                    # Thực hiện lệnh DELETE trên Supabase
                                    supabase.table("quan_tri_vien") \
                                        .delete() \
                                        .eq("username", u_selected['username']) \
                                        .execute()
                                    
                                    st.session_state.toast_message = f"💥 Đã xóa thành công tài khoản: {u_selected['username']} trên Cloud!"
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
                        data_response = load_data(st.session_state.get('reset_trigger', 0))
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
                            
                            st.session_state.toast_message = "💥 Đã dọn dẹp dữ liệu trên Cloud thành công!"
                            st.rerun()
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
                                res = supabase.table("quan_tri_vien") \
                                    .select("password") \
                                    .eq("username", current_user) \
                                    .execute()
                                
                                if res.data and res.data[0].get("password") == pw_old_hashed:
                                    # 3. Mã hóa mật khẩu mới
                                    pw_new_hashed = hashlib.sha256(p_new.encode()).hexdigest()
                                    
                                    # 4. Cập nhật mật khẩu mới lên Cloud
                                    supabase.table("quan_tri_vien") \
                                        .update({"password": pw_new_hashed}) \
                                        .eq("username", current_user) \
                                        .execute()
                                    st.cache_data.clear()
                                    st.session_state.reset_trigger = st.session_state.get('reset_trigger', 0) + 1
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
