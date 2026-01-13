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
import calendar 
import pytz


st.set_page_config(
    page_title="Đại Thành - Ứng Dụng Nội Bộ",
    layout="wide"
)

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

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
def register_user(username, password):
    supabase.table("users").insert({
        "username": username,
        "password": hash_password(password)
    }).execute()

# hàm logo
def get_base64_of_bin_file(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()

def display_logo(logo_path):
    if os.path.exists(logo_path):
        binary_data = get_base64_of_bin_file(logo_path)
        st.markdown(
            f"""
            <div style="text-align: center;">
                <img src="data:image/png;base64,{binary_data}" width="150">
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

if not cookies.ready():
    st.stop()

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
# ========================
# SECTION 6. AUTO LOGIN (CẬP NHẬT AN TOÀN)
# ========================

# Chỉ tự động đăng nhập nếu Session chưa được xác thực
if not st.session_state.get("authenticated", False):
    saved_user = cookies.get("saved_user")
    
    # Kiểm tra kỹ: cookie phải tồn tại, không rỗng, và không phải 'None' (chuỗi)
    if saved_user and saved_user != "None" and saved_user != "": 
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
            remember_me = st.checkbox("Ghi nhớ đăng nhập (30 ngày)")
            
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
                        cookies["saved_user"] = res.get("username")
                        cookies.save()

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
    df['thoi_gian'] = pd.to_datetime(df['thoi_gian'])
    
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
                
            # Sử dụng múi giờ Việt Nam
            now = datetime.now()
            today_str = now.strftime("%Y-%m-%d")
            current_month = now.strftime("%Y-%m") 
            display_month = now.strftime("%m/%Y")

            try:
                # 1. Kiểm tra trạng thái hôm nay trên Supabase thay cho SQLite
                # Sử dụng gte (lớn hơn hoặc bằng) và lt (nhỏ hơn) để lọc chính xác ngày hôm nay
                res = supabase.table("cham_cong_di_lam") \
                    .select("trang_thai_lam") \
                    .eq("username", user) \
                    .gte("thoi_gian", f"{today_str} 00:00:00") \
                    .lte("thoi_gian", f"{today_str} 23:59:59") \
                    .execute()
                
                df_today = pd.DataFrame(res.data)
                
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

    # =========================================================
    # TAB 3 – ĐĂNG KÝ LỊCH NGHỈ (TẤT CẢ USER ĐỀU VÀO ĐƯỢC)
    # =========================================================
    with tabs[-1]:

        with st.expander("🔍 Xem lịch nghỉ chi tiết trong tháng", expanded=True):
            # --- KHU VỰC GHI CHÚ (LEGEND) ---
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
            """, unsafe_allow_html =True)
            try:
                # SỬA 1: Lấy tất cả trừ đơn bị từ chối (Lấy đơn Đã duyệt và Chờ duyệt)
                res_nghi = supabase.table("dang_ky_nghi").select("*").neq("trang_thai", "Bị từ chối").execute()
                
                if res_nghi.data:
                    df_all = pd.DataFrame(res_nghi.data)
                    df_all['ngay_nghi'] = pd.to_datetime(df_all['ngay_nghi'])
                    
                    today = date.today()
                    curr_month, curr_year = today.month, today.year
                    last_day = calendar.monthrange(curr_year, curr_month)[1]
                    all_days = list(range(1, last_day + 1))
                    
                    df_month = df_all[(df_all['ngay_nghi'].dt.month == curr_month) & (df_all['ngay_nghi'].dt.year == curr_year)].copy()
                    
                    if not df_month.empty:
                        df_month['Ngày'] = df_month['ngay_nghi'].dt.day
                        
                        # SỬA 2: Hàm map_symbol nhận vào cả dòng dữ liệu (Series)
                        def map_symbol(row):
                            symbol = ""
                            if row['buoi_nghi'] == "Cả ngày": symbol = "OFF"
                            elif row['buoi_nghi'] == "Sáng": symbol = "1/2S"
                            elif row['buoi_nghi'] == "Chiều": symbol = "1/2C"
                            
                            # Hiển thị dấu ngoặc đơn nếu đơn vẫn đang chờ duyệt
                            if row['trang_thai'] == "Chờ duyệt":
                                return f"({symbol})" 
                            return symbol

                        # SỬA 3: Pivot Table truyền toàn bộ dòng vào aggfunc
                        # Để map_symbol truy cập được 'buoi_nghi' và 'trang_thai'
                        pivot_nghi = df_month.pivot_table(
                            index='ho_ten',
                            columns='Ngày',
                            # Không chỉ lấy values='buoi_nghi' mà để pivot xử lý trên dataframe
                            aggfunc=lambda x: map_symbol(df_month.loc[x.index[0]]) if not x.empty else ""
                        )['buoi_nghi'] # Lấy kết quả cột buoi_nghi sau khi đã map
                        
                        for d in all_days:
                            if d not in pivot_nghi.columns: pivot_nghi[d] = ""
                        
                        pivot_nghi = pivot_nghi[all_days].fillna("")
                        pivot_nghi.index.name = "Họ và Tên"

                        def style_leave(val):
                            if 'OFF' in str(val): return 'background-color: #ff4b4b; color: white'
                            if '1/2S' in str(val) or '1/2C' in str(val): return 'background-color: #ffa500; color: white'
                            return ''

                        st.dataframe(pivot_nghi.style.applymap(style_leave), use_container_width=True)
                    else:
                        st.info("Chưa có dữ liệu nghỉ tháng này.")
            except Exception as e:
                st.error(f"Lỗi tải lịch: {e}")

        st.divider()

        # 2. KHU VỰC USER – ĐĂNG KÝ + LỊCH SỬ
        if role != "System Admin":
            with st.expander("✨ Đăng ký & Theo dõi lịch nghỉ", expanded=True):
                col_left, col_right = st.columns([2, 3])

                with col_left:
                    st.markdown("#### 📝 Tạo đơn mới")
                    
                    # 1. Đưa Selectbox ra ngoài form để giao diện phản ứng tức thì khi chọn "Khác"
                    reason_main = st.selectbox("Lý do nghỉ", ["Nghỉ phép", "Việc nhà", "Nghỉ không phép", "Khác"])
                    
                    # 2. Chỉ hiện ô nhập văn bản khi chọn "Khác"
                    other_reason = ""
                    if reason_main == "Khác":
                        other_reason = st.text_input("👉 Vui lòng ghi rõ lý do:", placeholder="Nhập lý do của bạn tại đây...")

                    if "pending_nghi" not in st.session_state:
                        st.session_state.pending_nghi = None

                    with st.form("form_dang_ky_nghi_vertical", clear_on_submit=True):
                        # Mặc định gợi ý quy tắc nghỉ trước 24h
                        range_date = st.date_input("Khoảng thời gian nghỉ", 
                                                value=(date.today() + timedelta(days=1), date.today() + timedelta(days=1)), 
                                                format="DD/MM/YYYY")
                        session_off = st.selectbox("Buổi nghỉ", ["Cả ngày", "Sáng", "Chiều"])
                        special_request = st.checkbox("Gửi thông báo đặc biệt (Nghỉ quá 2 ngày/tháng hoặc lý do khẩn cấp)")
                        
                        submit = st.form_submit_button("GỬI ĐƠN", use_container_width=True, type="primary")

                        if submit:
                            # 3. Xử lý logic gộp lý do chi tiết
                            final_reason = reason_main
                            if reason_main == "Khác":
                                if not other_reason.strip():
                                    st.error("⚠️ Bạn đã chọn 'Khác', vui lòng nhập lý do chi tiết ở ô phía trên!")
                                    st.stop()
                                final_reason = other_reason.strip()
                            
                            # Gán nhãn đặc biệt nếu được tích chọn
                            if special_request:
                                final_reason = f"[ĐẶC BIỆT] {final_reason}"

                            if not isinstance(range_date, tuple) or len(range_date) != 2:
                                st.error("Vui lòng chọn đủ ngày bắt đầu và kết thúc!")
                            else:
                                start_date, end_date = range_date
                                now = datetime.now()
                                
                                # Kiểm tra đăng ký trước 24h (00:00 ngày nghỉ so với hiện tại)
                                start_datetime = datetime.combine(start_date, dt_module.time.min)
                                if start_datetime < now + timedelta(hours=24):
                                    st.error("❌ Bạn phải đăng ký nghỉ tối thiểu trước 24h!")
                                else:
                                    try:
                                        # 4. Truy vấn loại trừ các đơn "Bị từ chối" để cho phép đăng ký lại
                                        res_check = supabase.table("dang_ky_nghi").select("*")\
                                            .neq("trang_thai", "Bị từ chối")\
                                            .execute()
                                        df_check = pd.DataFrame(res_check.data) if res_check.data else pd.DataFrame()

                                        # Kiểm tra giới hạn 2 ngày/tháng
                                        month_now, year_now = start_date.month, start_date.year
                                        user_days_this_month = 0
                                        if not df_check.empty:
                                            user_month_data = df_check[
                                                (df_check['username'] == st.session_state.username) & 
                                                (pd.to_datetime(df_check['ngay_nghi']).dt.month == month_now) &
                                                (pd.to_datetime(df_check['ngay_nghi']).dt.year == year_now)
                                            ]
                                            user_days_this_month = len(user_month_data)

                                        data_to_insert, data_to_update = [], []
                                        error_overlap_colleague, own_overlap_days = [], []
                                        error_sunday = []
                                        
                                        num_new_days = (end_date - start_date).days + 1

                                        for i in range(num_new_days):
                                            curr_day = start_date + timedelta(days=i)
                                            curr_day_str = curr_day.isoformat()

                                            if not df_check.empty:
                                                # Kiểm tra trùng chính mình (chỉ tính đơn chưa bị từ chối)
                                                own = df_check[(df_check['ngay_nghi'] == curr_day_str) & (df_check['username'] == st.session_state.username)]
                                                if not own.empty:
                                                    own_overlap_days.append(curr_day.strftime('%d/%m/%Y'))
                                                    data_to_update.append({
                                                        "id": own.iloc[0]['id'], 
                                                        "buoi_nghi": session_off, 
                                                        "ly_do": final_reason, # Dùng lý do mới
                                                        "trang_thai": "Chờ duyệt"
                                                    })
                                                    continue 

                                                # Kiểm tra trùng đồng nghiệp
                                                colleague = df_check[(df_check['ngay_nghi'] == curr_day_str) & 
                                                                    (df_check['nhom'] == st.session_state.chuc_danh) & 
                                                                    (df_check['username'] != st.session_state.username)]
                                                if not colleague.empty:
                                                    error_overlap_colleague.append(f"{curr_day.strftime('%d/%m/%Y')} ({', '.join(colleague['ho_ten'].tolist())})")

                                            data_to_insert.append({
                                                "username": st.session_state.username, 
                                                "ho_ten": st.session_state.ho_ten, 
                                                "nhom": st.session_state.chuc_danh, 
                                                "ngay_nghi": curr_day_str, 
                                                "buoi_nghi": session_off, 
                                                "ly_do": final_reason, 
                                                "trang_thai": "Chờ duyệt"
                                            })

                                        # Hiển thị lỗi theo thứ tự ưu tiên
                                        
                                        if (user_days_this_month + num_new_days) > 2 and not special_request:
                                            st.error(f"❌ Bạn đã nghỉ {user_days_this_month} ngày. Hãy tích chọn 'Thông báo đặc biệt' để đăng ký thêm.")
                                        elif error_overlap_colleague:
                                            st.error(f"❌ Trùng lịch nhóm {st.session_state.chuc_danh}: {', '.join(error_overlap_colleague)}")
                                        elif own_overlap_days:
                                            st.session_state.pending_nghi = {"days": own_overlap_days, "to_update": data_to_update, "to_insert": data_to_insert}
                                        else:
                                            if data_to_insert:
                                                supabase.table("dang_ky_nghi").insert(data_to_insert).execute()
                                                st.success("✅ Gửi đơn thành công!")
                                                time.sleep(1)
                                                st.rerun()
                                    except Exception as e:
                                        st.error(f"Lỗi: {e}")

                    # XỬ LÝ CẬP NHẬT TRÙNG LỊCH
                    if st.session_state.pending_nghi:
                        pending = st.session_state.pending_nghi
                        st.warning(f"🔔 Bạn đã có lịch nghỉ vào ngày: {', '.join(pending['days'])}. Cập nhật lại?")
                        c_u1, c_u2 = st.columns(2)
                        if c_u1.button("🔄 Cập nhật", use_container_width=True, type="primary"):
                            for item in pending['to_update']:
                                id_up = item.pop('id')
                                # Thêm prefix đặc biệt nếu có tích chọn
                                if special_request: item['ly_do'] = f"[ĐẶC BIỆT] {item['ly_do']}"
                                supabase.table("dang_ky_nghi").update(item).eq("id", id_up).execute()
                            if pending['to_insert']:
                                supabase.table("dang_ky_nghi").insert(pending['to_insert']).execute()
                            st.session_state.pending_nghi = None
                            st.success("✅ Đã cập nhật!")
                            time.sleep(1)
                            st.rerun()
                        if c_u2.button("❌ Hủy", use_container_width=True):
                            st.session_state.pending_nghi = None
                            st.rerun()

                # --- PHÍA BÊN PHẢI: LỊCH SỬ ĐƠN (GOM NHÓM) ---
                with col_right:
                    st.markdown("#### 🕒 Lịch sử đơn của bạn")
                    
                    res_history = supabase.table("dang_ky_nghi")\
                        .select("*")\
                        .eq("username", st.session_state.username)\
                        .order("ngay_nghi", desc=True).execute()

                    if res_history.data:
                        df_hist = pd.DataFrame(res_history.data)
                        df_hist['ngay_nghi'] = pd.to_datetime(df_hist['ngay_nghi'])
                        
                        # Logic gom nhóm các ngày liên tiếp có cùng trạng thái và lý do
                        df_hist = df_hist.sort_values(by='ngay_nghi')
                        groups = []
                        if not df_hist.empty:
                            current_group = [df_hist.iloc[0]]
                            for i in range(1, len(df_hist)):
                                prev = df_hist.iloc[i-1]
                                curr = df_hist.iloc[i]
                                
                                # Nếu ngày liên tiếp và cùng trạng thái/buổi nghỉ/lý do -> Gom nhóm
                                diff = (curr['ngay_nghi'] - prev['ngay_nghi']).days
                                if diff == 1 and curr['trang_thai'] == prev['trang_thai'] and curr['buoi_nghi'] == prev['buoi_nghi']:
                                    current_group.append(curr)
                                else:
                                    groups.append(current_group)
                                    current_group = [curr]
                            groups.append(current_group)

                        # Hiển thị lịch sử đã gom nhóm
                        for g in reversed(groups): # Hiện mới nhất lên đầu
                            start_g = g[0]['ngay_nghi'].strftime('%d/%m/%Y')
                            end_g = g[-1]['ngay_nghi'].strftime('%d/%m/%Y')
                            total_days = len(g)
                            status = g[0]['trang_thai']
                            buoi = g[0]['buoi_nghi']
                            
                            # Chọn màu sắc cho trạng thái
                            color = "#ffa500" if status == "Chờ duyệt" else "#28a745"
                            if status == "Bị từ chối": color = "#dc3545"

                            with st.container(border=True):
                                col1, col2 = st.columns([3, 1])
                                with col1:
                                    if total_days > 1:
                                        st.markdown(f"📅 **{start_g} - {end_g}** ({total_days} ngày)")
                                    else:
                                        st.markdown(f"📅 **{start_g}**")
                                    st.caption(f"Buổi: {buoi} | Lý do: {g[0]['ly_do']}")
                                with col2:
                                    st.markdown(f"<span style='color:{color}; font-weight:bold;'>{status}</span>", unsafe_allow_html=True)
                    else:
                        st.info("Bạn chưa có lịch sử đăng ký nào.")

        # 3. KHU VỰC SYSTEM ADMIN – PHÊ DUYỆT + LỊCH SỬ
        if role == "System Admin":
            with st.expander("🛠️ Phê duyệt & Quản lý đơn nghỉ", expanded=True):
                # --- TRONG KHU VỰC 3: PHÊ DUYỆT & QUẢN LÝ ---
                res = supabase.table("dang_ky_nghi").select("*").eq("trang_thai", "Chờ duyệt").order("ho_ten").order("ngay_nghi").execute()

                if res.data:
                    df_raw = pd.DataFrame(res.data)
                    df_raw['ngay_nghi'] = pd.to_datetime(df_raw['ngay_nghi'])
                    
                    # --- LOGIC GOM NHÓM ĐƠN ĐỂ HIỂN THỊ ---
                    grouped_data = []
                    if not df_raw.empty:
                        # Nhóm theo User, Lý do và Buổi nghỉ trước
                        for (uname, name, reason, session, role_name), group in df_raw.groupby(['username', 'ho_ten', 'ly_do', 'buoi_nghi', 'nhom']):
                            group = group.sort_values('ngay_nghi')
                            
                            # Kiểm tra tính liên tiếp của ngày
                            start_date = None
                            prev_date = None
                            ids_in_group = []

                            for index, row in group.iterrows():
                                curr_date = row['ngay_nghi']
                                
                                if start_date is None:
                                    start_date = curr_date
                                    ids_in_group = [row['id']]
                                elif (curr_date - prev_date).days == 1:
                                    ids_in_group.append(row['id'])
                                else:
                                    # Kết thúc một đợt, lưu lại và bắt đầu đợt mới
                                    grouped_data.append({
                                        "username": uname,
                                        "Họ và Tên": name,
                                        "Chức danh": role_name,
                                        "Từ ngày": start_date.strftime('%d/%m/%Y'),
                                        "Đến ngày": prev_date.strftime('%d/%m/%Y'),
                                        "Tổng ngày": len(ids_in_group),
                                        "Buổi nghỉ": session,
                                        "Lý do đăng ký": reason,
                                        "ids": ids_in_group # Lưu lại danh sách ID để xử lý hàng loạt
                                    })
                                    start_date = curr_date
                                    ids_in_group = [row['id']]
                                prev_date = curr_date
                            
                            # Thêm đợt cuối cùng
                            grouped_data.append({
                                "username": uname,
                                "Họ và Tên": name,
                                "Chức danh": role_name,
                                "Từ ngày": start_date.strftime('%d/%m/%Y'),
                                "Đến ngày": prev_date.strftime('%d/%m/%Y'),
                                "Tổng ngày": len(ids_in_group),
                                "Buổi nghỉ": session,
                                "Lý do đăng ký": reason,
                                "ids": ids_in_group
                            })

                    df_display = pd.DataFrame(grouped_data)

                    st.write("📌 *Chọn các đợt nghỉ cần xử lý:*")
                    event = st.dataframe(
                        df_display.drop(columns=['ids']), # Ẩn cột IDs bí mật
                        use_container_width=True,
                        hide_index=True,
                        on_select="rerun",
                        selection_mode="multi-row" # Đảm bảo dùng dấu gạch nối
                    )

                    selected_indices = event.selection.rows
                    
                    if selected_indices:
                        st.divider()
                        col_form, col_history = st.columns([2, 3])
                        
                        # Lấy toàn bộ danh sách ID thực tế từ các hàng được chọn
                        all_selected_ids = []
                        for idx in selected_indices:
                            all_selected_ids.extend(df_display.iloc[idx]['ids'])
                            
                        first_selection = df_display.iloc[selected_indices[0]]

                        # --- PHÍA BÊN TRÁI: FORM XỬ LÝ CHIỀU DỌC ---
                        with col_form:
                            st.markdown(f"#### 📝 Xử lý đơn cho: **{first_selection['Họ và Tên']}**")
                            reason_reject = st.text_area("Lý do từ chối (nếu có):", key="admin_reject_reason")
                            
                            c1, c2 = st.columns(2)
                            with c1:
                                if st.button("✅ Xác nhận duyệt", type="primary", use_container_width=True):
                                    # Xử lý update cho tất cả ID đã gom nhóm
                                    supabase.table("dang_ky_nghi").update({"trang_thai": "Đã duyệt"}).in_("id", all_selected_ids).execute()
                                    st.success("Đã duyệt thành công!")
                                    st.rerun()

                            with c2:
                                if st.button("❌ Từ chối đơn", use_container_width=True):
                                    if not reason_reject:
                                        st.error("⚠️ Vui lòng nhập lý do!")
                                    else:
                                        supabase.table("dang_ky_nghi").update({
                                            "trang_thai": "Bị từ chối",
                                            "ly_do_tu_choi": reason_reject
                                        }).in_("id", all_selected_ids).execute()
                                        st.warning("Đã từ chối đơn.")
                                        st.rerun()

                        # --- PHÍA BÊN PHẢI: XEM LỊCH SỬ NHÂN VIÊN ĐƯỢC CHỌN ---
                        with col_history:
                            st.markdown(f"#### 🕒 Lịch sử tóm tắt: **{first_selection['Họ và Tên']}**")
                            
                            # Truy vấn dữ liệu lịch sử của nhân viên
                            history_res = supabase.table("dang_ky_nghi")\
                                .select("ngay_nghi, trang_thai, ly_do_tu_choi, buoi_nghi, ly_do")\
                                .eq("username", first_selection['username'])\
                                .order("ngay_nghi", desc=False).execute() # Sắp xếp tăng dần để gom nhóm
                            
                            if history_res.data:
                                h_df = pd.DataFrame(history_res.data)
                                h_df['ngay_nghi'] = pd.to_datetime(h_df['ngay_nghi'])
                                
                                # --- LOGIC GOM NHÓM NGÀY LIÊN TIẾP ---
                                groups = []
                                if not h_df.empty:
                                    current_group = [h_df.iloc[0]]
                                    for i in range(1, len(h_df)):
                                        prev = h_df.iloc[i-1]
                                        curr = h_df.iloc[i]
                                        
                                        # Điều kiện gom nhóm: Ngày liên tiếp + Cùng trạng thái + Cùng buổi + Cùng lý do
                                        diff = (curr['ngay_nghi'] - prev['ngay_nghi']).days
                                        if diff == 1 and curr['trang_thai'] == prev['trang_thai'] and \
                                        curr['buoi_nghi'] == prev['buoi_nghi'] and curr['ly_do'] == prev['ly_do']:
                                            current_group.append(curr)
                                        else:
                                            groups.append(current_group)
                                            current_group = [curr]
                                    groups.append(current_group)

                                # Hiển thị kết quả (Đảo ngược danh sách để đơn mới nhất lên đầu)
                                for group in reversed(groups):
                                    start_d = group[0]['ngay_nghi'].strftime('%d/%m/%Y')
                                    end_d = group[-1]['ngay_nghi'].strftime('%d/%m/%Y')
                                    count = len(group)
                                    status = group[0]['trang_thai']
                                    buoi = group[0]['buoi_nghi']
                                    ly_do = group[0]['ly_do']
                                    phan_hoi = group[0].get('ly_do_tu_choi') or "---"

                                    # Xác định màu sắc trạng thái
                                    status_color = "#ffa500" if status == "Chờ duyệt" else "#28a745"
                                    if status == "Bị từ chối": status_color = "#dc3545"

                                    # Hiển thị từng đợt nghỉ trong một Container gọn gàng
                                    with st.container(border=True):
                                        c1, c2 = st.columns([3, 1])
                                        with c1:
                                            if count > 1:
                                                st.markdown(f"📅 **{start_d} - {end_d}**")
                                                st.caption(f"Tổng cộng: **{count} ngày** ({buoi})")
                                            else:
                                                st.markdown(f"📅 **{start_d}** ({buoi})")
                                            st.markdown(f"**Lý do:** {ly_do}")
                                            if status == "Bị từ chối":
                                                st.caption(f"💬 Phản hồi: {phan_hoi}")
                                        with c2:
                                            st.markdown(f"<div style='text-align:right; color:{status_color}; font-weight:bold; padding-top:10px;'>{status}</div>", unsafe_allow_html=True)
                            else:
                                st.info("Nhân viên này chưa có lịch sử đăng ký.")
                else:
                    st.info("Hiện tại không có đơn nào cần xử lý.") 
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
                        res = supabase.table("cham_cong").insert(data_insert).execute()
                        
                        if res.data:
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
    if role in ["Admin", "System Admin", "Manager","User"]:
        with tabs[1]:
            st.markdown("#### 📋 Danh sách đơn chờ duyệt")
            
            try:
                # 1. Truy vấn đơn hàng 'Chờ duyệt' và JOIN lấy ho_ten từ bảng quan_tri_vien
                res = supabase.table("cham_cong") \
                    .select("*, quan_tri_vien(ho_ten)") \
                    .eq("trang_thai", "Chờ duyệt") \
                
                if role not in ["Admin", "System Admin", "Manager"]:
                    res = res.eq("username", user_hien_tai)
                # 3. Sắp xếp và thực thi gửi lệnh lên Server
                res = res.order("thoi_gian", desc=False).execute()
                df_p = pd.DataFrame(res.data)
                
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
                    # 1. Chuyển đổi chuỗi thời gian sang kiểu datetime
                    dt_raw = pd.to_datetime(r['thoi_gian'])

                    # 2. Xử lý múi giờ Việt Nam (UTC sang Asia/Ho_Chi_Minh)
                    try:
                        # Nếu dữ liệu đã có múi giờ (tz-aware)
                        if dt_raw.tz is not None:
                            dt_vn = dt_raw.tz_convert('Asia/Ho_Chi_Minh')
                        else:
                            # Nếu dữ liệu chưa có múi giờ, coi như là UTC rồi chuyển sang VN
                            dt_vn = dt_raw.tz_localize('UTC').tz_convert('Asia/Ho_Chi_Minh')
                    except:
                        # Fallback: Nếu lỗi múi giờ, cộng thủ công 7 tiếng
                        dt_vn = dt_raw + pd.Timedelta(hours=7)

                    # 3. Định dạng chuỗi hiển thị
                    time_display = dt_vn.strftime('%d/%m/%Y %H:%M')

                    # 4. Đưa vào tiêu đề Expander
                    expander_title = f"📦 HĐ: {r['so_hoa_don']} — 👤 {r['ho_ten_nv']} — 🕒 {time_display}"
                    
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
                                                    st.toast("🔴 Đã từ chối đơn ")
                                                    time.sleep(0.5)
                                                    st.rerun()
                            elif user_hien_tai:
                                # 2. QUYỀN USER (CHỦ ĐƠN): Cho phép xem thông tin đơn đang chờ
                                if r["trang_thai"] == "Chờ duyệt":
                                    st.warning("⏳ Đơn đang trong trạng thái chờ Kế toán phê duyệt.")
                                elif r["trang_thai"] == "Từ chối":
                                    st.error(f"❌ Đơn bị từ chối. Lý do: {r.get('ghi_chu_duyet', 'Không có lý do cụ thể')}")
                                else:
                                    st.success("✅ Đơn đã được duyệt thành công.")
                            else:
                                # Nếu là Manager (Chỉ xem, không có quyền duyệt tiền)
                                st.info("ℹ️ Bạn chỉ có thể xem đơn. Quyền Duyệt/Từ chối thuộc về Kế toán.")
                                    
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
            res = supabase.table("cham_cong") \
                .select("*, quan_tri_vien(ho_ten)") \
                .execute()
            
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
                                # --- HIỂN THỊ METRIC TỔNG THU NHẬP ---
                                c_met, c_exp = st.columns([2, 1])
                                rev_sum = df_display[df_display["Trạng thái"] == "Đã duyệt"]["Thành tiền"].sum()
                                c_met.metric("💰 Tổng thu nhập đã duyệt", f"{rev_sum:,.0f} VNĐ")
                                
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

                                # --- 🚀 LOGIC PHÂN TRANG (PAGINATION) ---
                                items_per_page = 10
                                total_rows = len(df_final)
                                total_pages = (total_rows // items_per_page) + (1 if total_rows % items_per_page > 0 else 0)

                                # Khởi tạo hoặc kiểm tra session_state cho phân trang
                                if 'current_page' not in st.session_state:
                                    st.session_state.current_page = 1
                                
                                # Đảm bảo trang hiện tại không vượt quá tổng số trang sau khi lọc
                                if st.session_state.current_page > total_pages:
                                    st.session_state.current_page = max(1, total_pages)

                                # Cắt dữ liệu hiển thị theo trang
                                start_idx = (st.session_state.current_page - 1) * items_per_page
                                end_idx = start_idx + items_per_page
                                df_page = df_final.iloc[start_idx:end_idx]

                                # Hiển thị bảng (Chỉ 10 dòng)
                                #st.dataframe(df_page, use_container_width=True, hide_index=True)
                                # --- CHỈ SYSTEM ADMIN MỚI THẤY CỘT CHỌN XÓA ---
                                is_admin = st.session_state.get("role") == "System Admin"

                                if is_admin:
                                    # Thêm cột checkbox vào đầu bảng (mặc định là False)
                                    df_page.insert(0, "🗑️", False)
                                    
                                    # Sử dụng data_editor để có thể tích chọn
                                    edited_df = st.data_editor(
                                        df_page,
                                        use_container_width=True,
                                        hide_index=True,
                                        disabled=[c for c in df_page.columns if c != "🗑️"], # Chỉ cho phép sửa cột checkbox
                                        key="editor_delete_table"
                                    )

                                    # Lọc ra các dòng được tích chọn xóa
                                    rows_to_delete = edited_df[edited_df["🗑️"] == True]
                                    
                                    if not rows_to_delete.empty:
                                        st.warning(f"⚠️ Đang chọn {len(rows_to_delete)} đơn để xóa.")
                                        if st.button("🔥 XÁC NHẬN XÓA VĨNH VIỄN", type="primary", use_container_width=True):
                                            try:
                                                # Chú ý: Nếu bảng hiển thị đã đổi tên cột thành "Số HĐ", 
                                                # bạn phải dùng rows_to_delete["Số HĐ"]
                                                list_so_hd = rows_to_delete["Số HĐ"].tolist() 
                                                
                                                for hd_id in list_so_hd:
                                                    # Sửa 'value' thành 'hd_id' để khớp với biến vòng lặp
                                                    response = supabase.table("cham_cong").delete().eq("so_hoa_don", hd_id).execute()                                                
                                                
                                                st.success("✅ Đã xóa các đơn được chọn thành công!")
                                                time.sleep(1)
                                                st.rerun()
                                            except Exception as e:
                                                st.error(f"Lỗi khi xóa: {e}")
                                else:
                                    # Nếu không phải admin, hiển thị bảng xem thông thường
                                    st.dataframe(df_page, use_container_width=True, hide_index=True)
                                # --- BỘ CHUYỂN TRANG ---
                            
                                if total_pages > 1:
                                    st.write("") 
                                    
                                    # CSS để ép các cột không bị nhảy dòng trên điện thoại
                                    st.markdown("""
                                        <style>
                                        [data-testid="column"] {
                                            width: calc(33.3333% - 1rem) !important;
                                            flex: 1 1 calc(33.3333% - 1rem) !important;
                                            min-width: calc(33.3333% - 1rem) !important;
                                        }
                                        </style>
                                        """, unsafe_allow_html=True)

                                    # Sử dụng gap="extra_small" để tiết kiệm diện tích tối đa
                                    page_col1, page_col2, page_col3 = st.columns([1, 1, 1], gap="small")
                                    
                                    with page_col1:
                                        if st.button("⬅️ Trước", use_container_width=True, disabled=(st.session_state.current_page == 1)):
                                            st.session_state.current_page -= 1
                                            st.rerun()

                                    with page_col2:
                                        # Căn chỉnh số trang nằm giữa và ngang hàng với nút
                                        st.markdown(
                                            f"""
                                            <div style='text-align: center; line-height: 40px; font-weight: bold; font-size: 14px; white-space: nowrap;'>
                                                {st.session_state.current_page} / {total_pages}
                                            </div>
                                            """, 
                                            unsafe_allow_html=True
                                        )
                                    
                                    with page_col3:
                                        if st.button("Sau ➡️", use_container_width=True, disabled=(st.session_state.current_page == total_pages)):
                                            st.session_state.current_page += 1
                                            st.rerun()

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
                                c_exp.download_button(
                                    label="📥 Tải Excel Báo Cáo", 
                                    data=out.getvalue(), 
                                    file_name=f"Bao_Cao_Lap_Dat_{current_user}_{date.today()}.xlsx", 
                                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                    use_container_width=True
                                )
            else:
                st.info("📭 Chưa có dữ liệu đơn nào trong hệ thống.")
        except Exception as e:
            st.error(f"Lỗi tải dữ liệu: {e}")


        # --- 3. QUẢN LÝ ĐƠN HÀNG (SỬA/XÓA/HỦY) ---
        # Lấy thông tin từ Cookie/Session
        user_login = st.session_state.get("username"," ")
        role_login = st.session_state.get("role")

        # --- DÀNH CHO USER & MANAGER: SỬA HOẶC XÓA ĐƠN CỦA CHÍNH MÌNH ---
        if role_login in ["User", "Manager"]:
            with st.expander("🛠️ Cập nhật thông tin đơn", expanded=False):
                st.markdown("""
                **📌 Hướng dẫn trạng thái đơn lắp đặt:**
                - 🟡 **Chờ duyệt:** Đơn đã gửi. Bạn có thể **Sửa** hoặc **Xóa**.
                - 🔴 **Từ chối:** Đơn sai thông tin. Vui lòng **cập nhật lại**.
                - 🟢 **Đã duyệt:** Đơn hợp lệ. **Không thể chỉnh sửa**.
                """)
                    
                # 1. Lọc đơn và đảm bảo kiểu dữ liệu đồng nhất để tránh lỗi lọc
                df_edit = df_all[
                    (df_all["username"] == user_login) & 
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
                                    .eq("username", user_login) \
                                    .eq("trang_thai", "Chờ duyệt") \
                                    .execute()
                                
                                st.success("✅ Đã xóa đơn thành công!")
                                time.sleep(1) # Tăng thời gian chờ để user kịp thấy thông báo
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
                                img_display = old_img_base64
                                if isinstance(img_display, str) and not img_display.startswith("data:image"):
                                    img_display = f"data:image/jpeg;base64,{img_display}"
                                st.image(img_display, use_container_width=True)

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
                                # Logic tính toán đơn giá (Giữ nguyên logic của bạn)
                                if n_quang_duong <= 50:
                                    n_don_gia_km = 30000 if n_quang_duong < 20 else 50000 if n_quang_duong <= 30 else 70000 if n_quang_duong <= 40 else 80000
                                else:
                                    n_don_gia_km = 80000 + (n_quang_duong - 50) * 5000
                                
                                n_tong_tien = (n_may_lon * 200000) + (n_may_nho * n_don_gia_km)
                                n_tong_combo = n_may_lon + n_may_nho
                                # Chuẩn hóa tiêu đề địa chỉ
                                n_noi_dung_final = f"{n_noi_dung.title().strip()} | (Máy lớn: {n_may_lon}, Máy nhỏ: {n_may_nho})"
                                
                                try:
                                    # Xử lý ảnh mới nếu có
                                    final_img_data = old_img_base64
                                    if n_uploaded_file:
                                        img_pil = Image.open(n_uploaded_file)
                                        if img_pil.mode in ("RGBA", "P"): 
                                            img_pil = img_pil.convert("RGB")
                                        
                                        img_byte_arr = io.BytesIO()
                                        img_pil.save(img_byte_arr, format='JPEG', quality=70, optimize=True)
                                        final_img_data = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')

                                    # Payload cập nhật
                                    update_payload = {
                                        "so_hoa_don": n_hd_in.upper().strip(),
                                        "noi_dung": n_noi_dung_final,
                                        "quang_duong": int(n_quang_duong),
                                        "combo": int(n_tong_combo),
                                        "thanh_tien": float(n_tong_tien),
                                        "hinh_anh": final_img_data,
                                        "trang_thai": 'Chờ duyệt',
                                        "thoi_gian": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                        "ghi_chu_duyet": '' # Xóa lý do từ chối cũ khi gửi lại
                                    }

                                    # LƯU Ý: Dùng user_login (biến bạn đã lấy từ session ở đoạn code trước)
                                    supabase.table("cham_cong") \
                                        .update(update_payload) \
                                        .eq("id", row_id) \
                                        .eq("username", user_login) \
                                        .execute()
                                    
                                    st.success("✅ Đã cập nhật và gửi duyệt lại!")
                                    time.sleep(0.8)
                                    st.rerun()
                                    
                                except Exception as e:
                                    st.error(f"❌ Lỗi hệ thống: {e}")

        # --- DÀNH CHO ADMIN: ĐẢO NGƯỢC TRẠNG THÁI ---
        if role in ["Admin", "System Admin"]:
            st.divider()
            with st.expander("🔄 Quản lý trạng thái (Hủy duyệt đơn)", expanded=False):
                st.warning("⚠️ **Lưu ý:** Thao tác này đưa đơn về trạng thái 'Chờ duyệt'.")
                
                # Đảm bảo df_all tồn tại và không rỗng
                df_undo = df_all[df_all["Trạng thái"] == "Đã duyệt"].copy()
                
                if df_undo.empty:
                    st.info("ℹ️ Không có đơn nào 'Đã duyệt' để đảo ngược.")
                else:
                    # Sửa lỗi lấy danh sách Số HĐ
                    list_hd = df_undo["Số HĐ"].astype(str).tolist()
                    sel_undo = st.selectbox("⏪ Chọn Số HĐ:", list_hd, key="undo_select_box_unique")
                    
                    # Lấy dòng dữ liệu được chọn
                    row_undo_data = df_undo[df_undo["Số HĐ"].astype(str) == sel_undo].iloc[0]
                    
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
                                
                                st.success("✅ Đã chuyển đơn về trạng thái Chờ duyệt thành công!")
                                time.sleep(0.5)
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
