import streamlit as st
from supabase import create_client, Client
import pandas as pd
from datetime import datetime, date, time, timedelta
import os
import hashlib
import time
import io
import base64
from PIL import Image
import plotly.express as px
from streamlit_cookies_manager import EncryptedCookieManager
from streamlit_local_storage import LocalStorage
import calendar 
import pytz
import warnings
from sqlalchemy import text

# Tắt cảnh báo không cần thiết
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Cấu hình trang (Phải đặt đầu tiên)
st.set_page_config(
    page_title="Đại Thành - Ứng Dụng Nội Bộ",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS Tùy chỉnh để ẩn header mặc định và làm đẹp giao diện
st.markdown("""
<style>
    [data-testid="stHeader"] {visibility: hidden;}
    .block-container {padding-top: 1rem; padding-bottom: 1rem;}
    /* Tối ưu hiển thị bảng trên mobile */
    [data-testid="stDataFrame"] {width: 100%;}
    /* Style cho các metrics */
    div[data-testid="metric-container"] {
        background-color: #f0f2f6;
        border: 1px solid #dce4ef;
        padding: 10px;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

# Khởi tạo Local Storage
local_storage = LocalStorage()
# ========================
# SECTION 2. SUPABASE & DATA UTILS
# ========================

@st.cache_resource
def get_supabase() -> Client:   
    return create_client(
        st.secrets["SUPABASE_URL"],
        st.secrets["SUPABASE_KEY"]
    )

supabase = get_supabase()

# Hàm băm mật khẩu
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def fast_import_data(df, table_name, if_exists='append'):
    """
    Import dữ liệu tốc độ cao dùng SQL Connection.
    - df: Pandas DataFrame chứa dữ liệu
    - table_name: Tên bảng trong Supabase (vd: 'cham_cong')
    - if_exists: 'append' (nối thêm) hoặc 'replace' (ghi đè - CẨN THẬN!)
    """
    try:
        # 1. Tạo kết nối từ secrets đã cấu hình
        conn = st.connection("supabase_sql", type="sql")
        
        # 2. Sử dụng to_sql của Pandas để đẩy dữ liệu
        # method='multi': Gửi nhiều dòng trong 1 gói tin (nhanh hơn)
        # chunksize=1000: Chia nhỏ mỗi lần gửi 1000 dòng để tránh quá tải
        df.to_sql(
            name=table_name,
            con=conn.engine,
            if_exists=if_exists,
            index=False,
            method='multi', 
            chunksize=1000 
        )
        return True, f"Đã import thành công {len(df)} dòng!"
    except Exception as e:
        return False, f"Lỗi Import: {str(e)}"
# Hàm xử lý ảnh tối ưu: Resize trước khi chuyển Base64
def process_image_to_base64(uploaded_file, quality=60, max_width=1024):
    """Nén và resize ảnh để giảm tải băng thông DB"""
    try:
        if uploaded_file is None: return None
        img = Image.open(uploaded_file)
        
        # Convert sang RGB nếu là RGBA
        if img.mode in ("RGBA", "P"): img = img.convert("RGB")
        
        # Resize nếu ảnh quá lớn (giữ tỷ lệ)
        if img.width > max_width:
            ratio = max_width / float(img.width)
            new_height = int((float(img.height) * float(ratio)))
            img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)

        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality, optimize=True)
        return base64.b64encode(buf.getvalue()).decode('utf-8')
    except Exception as e:
        st.error(f"Lỗi xử lý ảnh: {e}")
        return None

# Cache logo
@st.cache_data
def load_logo_base64(file_path="LOGO.png"):
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            return base64.b64encode(f.read()).decode()
    return None

def display_logo():
    b64 = load_logo_base64()
    if b64:
        st.markdown(f"""
            <div style="text-align: center; margin-bottom: 20px;">
                <img src="data:image/png;base64,{b64}" width="120" style="border-radius: 10px;">
            </div>
            """, unsafe_allow_html=True)

# --- CÁC HÀM FETCH DỮ LIỆU TỐI ƯU ---

@st.cache_data(ttl=60) # Cache 1 phút
def get_user_info(username):
    """Lấy thông tin user, dùng cache để đỡ gọi DB nhiều lần"""
    try:
        res = supabase.table("quan_tri_vien").select("*").eq("username", username).execute()
        return res.data[0] if res.data else None
    except:
        return None

# Tối ưu: Chỉ lấy dữ liệu trong khoảng thời gian cần thiết (Server-side filtering)
@st.cache_data(ttl=300)
def fetch_cham_cong_lap_dat(start_date=None, end_date=None, username=None):
    query = supabase.table("cham_cong").select("*, quan_tri_vien(ho_ten)")
    
    if username:
        query = query.eq("username", username)
    
    # Lọc theo ngày ngay tại server nếu có
    if start_date and end_date:
        query = query.gte("thoi_gian", f"{start_date} 00:00:00").lte("thoi_gian", f"{end_date} 23:59:59")
    
    # Giới hạn 500 dòng mới nhất để tránh crash app
    res = query.order("thoi_gian", desc=True).limit(500).execute()
    
    if res.data:
        df = pd.DataFrame(res.data)
        # Flatten cột quan_tri_vien
        df['ho_ten_nv'] = df['quan_tri_vien'].apply(lambda x: x.get('ho_ten') if x else "N/A")
        return df
    return pd.DataFrame()
# ========================
# SECTION 3. AUTH & SESSION
# ========================

# Khởi tạo Session State mặc định
DEFAULT_SESSION = {
    "authenticated": False,
    "username": "",
    "role": "",
    "chuc_danh": "",
    "ho_ten": "",
    "toast_message": None,
    "reset_trigger": 0
}

for k, v in DEFAULT_SESSION.items():
    if k not in st.session_state:
        st.session_state[k] = v

# Xử lý Toast Message (Thông báo nổi)
if st.session_state.toast_message:
    st.toast(st.session_state.toast_message)
    st.session_state.toast_message = None

# Cookie Manager
cookies = EncryptedCookieManager(
    prefix="daithanh/",
    password=st.secrets["COOKIE_PASSWORD"]
)

if not cookies.ready():
    st.stop()

def check_login(username, password):
    try:
        u_clean = username.lower().strip()
        p_hash = hash_password(password)
        
        # Tìm user
        user = get_user_info(u_clean) # Dùng hàm cached
        
        if user:
            # Kiểm tra pass (hỗ trợ tự động hash pass cũ)
            if user.get("password") == p_hash:
                return user
            elif user.get("password") == password: # Nếu pass chưa hash
                supabase.table("quan_tri_vien").update({"password": p_hash}).eq("username", u_clean).execute()
                return user
        return None
    except Exception as e:
        st.error(f"Lỗi đăng nhập: {e}")
        return None

# --- LOGIC AUTO LOGIN ---
if not st.session_state.authenticated:
    # Ưu tiên 1: LocalStorage (nhanh hơn)
    saved_user = local_storage.getItem("backup_saved_user")
    
    # Ưu tiên 2: Cookie
    if not saved_user or saved_user == "null":
        saved_user = cookies.get("saved_user")
        
    if saved_user and saved_user not in ["None", "", "null"]:
        user_info = get_user_info(saved_user)
        if user_info:
            st.session_state.update({
                "authenticated": True,
                "role": user_info.get('role'),
                "username": user_info.get('username'),
                "chuc_danh": user_info.get('chuc_danh'),
                "ho_ten": user_info.get('ho_ten')
            })
            st.rerun()

# --- GIAO DIỆN LOGIN ---
if not st.session_state.authenticated:
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        display_logo()
        st.markdown("<h3 style='text-align: center;'>🔐 Đăng nhập hệ thống</h3>", unsafe_allow_html=True)
        with st.form("login_form"):
            u_in = st.text_input("Tài khoản").strip()
            p_in = st.text_input("Mật khẩu", type="password")
            remember = st.checkbox("Ghi nhớ đăng nhập")
            
            if st.form_submit_button("ĐĂNG NHẬP", use_container_width=True, type="primary"):
                user_data = check_login(u_in, p_in)
                if user_data:
                    st.session_state.update({
                        "authenticated": True,
                        "role": user_data.get('role'),
                        "username": user_data.get('username'),
                        "chuc_danh": user_data.get('chuc_danh'),
                        "ho_ten": user_data.get('ho_ten')
                    })
                    
                    if remember:
                        cookies["saved_user"] = user_data.get("username")
                        cookies.save()
                        local_storage.setItem("backup_saved_user", user_data.get("username"))
                    
                    st.success(f"Chào mừng {user_data.get('ho_ten')}")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("Sai tài khoản hoặc mật khẩu")
    st.stop()
    # ========================
# SECTION 4. SIDEBAR
# ========================

def logout():
    cookies["saved_user"] = ""
    cookies.save()
    local_storage.deleteItem("backup_saved_user")
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.session_state.authenticated = False
    st.rerun()

with st.sidebar:
    st.markdown(f"### 👤 {st.session_state.ho_ten}")
    st.caption(f"Vai trò: {st.session_state.role} | {st.session_state.chuc_danh}")
    
    if st.button("🚪 Đăng xuất", use_container_width=True):
        logout()
        
    st.divider()
    
    menu = st.radio("Menu chính:", 
             ["📦 Giao hàng - Lắp đặt", "🕒 Chấm công đi làm", "⚙️ Quản trị hệ thống"],
             label_visibility="collapsed")
             
    st.info("💡 Tip: Dùng App trên điện thoại, hãy xoay ngang màn hình để xem các bảng dữ liệu rộng.")
    # ========================
# MODULE: CHẤM CÔNG ĐI LÀM
# ========================
if menu == "🕒 Chấm công đi làm":
    user = st.session_state.username
    tabs = st.tabs(["📍 Chấm công", "📊 Báo cáo & Lịch nghỉ"])

    # --- TAB 1: CHẤM CÔNG ---
    with tabs[0]:
        st.markdown(f"#### 👋 Xin chào, {st.session_state.ho_ten}")
        now = datetime.now()
        today_str = now.strftime("%Y-%m-%d")

        # Lấy trạng thái hôm nay (Chỉ query đúng ngày hôm nay và user hiện tại)
        @st.cache_data(ttl=60)
        def get_today_status(u, d_str):
            res = supabase.table("cham_cong_di_lam").select("trang_thai_lam")\
                .eq("username", u)\
                .gte("thoi_gian", f"{d_str} 00:00:00")\
                .lte("thoi_gian", f"{d_str} 23:59:59").execute()
            return [r['trang_thai_lam'] for r in res.data] if res.data else []

        statuses = get_today_status(user, today_str)
        has_in = "Vào làm" in statuses
        has_out = "Ra về" in statuses
        
        c1, c2 = st.columns(2)
        
        # Nút Vào làm
        if c1.button("🟢 VÀO LÀM", disabled=has_in, use_container_width=True, type="primary"):
            try:
                supabase.table("cham_cong_di_lam").insert({
                    "username": user, "thoi_gian": now.isoformat(), "trang_thai_lam": "Vào làm", "nguoi_thao_tac": user
                }).execute()
                st.cache_data.clear()
                st.session_state.toast_message = "✅ Đã chấm công Vào làm!"
                st.rerun()
            except Exception as e: st.error(str(e))

        # Nút Ra về
        if c2.button("🔴 RA VỀ", disabled=(not has_in or has_out), use_container_width=True):
            try:
                supabase.table("cham_cong_di_lam").insert({
                    "username": user, "thoi_gian": now.isoformat(), "trang_thai_lam": "Ra về", "nguoi_thao_tac": user
                }).execute()
                st.cache_data.clear()
                st.session_state.toast_message = "🏁 Đã chấm công Ra về!"
                st.rerun()
            except Exception as e: st.error(str(e))
            
        # Hiển thị lịch sử trong ngày
        if statuses:
            st.info(f"Hoạt động hôm nay: {' -> '.join(statuses)}")

    # --- TAB 2: LỊCH NGHỈ (Tối ưu Pivot Table) ---
    with tabs[1]:
        st.markdown("##### 📅 Lịch nghỉ trong tháng")
        
        # Chỉ tải dữ liệu tháng hiện tại để nhẹ máy
        curr_month = datetime.now().month
        curr_year = datetime.now().year
        
        @st.cache_data(ttl=300)
        def get_leave_calendar(m, y):
            # Query lọc theo tháng
            start_d = f"{y}-{m:02d}-01"
            end_d = f"{y}-{m:02d}-31" # Supabase tự xử lý ngày thừa
            res = supabase.table("dang_ky_nghi").select("*")\
                .gte("ngay_nghi", start_d).lte("ngay_nghi", end_d)\
                .neq("trang_thai", "Bị từ chối").execute()
            return pd.DataFrame(res.data) if res.data else pd.DataFrame()

        df_leave = get_leave_calendar(curr_month, curr_year)
        
        if not df_leave.empty:
            df_leave['ngay_nghi'] = pd.to_datetime(df_leave['ngay_nghi'])
            df_leave['Day'] = df_leave['ngay_nghi'].dt.day
            
            # Logic tạo ký hiệu ngắn gọn
            def make_symbol(row):
                s = "OFF" if row['buoi_nghi'] == "Cả ngày" else "1/2"
                return f"({s})" if row['trang_thai'] == "Chờ duyệt" else s
                
            df_leave['Sym'] = df_leave.apply(make_symbol, axis=1)
            
            # Pivot table
            pivot = df_leave.pivot_table(index='ho_ten', columns='Day', values='Sym', aggfunc='first').fillna("")
            st.dataframe(pivot, use_container_width=True)
        else:
            st.caption("Chưa có dữ liệu nghỉ tháng này.")
# ========================
# MODULE: GIAO HÀNG - LẮP ĐẶT
# ========================
elif menu == "📦 Giao hàng - Lắp đặt":
    user = st.session_state.username
    role = st.session_state.role
    
    tabs = st.tabs(["🚀 Gửi đơn mới", "📋 Duyệt đơn & Báo cáo"])

    # --- TAB 1: GỬI ĐƠN ---
    with tabs[0]:
        st.markdown("#### 📸 Tạo phiếu lắp đặt / Giao hàng")
        
        with st.form("delivery_form", clear_on_submit=True):
            f_img = st.file_uploader("Ảnh hóa đơn/Nghiệm thu *", type=['png', 'jpg', 'jpeg'])
            c1, c2 = st.columns(2)
            so_hd = c1.text_input("Số hóa đơn *").upper().strip()
            km = c2.number_input("Quãng đường (Km) *", min_value=0, step=1)
            
            m1, m2 = st.columns(2)
            may_lon = m1.number_input("Máy lớn (200k)", min_value=0)
            may_nho = m2.number_input("Máy nhỏ/Vật tư", min_value=0)
            
            note = st.text_area("Địa chỉ & Ghi chú *", height=80)
            
            if st.form_submit_button("GỬI YÊU CẦU", use_container_width=True, type="primary"):
                if not f_img or not so_hd or not note:
                    st.error("❌ Thiếu thông tin bắt buộc (Ảnh, Số HĐ, Địa chỉ)")
                else:
                    # 1. TÍNH TOÁN
                    unit_price = 80000
                    if km <= 50:
                        unit_price = 30000 if km < 20 else 50000 if km <= 30 else 70000 if km <= 40 else 80000
                    else:
                        unit_price = 80000 + (km - 50) * 5000
                    
                    total = (may_lon * 200000) + (may_nho * unit_price)
                    content = f"{note} | (Lớn:{may_lon}, Nhỏ:{may_nho})"
                    
                    # 2. XỬ LÝ ẢNH (QUAN TRỌNG: Resize trước khi upload)
                    # Hàm process_image_to_base64 đã định nghĩa ở Patch 2
                    img_b64 = process_image_to_base64(f_img)
                    
                    if img_b64:
                        try:
                            supabase.table("cham_cong").insert({
                                "username": user,
                                "ten": st.session_state.ho_ten,
                                "thoi_gian": datetime.now().isoformat(),
                                "so_hoa_don": so_hd,
                                "noi_dung": content,
                                "quang_duong": km,
                                "combo": may_lon + may_nho,
                                "thanh_tien": total,
                                "hinh_anh": img_b64,
                                "trang_thai": "Chờ duyệt"
                            }).execute()
                            st.session_state.toast_message = "✅ Gửi đơn thành công!"
                            st.rerun()
                        except Exception as e:
                            st.error(f"Lỗi gửi đơn: {e}")

    # --- TAB 2: DUYỆT ĐƠN & BÁO CÁO (Server-side Filter) ---
    with tabs[1]:
        # Filter Bar
        c_m, c_y, c_u = st.columns([1, 1, 2])
        v_month = c_m.selectbox("Tháng", range(1, 13), index=datetime.now().month-1)
        v_year = c_y.selectbox("Năm", [2024, 2025, 2026], index=2)
        
        # Chỉ Admin mới chọn được user khác
        filter_user = None
        if role in ["Admin", "System Admin", "Manager"]:
            # Lấy list user gọn nhẹ
            users = supabase.table("quan_tri_vien").select("username, ho_ten").execute()
            if users.data:
                u_opts = {f"{u['ho_ten']} ({u['username']})": u['username'] for u in users.data}
                sel_u = c_u.selectbox("Nhân viên", ["Tất cả"] + list(u_opts.keys()))
                if sel_u != "Tất cả":
                    filter_user = u_opts[sel_u]
        else:
            filter_user = user # User thường chỉ xem của mình
            c_u.text_input("Nhân viên", value=st.session_state.ho_ten, disabled=True)
            
        # Load Data (Sử dụng hàm tối ưu fetch_cham_cong_lap_dat ở Patch 2)
        # Tính ngày đầu và cuối tháng
        last_day = calendar.monthrange(v_year, v_month)[1]
        s_date = f"{v_year}-{v_month:02d}-01"
        e_date = f"{v_year}-{v_month:02d}-{last_day}"
        
        df = fetch_cham_cong_lap_dat(s_date, e_date, filter_user)
        
        if not df.empty:
            # Metrics
            total_money = df[df['trang_thai'] == 'Đã duyệt']['thanh_tien'].sum()
            count_ok = len(df[df['trang_thai'] == 'Đã duyệt'])
            
            m1, m2 = st.columns(2)
            m1.metric("💰 Doanh thu được duyệt", f"{total_money:,.0f} VNĐ")
            m2.metric("📦 Số đơn hoàn thành", f"{count_ok} / {len(df)}")
            
            # Hiển thị bảng (ẩn cột ảnh base64 để không lag)
            st.dataframe(
                df[['thoi_gian', 'so_hoa_don', 'ho_ten_nv', 'noi_dung', 'thanh_tien', 'trang_thai', 'ghi_chu_duyet']],
                column_config={
                    "thanh_tien": st.column_config.NumberColumn("Thành tiền", format="%d ₫"),
                    "trang_thai": st.column_config.TextColumn("Trạng thái", width="small")
                },
                use_container_width=True, hide_index=True
            )
            
            # Logic Duyệt đơn (Chỉ Admin)
            if role in ["Admin", "System Admin"]:
                st.divider()
                st.markdown("##### ⚡ Phê duyệt nhanh")
                to_approve = df[df['trang_thai'] == 'Chờ duyệt']
                if not to_approve.empty:
                    opts = to_approve.apply(lambda x: f"{x['so_hoa_don']} - {x['ho_ten_nv']} ({int(x['thanh_tien']):,}đ)", axis=1)
                    sel_app = st.multiselect("Chọn đơn để duyệt:", opts.tolist())
                    
                    if st.button("✅ DUYỆT CÁC ĐƠN ĐÃ CHỌN", type="primary"):
                        ids = []
                        for item in sel_app:
                            # Trích xuất lại ID hoặc query lại (Ở đây logic đơn giản lấy số HĐ)
                            hd = item.split(" - ")[0]
                            ids.append(hd)
                        
                        if ids:
                            # Update Batch
                            supabase.table("cham_cong").update({"trang_thai": "Đã duyệt", "ghi_chu_duyet": f"Duyệt bởi {user}"})\
                                .in_("so_hoa_don", ids).execute()
                            st.cache_data.clear()
                            st.session_state.toast_message = "✅ Đã duyệt thành công!"
                            st.rerun()
                else:
                    st.info("Không có đơn nào chờ duyệt.")
        else:
            st.warning("Không có dữ liệu trong tháng này.")
# ========================
# MODULE: QUẢN TRỊ HỆ THỐNG
# ========================
elif menu == "⚙️ Quản trị hệ thống":
    st.header("⚙️ Cài đặt")
    
    t1, t2 = st.tabs(["🔐 Đổi mật khẩu", "👥 Quản lý nhân sự (Admin)"])
    
    with t1:
        with st.form("change_pass"):
            p_old = st.text_input("Mật khẩu cũ", type="password")
            p_new = st.text_input("Mật khẩu mới", type="password")
            if st.form_submit_button("Cập nhật"):
                # Logic đổi pass (gọi lại check_login để verify pass cũ)
                u_info = check_login(st.session_state.username, p_old)
                if u_info:
                    new_hash = hash_password(p_new)
                    supabase.table("quan_tri_vien").update({"password": new_hash}).eq("username", st.session_state.username).execute()
                    st.success("Đổi mật khẩu thành công! Vui lòng đăng nhập lại.")
                    time.sleep(1)
                    logout()
                else:
                    st.error("Mật khẩu cũ không đúng.")
                    
    with t2:
        if st.session_state.role not in ["Admin", "System Admin"]:
            st.warning("Bạn không có quyền truy cập khu vực này.")
        else:
            with st.expander("📥 Import dữ liệu cũ (Excel/CSV)"):
                st.info("💡 Tính năng này dùng kết nối trực tiếp (Direct Query) giúp nạp hàng ngàn dòng dữ liệu chỉ trong vài giây.")
                
                # 1. Upload File
                uploaded_file = st.file_uploader("Chọn file Excel dữ liệu cũ", type=['xlsx', 'xls', 'csv'])
                
                # 2. Chọn bảng cần import
                target_table = st.selectbox("Chọn bảng đích", ["cham_cong", "cham_cong_di_lam", "dang_ky_nghi"])
                
                if uploaded_file:
                    # Đọc file vào DataFrame
                    if uploaded_file.name.endswith('.csv'):
                        df_import = pd.read_csv(uploaded_file)
                    else:
                        df_import = pd.read_excel(uploaded_file)
                        
                    st.write("Xem trước 5 dòng dữ liệu:", df_import.head())
                    
                    # Nút xác nhận
                    if st.button("🚀 BẮT ĐẦU IMPORT", type="primary"):
                        with st.spinner("Đang đẩy dữ liệu vào Database..."):
                            # Gọi hàm import nhanh
                            success, msg = fast_import_data(df_import, target_table)
                            
                            if success:
                                st.success(msg)
                                st.balloons()
                            else:
                                st.error(msg)
                # Load danh sách user
                users = supabase.table("quan_tri_vien").select("username, ho_ten, role, chuc_danh").execute()
                if users.data:
                    st.dataframe(users.data, use_container_width=True)
                    st.info("Liên hệ System Admin để thêm/xóa nhân sự.")