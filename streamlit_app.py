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
from sqlalchemy import create_engine

# Tắt cảnh báo không cần thiết
warnings.filterwarnings("ignore", category=DeprecationWarning)
def get_secret(path: list, label: str):
    """
    path: ["SUPABASE_URL"]
    label: tên hiển thị khi báo lỗi
    """
    try:
        # Hugging Face chỉ hỗ trợ ENV VAR phẳng
        if len(path) != 1:
            raise KeyError

        val = os.getenv(path[0])
        if not val:
            raise KeyError

        return val

    except Exception:
        st.error(f"❌ Thiếu cấu hình hệ thống: `{label}`")
        st.info("👉 Vui lòng kiểm tra **Variables and secrets** trong Hugging Face Spaces")
        st.stop()
SUPABASE_URL = get_secret(["SUPABASE_URL"], "SUPABASE_URL")
SUPABASE_KEY = get_secret(["SUPABASE_KEY"], "SUPABASE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
REQUIRED_SECRETS = [
    (["SUPABASE_URL"], "SUPABASE_URL"),
    (["SUPABASE_KEY"], "SUPABASE_KEY"),
    (["COOKIE_PASSWORD"], "COOKIE_PASSWORD")
]

for path, label in REQUIRED_SECRETS:
    get_secret(path, label)

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


# Hàm băm mật khẩu
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def get_sql_engine():
    conf = get_secret(
    ["connections", "supabase_sql"],
    "connections.supabase_sql"
    )
    # Tạo chuỗi kết nối từ các thành phần trong secrets
    conn_url = f"postgresql://{conf['username']}:{conf['password']}@{conf['host']}:{conf['port']}/{conf['database']}"
    return create_engine(conn_url)

# Khi cần nạp dữ liệu từ DataFrame (df)
def upload_data(df, table_name):
    engine = get_sql_engine()
    df.to_sql(table_name, engine, if_exists='append', index=False, method='multi')
    st.success("Đã nạp dữ liệu thành công!")
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
    
@st.cache_data(ttl=300)
def get_don_cho_duyet(role, username):
    try:
        query = supabase.table("cham_cong").select("""
            id, thoi_gian, so_hoa_don, noi_dung, quang_duong,
            combo, thanh_tien, hinh_anh, trang_thai, username,
            quan_tri_vien(ho_ten)
        """).eq("trang_thai", "Chờ duyệt")

        # ✅ CHỈ User mới bị giới hạn
        if role == "User":
            query = query.eq("username", username)

        res = query.order("thoi_gian", desc=True).execute()
        res = query.execute()
        return pd.DataFrame(res.data or [])

    except Exception as e:
        st.error(f"❌ Lỗi tải đơn chờ duyệt: {e}")
        return pd.DataFrame()

# Tối ưu: Chỉ lấy dữ liệu trong khoảng thời gian cần thiết (Server-side filtering)
@st.cache_data(ttl=300)
def get_cham_cong_bao_cao(role, username):
    query = supabase.table("cham_cong").select("""
        id, thoi_gian, so_hoa_don, noi_dung, quang_duong,
        combo, thanh_tien, trang_thai, ghi_chu_duyet,
        username, quan_tri_vien(ho_ten)
    """)

    # Chỉ USER thường mới bị lọc username
    if role not in ["Admin", "System Admin", "Manager"]:
        query = query.eq("username", username)
    res = query.execute()
    data = res.data if res else []
    res = query.order("thoi_gian", desc=True).execute()
    return pd.DataFrame(data)
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
#CÁC HÀM CHO PHẦN CHẤM CÔNG LẮP ĐẶT
@st.cache_data(ttl=600) # Lưu bộ nhớ đệm 10 phút
def get_employee_list(role, username):
    try:
        if role in ["System Admin", "Admin"]:
            res = supabase.table("quan_tri_vien").select("username, ho_ten").in_("role", ["Manager", "User"]).execute()
        elif role == "Manager":
            res = supabase.table("quan_tri_vien").select("username, ho_ten").eq("role", "User").execute()
        else:
            return pd.DataFrame()
        return pd.DataFrame(res.data)
    except Exception as e:
        return pd.DataFrame()

@st.cache_data(ttl=600) # Lưu bộ nhớ đệm 10 phút
def get_users_cached():
    res = supabase.table("quan_tri_vien").select("ho_ten, chuc_danh, role, so_dien_thoai, ngay_sinh, dia_chi, username").execute()
    return pd.DataFrame(res.data)

def optimize_image(uploaded_file, quality=60, max_width=800):
    """Nén ảnh để tiết kiệm băng thông Supabase (Giảm dung lượng từ 5MB xuống <100KB)"""
    from PIL import Image
    import io
    img = Image.open(uploaded_file)
    if img.mode in ("RGBA", "P"): img = img.convert("RGB")
    
    # Resize nếu ảnh quá lớn
    if img.width > max_width:
        ratio = max_width / float(img.width)
        new_height = int((float(img.height) * float(ratio)))
        img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)
    
    buffer = io.BytesIO()
    img.save(buffer, format="JPEG", quality=quality, optimize=True)
    return base64.b64encode(buffer.getvalue()).decode('utf-8')
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
COOKIE_PASSWORD = get_secret(["COOKIE_PASSWORD"], "COOKIE_PASSWORD")

cookies = EncryptedCookieManager(
    prefix="daithanh/",
    password=COOKIE_PASSWORD
)

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
            
            if st.form_submit_button("ĐĂNG NHẬP", width="stretch", type="primary"):
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
    # Xóa cookie thay vì gán rỗng (nếu thư viện cookies hỗ trợ .delete)
    if "saved_user" in cookies:
        del cookies["saved_user"]
        cookies.save()
    
    # Local storage thường an toàn, nhưng dùng try-except nếu muốn chắc chắn
    try:
        local_storage.deleteItem("backup_saved_user")
    except Exception:
        pass

    st.session_state.clear()
    # Sau khi clear(), bạn cần gán lại các biến khởi tạo quan trọng
    st.session_state.authenticated = False
    st.rerun()

with st.sidebar:
    st.markdown(f"### 👤 {st.session_state.ho_ten}")
    st.caption(f"Vai trò: {st.session_state.role} | {st.session_state.chuc_danh}")
    
    if st.button("🚪 Đăng xuất", width="stretch"):
        logout()
        
    st.divider()
    
    menu = st.radio("Menu chính:", 
             ["📦 Giao hàng - Lắp đặt", "⚙️ Quản trị hệ thống"],
             label_visibility="collapsed")
             
    st.info("💡 Tip: Dùng App trên điện thoại, hãy xoay ngang màn hình để xem các bảng dữ liệu rộng.")

# ========================
# MODULE: GIAO HÀNG - LẮP ĐẶT
# ========================
if menu == "📦 Giao hàng - Lắp đặt":
    # Lấy thông tin từ session_state (đã nạp từ Cookie)
    role = st.session_state.get("role", "User")
    chuc_danh = st.session_state.get("chuc_danh", "N/A")
    user_hien_tai = st.session_state.get("username")

    # 1. PHÂN QUYỀN TABS
    # Gom nhóm logic để dễ quản lý
    tabs = st.tabs(["📸 Chấm công lắp đặt", "📋 Duyệt đơn", "📈 Báo cáo lắp đặt"])

    
    # --- TAB 1: GỬI ĐƠN LẮP ĐẶT (TỐI ƯU CHO COOKIE) ---
    with tabs[0]:
        user = st.session_state.get("username")
        role = st.session_state.get("role")
        ho_ten_sender = st.session_state.get("ho_ten", user)

        # 1. Tải danh sách NV (Dùng Cache để chạy mượt)
        target_user = user
        if role in ["Manager", "Admin", "System Admin", "User"]:
            df_nv = get_employee_list(role, user)
            if not df_nv.empty:
                df_nv['display'] = df_nv['ho_ten'] + " (" + df_nv['username'] + ")"
                options = (["Tự chấm công"] + df_nv['display'].tolist()) if role == "Manager" else df_nv['display'].tolist()
                
                sel_nv = st.selectbox("🎯 Chấm công cho:", options)
                if sel_nv != "Tự chấm công":
                    target_user = df_nv[df_nv['display'] == sel_nv]['username'].values[0]
                    # Cập nhật lại họ tên người được chấm công để lưu vào cột 'ten'
                    ho_ten_sender = df_nv[df_nv['display'] == sel_nv]['ho_ten'].values[0]

        # 2. Upload ảnh với key để reset
        if "f_up_key" not in st.session_state: st.session_state["f_up_key"] = 0
        uploaded_file = st.file_uploader("🖼️ Ảnh hóa đơn *", type=["jpg", "png", "jpeg"], key=f"up_{st.session_state['f_up_key']}")
        
        with st.form("form_lap_dat", clear_on_submit=True):
            c1, c2 = st.columns(2)
            so_hd_in = c1.text_input("📝 Số hóa đơn *", placeholder="VD: 12345")
            quang_duong = c2.number_input("🛣️ Quãng đường (km) *", min_value=0, step=1)
            
            m1, m2 = st.columns(2)
            combo_may_lon = m1.number_input("🤖 Máy lớn (200k/máy)", min_value=0, step=1)
            combo_may_nho = m2.number_input("📦 Máy nhỏ / Vật tư", min_value=0, step=1)
            
            noi_dung = st.text_area("📍 Địa chỉ / Ghi chú *", height=80).strip()
            
            if st.form_submit_button("🚀 GỬI YÊU CẦU DUYỆT ĐƠN", width="stretch"):
                if not uploaded_file or not so_hd_in or not noi_dung:
                    st.error("❌ Thiếu thông tin bắt buộc!")
                elif combo_may_lon == 0 and combo_may_nho == 0:
                    st.error("❌ Nhập số lượng máy!")
                else:
                    try:
                        # Tối ưu ảnh ngay tại đây (QUAN TRỌNG NHẤT)
                        with st.spinner("Đang nén ảnh và gửi dữ liệu..."):
                            base64_image = optimize_image(uploaded_file)
                            if len(base64_image) > 200_000:
                                st.error("Ảnh quá lớn")
                            # Logic tính tiền (giữ nguyên của bạn)
                            if quang_duong <= 50:
                                don_gia_km = 30000 if quang_duong < 20 else 50000 if quang_duong <= 30 else 70000 if quang_duong <= 40 else 80000
                            else:
                                don_gia_km = 80000 + (quang_duong - 50) * 5000
                            
                            tong_tien = (combo_may_lon * 200000) + (combo_may_nho * don_gia_km)
                            so_hd = so_hd_in.strip().upper()
                            final_hd = f"HD{so_hd}" if not so_hd.startswith("HD") else so_hd

                            data_insert = {
                                "username": target_user,
                                "quan_tri_vien": user,
                                "ten": ho_ten_sender,
                                "thoi_gian": datetime.now().isoformat(), # Dùng isoformat cho chuẩn DB
                                "so_hoa_don": final_hd,
                                "noi_dung": f"{noi_dung} | (Lớn: {combo_may_lon}, Nhỏ: {combo_may_nho})",
                                "quang_duong": int(quang_duong),
                                "combo": int(combo_may_lon + combo_may_nho),
                                "thanh_tien": float(tong_tien),
                                "hinh_anh": base64_image,
                                "trang_thai": 'Chờ duyệt'
                            }

                            supabase.table("cham_cong").insert(data_insert).execute()
                            
                            st.session_state.toast_message = "✅ Gửi đơn thành công!"
                            st.session_state["f_up_key"] += 1 # Reset file uploader
                            st.rerun()
                    except Exception as e:
                        if "duplicate" in str(e):
                            st.error(f"❌ Số hóa đơn {final_hd} đã tồn tại!")
                        else:
                            st.error(f"❌ Lỗi: {e}")
    # --- TAB 2: DUYỆT ĐƠN  ---
    with tabs[1]:
        st.markdown("#### 📋 Danh sách đơn chờ duyệt")

        # 1️⃣ LẤY DỮ LIỆU
        df_p = get_don_cho_duyet(role, user_hien_tai)

        # 2️⃣ KHÔNG CÓ DỮ LIỆU → DỪNG
        if df_p.empty:
            st.info("📭 Hiện tại không có đơn nào đang chờ duyệt.")
            pass
        else:
            # 3️⃣ XỬ LÝ DỮ LIỆU (LUÔN CHẠY KHI CÓ DATA)
            if "quan_tri_vien" in df_p.columns:
                df_p["ho_ten_nv"] = df_p["quan_tri_vien"].apply(
                    lambda x: x.get("ho_ten") if isinstance(x, dict) else "N/A"
                )
            elif "ten" in df_p.columns:
                df_p["ho_ten_nv"] = df_p["ten"]
            else:
                df_p["ho_ten_nv"] = "N/A"


            df_p["dt_raw"] = pd.to_datetime(df_p["thoi_gian"], errors="coerce")

            vn_tz = pytz.timezone("Asia/Ho_Chi_Minh")
            df_p["time_display"] = df_p["dt_raw"].apply(
                lambda dt: (
                    dt.replace(tzinfo=pytz.UTC).astimezone(vn_tz)
                    if dt.tzinfo is None else dt.astimezone(vn_tz)
                ).strftime("%d/%m/%Y %H:%M")
            )

            # 4️⃣ RENDER UI
            for _, r in df_p.iterrows():
                expander_title = f"📦 HĐ: {r['so_hoa_don']} — 👤 {r['ho_ten_nv']} — 🕒 {r['time_display']}"

                with st.expander(expander_title):
                    cl, cr = st.columns([1.5, 1])

                    with cl:
                        st.write(f"**📍 Địa chỉ/Ghi chú:** {r['noi_dung']}")
                        st.write(f"🛣️ Quãng đường: **{r['quang_duong']} km** | 📦 Máy: **{r['combo']}**")
                        st.markdown(f"#### 💰 Tổng: `{r['thanh_tien']:,.0f}` VNĐ")
                        st.divider()

                        # --- PHÂN QUYỀN THAO TÁC ---
                        if role in ["Admin", "System Admin"]:
                            b1, b2 = st.columns(2)

                            if b1.button(
                                "✅ DUYỆT ĐƠN",
                                key=f"ap_{r['id']}",
                                width="stretch",
                                type="primary"
                            ):
                                if quick_update_status(r["id"], "Đã duyệt", "Thông tin chính xác"):
                                    st.session_state.toast_message = f"✅ Đã duyệt {r['so_hoa_don']}"
                                    st.rerun()

                            with b2:
                                with st.popover("❌ TỪ CHỐI", width="stretch"):
                                    reason = st.text_area("Lý do:", key=f"txt_{r['id']}")
                                    if st.button("Xác nhận", key=f"conf_{r['id']}", width="stretch"):
                                        if reason.strip() and quick_update_status(r["id"], "Từ chối", reason.strip()):
                                            st.session_state.toast_message = "🔴 Đã từ chối đơn"
                                            st.rerun()

                        elif role == "Manager":
                            st.info("ℹ️ Quyền Duyệt/Từ chối thuộc về Kế toán.")
                        else:
                            st.warning("⏳ Đơn đang chờ Kế toán phê duyệt.")

                    with cr:
                        img_data = r.get("hinh_anh")
                        if img_data:
                            if len(img_data) > 100:
                                if not img_data.startswith("data:image"):
                                    img_data = f"data:image/jpeg;base64,{img_data}"
                                st.image(img_data, caption=f"HĐ {r['so_hoa_don']}", width="stretch")
                            else:
                                st.error("⚠️ Dữ liệu ảnh bị lỗi.")
                        else:
                            st.warning("⚠️ Không có ảnh.")
    with tabs[-1]:
        
        # Lấy thông tin từ Session (đã nạp bởi Cookie Manager)
        # Lấy dữ liệu gốc
        current_u = user_hien_tai
        current_r = role
        
        row_id = None
        # --- KHỞI TẠO BIẾN TRƯỚC ĐỂ TRÁNH CRASH ---
        df_all = pd.DataFrame() 
        res = None
        
        
        try:
            
            # --- 1. LẤY DỮ LIỆU VÀ XỬ LÝ TRUNG TÂM (QUAN TRỌNG) ---
            # Gọi hàm lấy dữ liệu (đã sửa ở bước trước để lấy all status)
            
            df_raw = get_cham_cong_bao_cao(current_r, user_hien_tai)
            if df_raw.empty:
                if current_r in ["Admin", "System Admin", "Manager"]:
                    st.info("ℹ️ Chưa có dữ liệu đơn lắp đặt nào trong hệ thống.")
                else:
                    st.info("ℹ️ Bạn chưa có đơn lắp đặt nào.")
                    df_all = pd.DataFrame(columns=['thoi_gian', 'trang_thai', 'so_hoa_don', 'username'])
                #st.stop()
            else:
                required_cols = {"thoi_gian", "trang_thai", "so_hoa_don"}
                missing = required_cols - set(df_raw.columns)
                # A. Xử lý "Tên" từ JSON
                if 'quan_tri_vien' in df_raw.columns:
                    df_raw['Tên'] = df_raw['quan_tri_vien'].apply(lambda x: x.get('ho_ten') if isinstance(x, dict) else "N/A")
                
                if "thoi_gian" not in df_raw.columns:
                    st.error("❌ Không tìm thấy cột 'thoi_gian' trong dữ liệu Supabase.")
                    st.write(df_raw.columns.tolist())
                    pass

                df_raw["thoi_gian"] = pd.to_datetime(
                df_raw["thoi_gian"],
                errors="coerce"
                )
                
                # Sau khi pd.to_datetime ở trên
                if df_raw["thoi_gian"].dt.tz is None:
                    df_raw["Thời Gian"] = (
                        df_raw["thoi_gian"]
                        .dt.tz_localize("UTC")
                        .dt.tz_convert("Asia/Ho_Chi_Minh")
                    )
                else:
                    df_raw["Thời Gian"] = df_raw["thoi_gian"].dt.tz_convert("Asia/Ho_Chi_Minh")
                
                # C. Đổi tên toàn bộ cột sang tiếng Việt ngay lập tức
                # (Để sau này không bị nhầm lẫn giữa tên Anh/Việt)
                map_cols = {
                    'so_hoa_don': 'Số HĐ',
                    'noi_dung': 'Địa chỉ',
                    'thanh_tien': 'Thành tiền',
                    'trang_thai': 'Trạng thái',
                    'ghi_chu_duyet': 'Lý do',
                    'combo': 'Số máy',
                    'quang_duong': 'Quãng đường (Km)',
                    'username': 'username' # Giữ lại để lọc
                }
                df_all = df_raw.rename(columns=map_cols).copy()
                
                # Format lại chuỗi thời gian hiển thị sau khi đã tính toán xong
                df_all['Thời Gian Str'] = df_all['Thời Gian'].dt.strftime('%d/%m/%Y %H:%M')
                if df_all.empty:
                    st.warning("Không có dữ liệu hiển thị.")
                else:
                    # --- 3. BIỂU ĐỒ TỔNG QUAN (Dành cho Admin/Manager) ---
                    if current_r in ["Admin", "System Admin", "Manager"]:
                        st.markdown("### 📈 Biểu đồ tổng quan (Toàn thời gian)")
                        
                        # Chỉ tính toán trên các đơn ĐÃ DUYỆT
                        df_chart = df_all[df_all["Trạng thái"] == "Đã duyệt"]
                        
                        if not df_chart.empty:
                            stats = df_chart.groupby("Tên").agg(
                                So_don=("Số HĐ", "count"), 
                                Doanh_thu=("Thành tiền", "sum")
                            ).reset_index()
                            
                            c1, c2 = st.columns(2)
                            with c1:
                                fig_bar = px.bar(
                                    stats, 
                                    x="Tên", 
                                    y="So_don", 
                                    title="Số đơn đã duyệt", 
                                    text_auto=True, 
                                    color="Tên"
                                )
                                # Thêm config nếu bạn muốn tùy chỉnh (ví dụ: ẩn thanh công cụ hoặc bật/tắt zoom)
                                st.plotly_chart(fig_bar, width="stretch", config={'displayModeBar': False})
                                
                            with c2:
                                fig_pie = px.pie(
                                    stats, 
                                    values="Doanh_thu", 
                                    names="Tên", 
                                    title="Tỷ lệ doanh thu lắp đặt",
                                    hole=0.4
                                )
                                # width="stretch" là chính xác cho phiên bản 2026
                                st.plotly_chart(fig_pie, width="stretch", config={'displayModeBar': False})
                        else:
                            st.info("Chưa có dữ liệu 'Đã duyệt' để vẽ biểu đồ.")
                    
                    st.divider()

                    # --- 4. BỘ LỌC VÀ BÁO CÁO CHI TIẾT ---
                    with st.expander("📊 Tra cứu chi tiết và Xuất báo cáo", expanded=True):
                        col_f1, col_f2, col_f3 = st.columns(3)

                        # Chọn tháng
                        curr_date = date.today()
                        month_opts = [(curr_date.replace(day=1) - pd.DateOffset(months=i)).strftime("%m/%Y") for i in range(12)]
                        sel_month = col_f1.selectbox("📅 Chọn tháng báo cáo", month_opts)

                        # Tính ngày start/end
                        sel_dt = datetime.strptime(sel_month, "%m/%Y")
                        start_d = sel_dt.date().replace(day=1)
                        last_day = calendar.monthrange(sel_dt.year, sel_dt.month)[1]
                        end_d = sel_dt.date().replace(day=last_day)
                        d_range = [start_d, end_d]

                        # Chọn Nhân viên & Trạng thái
                        if current_r in ["Admin", "System Admin", "Manager"]:
                            nv_opts = ["Tất cả"] + sorted(df_all["Tên"].astype(str).unique().tolist())
                            sel_nv = col_f2.selectbox("👤 Nhân viên", nv_opts, index=0)
                            sel_tt = col_f3.selectbox("📌 Trạng thái", ["Tất cả", "Chờ duyệt", "Đã duyệt", "Từ chối"])
                        else:
                            sel_nv = user_hien_tai 
                            col_f2.text_input("👤 Nhân viên", value=user_hien_tai   , disabled=True)
                            sel_tt = col_f3.selectbox("📌 Trạng thái", ["Tất cả", "Chờ duyệt", "Đã duyệt", "Từ chối"])

                        # --- 5. LOGIC LỌC CHUẨN HÓA ---

                        # Lọc thời gian: Chuyển d_range về cùng kiểu với cột Thời Gian
                        mask_time = (df_all["Thời Gian"].dt.date >= start_d) & (df_all["Thời Gian"].dt.date <= end_d)

                        # Lọc nhân viên
                        if current_r in ["Admin", "System Admin", "Manager"]:
                            if sel_nv != "Tất cả":
                                mask_user = (df_all["Tên"] == sel_nv)
                            else:
                                mask_user = True # Lấy tất cả
                        else:
                            # QUAN TRỌNG: Kiểm tra xem bạn lọc theo 'Tên' (Họ tên) hay 'username' (ID)
                            # Nếu user thường, nên lọc theo cột 'username' gốc để chính xác 100%
                            mask_user = (df_all["username"] == user_hien_tai)

                        # Kết hợp mask cơ bản
                        mask_base = mask_time & mask_user
                        df_stats_base = df_all[mask_base].copy()

                        # B. Lọc thêm TRẠNG THÁI cho bảng hiển thị
                        if sel_tt != "Tất cả":
                            mask_view = mask_base & (df_all["Trạng thái"] == sel_tt)
                        else:
                            mask_view = mask_base

                        df_display = df_all[mask_view].sort_values("Thời Gian", ascending=False)

                        # --- 6. HIỂN THỊ THỐNG KÊ (Dùng df_stats_base) ---
                        if df_stats_base.empty:
                            st.info("Không có dữ liệu trong tháng này.")
                        else:
                            # Tính toán trên tập dữ liệu đầy đủ của tháng (Không bị ảnh hưởng bởi selectbox Trạng thái)
                            total_orders = len(df_stats_base)
                            
                            df_approved_only = df_stats_base[df_stats_base["Trạng thái"] == "Đã duyệt"]
                            approved_count = len(df_approved_only)
                            rev_sum = df_approved_only["Thành tiền"].sum()

                            # CSS Style (Giữ nguyên của bạn)
                            st.markdown("""
                                <style>
                                .stats-container { display: flex; gap: 40px; padding: 10px 5px; margin-bottom: 10px; }
                                .stat-item { display: flex; flex-direction: column; }
                                .stat-label { color: #94a3b8; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }
                                .stat-value { color: #dc2626; font-size: 2rem; font-weight: 800; line-height: 1; }
                                .currency { font-size: 0.9rem; color: #38bdf8; margin-left: 4px; }
                                .count-highlight { color: #4ade80; }
                                .count-total { color: #64748b; font-size: 1.1rem; }
                                </style>
                            """, unsafe_allow_html=True)

                            col_info, c_exp = st.columns([4, 1.2])
                            with col_info:
                                st.markdown(f"""
                                    <div class="stats-container">
                                        <div class="stat-item">
                                            <div class="stat-label">💰 Tổng thu nhập (Đã duyệt)</div>
                                            <div class="stat-value">{rev_sum:,.0f}<span class="currency">VNĐ</span></div>
                                        </div>
                                        <div class="stat-item">
                                            <div class="stat-label">📊 Thống kê đơn</div>
                                            <div class="stat-value">
                                                <span class="count-highlight">{approved_count}</span><span class="count-total"> / {total_orders} đơn</span>
                                            </div>
                                        </div>
                                    </div>
                                """, unsafe_allow_html=True)
                            
                            # --- 7. HIỂN THỊ BẢNG CHI TIẾT (Dùng df_display) ---
                            if df_display.empty:
                                st.info(f"🔍 Không tìm thấy đơn nào có trạng thái '{sel_tt}' trong tháng này.")
                            else:
                                # Chuẩn bị dữ liệu hiển thị (Cột đã được đổi tên ở Bước 1C rồi)
                                df_view = df_display.copy()
                                
                                # Thêm STT
                                df_view.reset_index(drop=True, inplace=True)
                                df_view.insert(0, "STT", df_view.index + 1)
                                
                                # Dùng cột Thời Gian Str đã format để hiển thị cho đẹp
                                df_view["Thời Gian"] = df_view["Thời Gian Str"]

                                # Chọn các cột cần hiển thị
                                cols_show = ["STT", "Tên", "Thời Gian", "Số HĐ", "Địa chỉ", 
                                            "Quãng đường (Km)", "Số máy", "Thành tiền", "Trạng thái", "Lý do"]
                                
                                # Đảm bảo chỉ lấy cột tồn tại
                                valid_cols = [c for c in cols_show if c in df_view.columns]
                                df_final = df_view[valid_cols]

                                # Cấu hình cột
                                column_cfg = {
                                    "Tên": st.column_config.TextColumn("Tên", width="medium"),
                                    "Lý do": st.column_config.TextColumn("Lý do", width="large"),
                                    "Thành tiền": st.column_config.NumberColumn("Thành tiền", format="%d ₫"),
                                }
                                
                                # Render Bảng
                                is_admin = current_r == "System Admin"
                                with st.container(height=400, border=False):
                                    if is_admin:
                                        df_final.insert(0, "🗑️", False)
                                        edited_df = st.data_editor(
                                            df_final,
                                            width="stretch",
                                            hide_index=True,
                                            column_config=column_cfg,
                                            key="main_editor"
                                        )
                                        # Logic Xóa
                                        rows_del = edited_df[edited_df["🗑️"] == True]
                                        if not rows_del.empty:
                                            if st.button(f"Xóa {len(rows_del)} đơn đã chọn"):
                                                ids = rows_del["Số HĐ"].tolist()
                                                supabase.table("cham_cong").delete().in_("so_hoa_don", ids).execute()
                                                st.success("Đã xóa!")
                                                st.rerun()
                                    else:
                                        st.dataframe(df_final, width="stretch", hide_index=True, column_config=column_cfg)

                                # --- 🗑️ LOGIC XÓA TỐI ƯU (BATCH DELETE) ---
                                if is_admin and not rows_del.empty:
                                    st.warning(f"⚠️ Đang chọn {len(rows_del)} đơn để xóa.")
                                    if st.button("🔥 XÁC NHẬN XÓA VĨNH VIỄN", type="primary", width="stretch"):
                                        try:
                                            list_so_hd = rows_del["Số HĐ"].tolist()
                                            
                                            # TỐI ƯU: Xóa tất cả trong 1 lần gọi thay vì dùng vòng lặp for
                                            supabase.table("cham_cong").delete().in_("so_hoa_don", list_so_hd).execute()                                                
                                            
                                            get_cham_cong_bao_cao.clear()
                                            st.session_state.toast_message = "✅ Đã xóa các đơn được chọn thành công!"
                                            st.rerun()
                                        except Exception as e:
                                            st.error(f"Lỗi khi xóa: {e}")

                                # Đã bỏ toàn bộ CSS và bộ chuyển trang cũ

                                # --- XỬ LÝ XUẤT FILE EXCEL ---
                                out = io.BytesIO()
                                df_export = df_display.sort_values("Thời Gian").copy()
                                
                                # Định dạng ngày cho Excel
                                df_export['Thời Gian'] = pd.to_datetime(df_export['Thời Gian'], errors='coerce')
                                df_export['Ngày'] = df_export['Thời Gian'].dt.strftime('%d/%m/%Y')

                                df_export.insert(0, 'STT', range(1, len(df_export) + 1))

                                # Xử lý các cột số lượng
                                df_export['Máy'] = df_export['combo'].fillna(0).astype(int) if 'combo' in df_export.columns else 0
                                def fmt_km(x):
                                    try:
                                        return f"{int(float(x))} Km" if pd.notna(x) and float(x) > 0 else ""
                                    except (ValueError, TypeError):
                                        return ""

                                df_export['Km_Số'] = (
                                    df_export['quang_duong'].apply(fmt_km)
                                    if 'quang_duong' in df_export.columns
                                    else ""
                                )
                                cols_to_get = ['STT', 'Ngày', 'Địa chỉ', 'Tên', 'Máy', 'Km_Số', 'Thành tiền', 'Lý do', 'Trạng thái']
                                df_main = df_export.reindex(columns=cols_to_get).fillna("")
                                
                                #df_main = df_main.rename(columns={'ghi_chu_duyet': 'Ghi chú'})
                                df_main.columns = ['STT', 'Ngày', 'Địa chỉ', 'Nhân viên', 'Số Máy', 'Quãng đường', 'Thành tiền', 'Lý do', 'Tình trạng']

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
                                    label_time = sel_month if current_r in ["Admin", "System Admin"] else f"{d_range[0].strftime('%d/%m')} - {d_range[1].strftime('%d/%m/%Y')}"
                                    last_col = chr(ord('A') + len(df_main.columns) - 1)
                                    last_col = chr(ord('A') + len(df_main.columns) - 1)
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
                                    st.write("<div style='padding-top: 15px;'></div>", unsafe_allow_html=True)                                  
                                    st.download_button(
                                        
                                        label="📥 Tải Excel Báo Cáo", 
                                        data=out.getvalue(), 
                                        file_name=f"Bao_Cao_{current_u}.xlsx", 
                                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                        width="stretch"
                                        
                                    )
        except Exception as e:
            st.error(f"Lỗi tải dữ liệu: {e}")
            pass


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
                        pass
                        
                    row_data = df_edit[mask].iloc[0]
                    row_id = row_data["id"] # Bỏ ép kiểu int() để an toàn với Supabase
                    current_status = row_data["Trạng thái"]
                    
                    # --- LOGIC TÁCH DỮ LIỆU AN TOÀN ---
                    full_content = str(row_data.get('Địa chỉ', ''))
                    raw_address = full_content.split(" | (")[0] if " | (" in full_content else full_content
                    
                    # Lấy thông số kỹ thuật
                    try:
                        val_quang_duong = int(float(row_data.get('quang_duong', 0))) # Ép kiểu qua float trước để tránh lỗi nếu là '10.0'
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
                        if st.button("🗑️ XOÁ ĐƠN NÀY", width="stretch", type="secondary"):
                            try:
                                supabase.table("cham_cong") \
                                    .delete() \
                                    .eq("id", row_id) \
                                    .eq("username", user_login) \
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
                        with st.spinner("🔄 Đang tải ảnh hóa đơn..."):
                            # Chỉ truy vấn ảnh của đúng cái ID đang chọn
                            res_img = supabase.table("cham_cong").select("hinh_anh").eq("id", row_id).execute()
                            
                            if res_img.data:
                                img_base64 = res_img.data[0].get("hinh_anh")
                                
                                # Hiển thị ảnh (đoạn )
                                if img_base64:
                                    with st.popover("🖼️ Xem ảnh hóa đơn hiện tại", width="stretch"):
                                        # Kiểm tra và thêm tiền tố nếu cần (đoạn )
                                        img_src = img_base64
                                        if not str(img_src).startswith("data:image"):
                                            img_src = f"data:image/jpeg;base64,{img_src}"
                                        st.image(img_src, caption=f"Ảnh của hóa đơn {sel_hd_edit}")

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
                        submit_update = st.form_submit_button("💾 XÁC NHẬN CẬP NHẬT & GỬI DUYỆT LẠI", width="stretch", type="primary")

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
                                    
                                    st.session_state.toast_message = "✅ Đã cập nhật và gửi duyệt lại!"
                                    st.rerun()
                                    
                                except Exception as e:
                                    st.error(f"❌ Lỗi hệ thống: {e}")

        # --- DÀNH CHO ADMIN: ĐẢO NGƯỢC TRẠNG THÁI ---
        if role in ["Admin", "System Admin"]:
            st.divider()
            with st.expander("🔄 Quản lý trạng thái (Hủy duyệt đơn)", expanded=False):
                st.warning("⚠️ **Lưu ý:** Thao tác này đưa đơn về trạng thái 'Chờ duyệt'.")
                
                # Đảm bảo df_all tồn tại và không rỗng
                if "Trạng thái" not in df_all.columns:
                    st.error("❌ Không tìm thấy cột Trạng thái trong dữ liệu.")
                    pass

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
                        with st.popover(f"🔍 Xem lại ảnh hóa đơn {sel_undo}", width="stretch"):
                            # Chuẩn hóa Base64 an toàn
                            if isinstance(img_base64_undo, str):
                                if not img_base64_undo.startswith("data:image"):
                                    # Xử lý trường hợp chuỗi base64 thuần
                                    img_display = f"data:image/jpeg;base64,{img_base64_undo}"
                                else:
                                    img_display = img_base64_undo
                                st.image(img_display, width="stretch")
                            else:
                                st.warning("Định dạng ảnh không hợp lệ.")
                    
                    reason_undo = st.text_input("📝 Lý do đưa về chờ duyệt:", key="reason_undo_input")
                    
                    if st.button("⏪ XÁC NHẬN ĐẢO NGƯỢC", width="stretch", type="primary"):
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
                                
                                st.session_state.toast_message = "✅ Đã chuyển đơn về trạng thái Chờ duyệt thành công!"
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Lỗi khi cập nhật Cloud: {e}")
#==============================================================================
#PHÂN HỆ 3: QUẢN TRỊ HỆ THỐNG
#==============================================================================

elif menu == "⚙️ Quản trị hệ thống":
    role_login = st.session_state.get("role", "User")
    
    #1. Xác định danh sách tab dựa trên quyền
    if role_login == "System Admin":
        list_tabs = ["👥 Nhân sự", "🛠️ Quản trị tài khoản", "🔐 Đổi mật khẩu"]
    elif role_login in ["Admin", "Manager"]:
        list_tabs = ["👥 Nhân sự", "🔐 Đổi mật khẩu"]
    else: 
        list_tabs = ["🔐 Đổi mật khẩu"]
    
    #2. Khởi tạo Tabs
    tabs = st.tabs(list_tabs)

    #3. Hiển thị nội dung bằng cách duyệt qua list_tabs
    for i, tab_name in enumerate(list_tabs):
        with tabs[i]:
            if tab_name == "👥 Nhân sự":
                st.subheader("Quản lý nhân sự")
                #1. Lấy dữ liệu (Sử dụng get_conn để an toàn hơn cho hệ thống Cookie)
                try:
                    #1. Lấy dữ liệu từ Supabase thay vì SQLite
                    res = supabase.table("quan_tri_vien") \
                    .select("ho_ten, chuc_danh, role, so_dien_thoai, ngay_sinh, dia_chi, username") \
                    .execute()
                    df_users = get_users_cached()
                except Exception as e:
                    st.error(f"Lỗi kết nối Cloud: {e}")
                    df_users = get_users_cached

                if df_users.empty:
                    st.info("Chưa có dữ liệu nhân sự.")
                else:
                    #2. XỬ LÝ HIỂN THỊ BẢNG (Giữ nguyên cấu trúc logic của bạn)
                    df_users_display = df_users.copy()
                    
                    #Tạo cột STT
                    df_users_display.insert(0, 'STT', range(1, len(df_users_display) + 1))
                    
                    st.dataframe(
                        df_users_display,
                        width="stretch",
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

                    #3. LOGIC PHÂN QUYỀN CHỌN NHÂN VIÊN
                    if role_login == "System Admin":
                        df_filter = df_users.copy()
                    elif role_login == "Admin":
                        df_filter = df_users[df_users['role'].isin(['Manager', 'User'])].copy()
                    elif role_login == "Manager":
                        df_filter = df_users[df_users['role'] == 'User'].copy()
                    else:
                        df_filter = pd.DataFrame()

                    if df_filter.empty:
                        st.warning("🔒 Bạn không có quyền cập nhật nhân sự cấp cao hơn.")
                    else:
                        #Tạo tên hiển thị sạch sẽ để chọn
                        df_filter['display_name'] = df_filter['ho_ten'].fillna("Chưa có tên") + " (" + df_filter['username'] + ")"
                        selected_display = st.selectbox("🎯 Chọn nhân viên để cập nhật:", 
                                                    options=df_filter['display_name'].tolist(),
                                                    key="sb_edit_user")
                        
                        target_u = df_filter[df_filter['display_name'] == selected_display]['username'].values[0]
                        row = df_users[df_users['username'] == target_u].iloc[0]
                        
                       # Lock quyền nếu không phải System Admin
                        is_locked = (role_login != "System Admin")

                        #4. FORM CẬP NHẬT THÔNG TIN
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
                                
                                #Xử lý ngày sinh an toàn
                                val_birth = date.today()
                                if 'ngay_sinh' in row and row['ngay_sinh'] and str(row['ngay_sinh']) != 'None':
                                    try:
                                        val_birth = pd.to_datetime(row['ngay_sinh']).date()
                                    except:
                                        pass
                                new_birth = st.date_input("📅 Ngày sinh", value=val_birth, format="DD/MM/YYYY")

                            if st.form_submit_button("💾 XÁC NHẬN CẬP NHẬT", width="stretch", type="primary"):
                                if not new_name:
                                    st.error("❌ Họ và tên không được để trống!")
                                else:
                                    try:
                                        #1. Chuẩn hóa dữ liệu trước khi lưu
                                        final_name = new_name.strip().title()
                                        final_addr = new_addr.strip()
                                        ngay_sinh_str = new_birth.strftime("%Y-%m-%d")

                                        #2. Chuẩn bị dữ liệu cập nhật (Payload)
                                        update_data = {
                                            "ho_ten": final_name,
                                            "so_dien_thoai": new_phone,
                                            "dia_chi": final_addr,
                                            "ngay_sinh": ngay_sinh_str,
                                            "chuc_danh": new_cd,
                                            "role": new_role
                                        }

                                        #Nếu có nhập mật khẩu mới, mới đưa vào dữ liệu cập nhật
                                        if new_pass.strip():
                                            update_data["password"] = hash_password(new_pass)

                                        #3. Thực hiện cập nhật lên Supabase Cloud
                                        supabase.table("quan_tri_vien") \
                                            .update(update_data) \
                                            .eq("username", target_u) \
                                            .execute()
                                        
                                        st.success(f"✅ Đã cập nhật thành công nhân sự: {final_name}")
                                        
                                        #Kiểm tra nếu admin đang tự sửa chính mình
                                        if target_u == st.session_state.get("username"):
                                            st.session_state.toast_message = "💡 Bạn vừa cập nhật thông tin cá nhân. Hãy tải lại trang để thấy thay đổi."
                                        st.rerun()

                                    except Exception as e:
                                        st.error(f"❌ Lỗi hệ thống Cloud: {e}")
            elif tab_name == "🛠️ Quản trị tài khoản":
                st.subheader("Cài đặt hệ thống")
                current_user = st.session_state.get("username", "")
                #--- 1. QUẢN LÝ CHỨC DANH ---
                with st.expander("📂 Quản lý danh mục Chức danh"):
                    col_a, col_b = st.columns([3, 1], vertical_alignment="bottom")
                    
                    with col_a:
                        new_cd_input = st.text_input("Nhập chức danh mới:", key="new_cd_add", placeholder="Vd: Thiết Kế")
                    
                    with col_b:
                        if st.button("➕ Thêm", width="stretch", type="secondary"):
                            if new_cd_input:
                                clean_name = new_cd_input.strip()
                                #Khởi tạo list nếu chưa có trong session
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

                #--- 2. TẠO TÀI KHOẢN MỚI ---
                with st.expander("➕ Tạo tài khoản nhân sự mới", expanded=False):
                    with st.form("add_user_full_fixed", clear_on_submit=True): 
                        c1, c2, c3 = st.columns(3)
                        n_u = c1.text_input("Username* (Viết liền không dấu)").lower().strip()
                        n_p = c2.text_input("Mật khẩu*", type="password")
                        n_r = c3.selectbox("Quyền", ["User", "Manager", "Admin", "System Admin"])
                        n_ten = st.text_input("Họ và tên nhân viên*")
                        
                        c4, c5 = st.columns(2)
                        #Lấy danh sách chức danh an toàn từ session
                        available_cd = st.session_state.get("list_chuc_danh", ["KTV Lắp đặt", "Giao nhận", "Quản lý", "Văn phòng"])
                        n_cd = c4.selectbox("Chức danh", available_cd)
                        n_phone = c5.text_input("Số điện thoại")
                        
                        submit_create = st.form_submit_button("🚀 TẠO TÀI KHOẢN", width="stretch")
                        
                        if submit_create:
                            if not n_u or not n_p or not n_ten:
                                st.error("❌ Thiếu thông tin bắt buộc!")
                            else:
                                try:
                                    #1. Kiểm tra tài khoản đã tồn tại chưa trên Supabase
                                    check_response = supabase.table("quan_tri_vien") \
                                        .select("username") \
                                        .eq("username", n_u) \
                                        .execute()
                                    
                                    #Supabase trả về dữ liệu trong thuộc tính .data (dạng list)
                                    if check_response.data:
                                        st.error(f"❌ Tài khoản `{n_u}` đã tồn tại trên hệ thống Cloud!")
                                    else:
                                        #2. Thực hiện thêm tài khoản mới (INSERT)
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
                                    #Xử lý các lỗi kết nối hoặc lỗi ràng buộc dữ liệu từ Supabase
                                    st.error(f"❌ Lỗi hệ thống Supabase: {e}")

                #--- 3. XÓA TÀI KHOẢN (BẢO VỆ COOKIE SESSION) ---
                with st.expander("🗑️ Quản lý xóa tài khoản"):
                    st.warning("⚠️ **Cảnh báo:** Xóa tài khoản sẽ gỡ bỏ hoàn toàn quyền truy cập vào hệ thống.")
                    
                    try:
                        #1. Lấy danh sách tài khoản (trừ tài khoản hiện tại)
                        res_users = supabase.table("quan_tri_vien") \
                            .select("username, ho_ten, chuc_danh, role") \
                            .neq("username", current_user) \
                            .execute()
                        
                        df_to_del = df_users[df_users['username'] != current_user].copy()

                        #2. Đếm số lượng System Admin hiện có trên hệ thống
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
                            #Tạo chuỗi hiển thị để chọn
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
                        
                        if st.button("🔥 THỰC HIỆN XÓA", type="primary", disabled=not confirm_del, width="stretch"):
                            #Cơ chế bảo vệ: Không để hệ thống mồ côi (luôn phải có ít nhất 1 System Admin)
                            if u_selected['role'] == 'System Admin' and count_sysadmin <= 1:
                                st.error("❌ **Lỗi bảo mật:** Không thể xóa System Admin cuối cùng của hệ thống!")
                            elif u_selected['role'] == 'System Admin' and u_selected['username'] == 'admin':
                                st.error("❌ **Lỗi bảo mật:** Không thể xóa tài khoản của người phát triển hệ thống!")
                            else:
                                try:
                                    #Thực hiện lệnh DELETE trên Supabase
                                    supabase.table("quan_tri_vien") \
                                        .delete() \
                                        .eq("username", u_selected['username']) \
                                        .execute()
                                    
                                    st.session_state.toast_message = f"💥 Đã xóa thành công tài khoản: {u_selected['username']} trên Cloud!"
                                    st.rerun()
                                except Exception as e: 
                                    st.error(f"❌ Lỗi khi thực hiện xóa trên Cloud: {e}")
        #--- 4. BẢO TRÌ HỆ THỐNG ---
                st.subheader("🔑 Bảo trì hệ thống")           
                with st.expander("💾 Sao lưu và Phục hồi Hệ thống"):
                    st.info("💡 **Lưu ý:** Việc phục hồi sẽ ghi đè hoàn toàn dữ liệu hiện tại.")
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("##### 📥 Xuất dữ liệu")
                        #Lấy dữ liệu từ Supabase thay vì đọc file
                        data_response = supabase.table("cham_cong") \
                            .select("username, thoi_gian, so_hoa_don, noi_dung, quang_duong, combo, thanh_tien, trang_thai, ghi_chu_duyet") \
                            .execute()
                        if data_response.data:
                            df = pd.DataFrame(data_response.data)
                            #Chuyển DataFrame thành dữ liệu Excel (dùng BytesIO)
                            import io
                            output = io.BytesIO()
                            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                                df.to_excel(writer, index=False, sheet_name='Sheet1')
                            
                            st.download_button(
                                label="Tải báo cáo Excel",
                                data=output.getvalue(),
                                file_name=f"bao_cao_{datetime.now().strftime('%d%m%Y')}.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                width="stretch"
                            )
                # Trong menu == "⚙️ Quản trị hệ thống"
                with st.expander("📥 CÔNG CỤ NẠP DỮ LIỆU CŨ (IMPORT)"):
                    st.warning("Chú ý: Tên các cột trong file Excel phải trùng khớp với tên cột trên Database (Trừ cột ID sẽ tự sinh).")
                    
                    # 1. Chọn file
                    file_upload = st.file_uploader("Chọn file Excel hoặc CSV", type=['xlsx', 'csv'])
                    
                    # 2. Chọn bảng đích
                    target_table = st.selectbox("Nạp vào bảng nào?", ["cham_cong", "cham_cong_di_lam", "quan_tri_vien"])
                    
                    if file_upload:
                        # Đọc dữ liệu
                        if file_upload.name.endswith('.csv'):
                            df_preview = pd.read_csv(file_upload)
                        else:
                            df_preview = pd.read_excel(file_upload)
                            
                        # --- BẮT ĐẦU PHẦN SỬA ---
                        # Kiểm tra và loại bỏ cột ID (không phân biệt hoa thường)
                        cols_to_drop = [c for c in df_preview.columns if c.lower() == 'id']
                        if cols_to_drop:
                            df_final = df_preview.drop(columns=cols_to_drop)
                            st.info(f"Đã loại bỏ cột {cols_to_drop} từ file để Database tự tạo ID mới.")
                        else:
                            df_final = df_preview.copy()
                        # --- KẾT THÚC PHẦN SỬA ---

                        st.write("Xem trước dữ liệu sẽ nạp (đã bỏ ID):", df_final.head(3))
                        
                        # 3. Nút bấm kích hoạt hàm
                        if st.button("🚀 BẮT ĐẦU NẠP DỮ LIỆU"):
                            with st.spinner("Đang xử lý dữ liệu lớn..."):
                                # TRUYỀN df_final (đã bỏ ID) thay vì df_preview
                                success, message = upload_data(df_final, target_table)
                                
                                if success:
                                    st.success(message)
                                    st.balloons()
                                    st.cache_data.clear()
                                else:
                                    st.error(message)
                with st.expander("🔥 Dọn dẹp dữ liệu"):
                    st.warning("⚠️ Hành động này sẽ xóa vĩnh viễn dữ liệu trên Cloud Supabase.")
                    
                    # 1. Lựa chọn chế độ xóa
                    mode_delete = st.radio("Chọn phạm vi xóa:", ["Xóa theo tháng cụ thể", "Xóa toàn bộ (Reset)"], horizontal=True)
                    
                    target_date = None
                    if mode_delete == "Xóa theo tháng cụ thể":
                        # SỬA LỖI: Dùng định dạng chuẩn DD/MM/YYYY
                        target_date = st.date_input(
                            "Chọn một ngày trong tháng muốn dọn dẹp:", 
                            value=datetime.now(), 
                            format="DD/MM/YYYY" 
                        )
                        st.info(f"💡 Hệ thống sẽ xóa toàn bộ dữ liệu của tháng {target_date.month}/{target_date.year}")
                    
                    confirm_reset = st.checkbox("Tôi xác nhận muốn thực hiện hành động này.", key="confirm_cleanup_v2")
                    
                    if st.button("🗑️ THỰC HIỆN XÓA", type="primary", disabled=not confirm_reset, width="stretch"):
                        try:
                            with st.spinner("Đang xử lý trên Cloud..."):
                                if mode_delete == "Xóa theo tháng cụ thể":
                                    # Tính toán ngày đầu tháng và cuối tháng chính xác
                                    import calendar
                                    # Ngày đầu tháng: YYYY-MM-01
                                    first_day = target_date.replace(day=1).strftime("%Y-%m-%d 00:00:00")
                                    # Ngày cuối tháng
                                    last_day_num = calendar.monthrange(target_date.year, target_date.month)[1]
                                    last_day = target_date.replace(day=last_day_num).strftime("%Y-%m-%d 23:59:59")
                                    
                                    # Thực hiện lệnh xóa có điều kiện thời gian trên Supabase
                                    supabase.table("cham_cong").delete().gte("thoi_gian", first_day).lte("thoi_gian", last_day).execute()
                                    supabase.table("cham_cong_di_lam").delete().gte("thoi_gian", first_day).lte("thoi_gian", last_day).execute()
                                    
                                    st.success(f"✅ Đã dọn dẹp xong dữ liệu tháng {target_date.month}/{target_date.year}")
                                
                                else:
                                    # Chế độ Xóa toàn bộ (Reset) [cite: 102, 103, 105]
                                    supabase.table("cham_cong").delete().neq("id", 0).execute()
                                    supabase.table("cham_cong_di_lam").delete().neq("id", 0).execute()
                                    # Chỉ xóa tài khoản không phải System Admin [cite: 105]
                                    supabase.table("quan_tri_vien").delete().neq("role", "System Admin").execute()
                                    
                                    st.success("💥 Hệ thống đã được đưa về trạng thái mặc định!")

                                st.balloons()
                                time.sleep(2)
                                st.rerun() # Làm mới giao diện để cập nhật dữ liệu [cite: 106]
                                
                        except Exception as e: 
                            st.error(f"❌ Lỗi khi thực hiện xóa trên Cloud: {e}")

            elif tab_name == "🔐 Đổi mật khẩu":
                st.subheader("Thay đổi mật khẩu")
                st.info("💡 Lưu ý: Sau khi đổi mật khẩu thành công, bạn sẽ cần đăng nhập lại.")

                current_user = st.session_state.get("username", "")

                with st.form("change_pass_form_fixed"):
                    p_old = st.text_input("Mật khẩu hiện tại", type="password")
                    p_new = st.text_input("Mật khẩu mới", type="password")
                    p_conf = st.text_input("Xác nhận mật khẩu mới", type="password")
                    
                    submit_change = st.form_submit_button("💾 CẬP NHẬT MẬT KHẨU", width="stretch", type="primary")
                    
                    if submit_change:
                        if not p_old or not p_new:
                            st.error("❌ Vui lòng nhập đầy đủ thông tin")
                        elif p_new != p_conf:
                            st.error("❌ Mật khẩu xác nhận không khớp")
                        elif len(p_new) < 4:
                            st.error("❌ Mật khẩu mới quá ngắn (tối thiểu 4 ký tự)")
                        else:
                            try:
                                #1. Mã hóa mật khẩu cũ để kiểm tra
                                import hashlib
                                pw_old_hashed = hashlib.sha256(p_old.encode()).hexdigest()
                                
                                #2. Truy vấn lấy mật khẩu hiện tại từ Supabase
                                res = supabase.table("quan_tri_vien") \
                                    .select("password") \
                                    .eq("username", current_user) \
                                    .execute()
                                
                                if res.data and res.data[0].get("password") == pw_old_hashed:
                                    #3. Mã hóa mật khẩu mới
                                    pw_new_hashed = hashlib.sha256(p_new.encode()).hexdigest()
                                    
                                    #4. Cập nhật mật khẩu mới lên Cloud
                                    supabase.table("quan_tri_vien") \
                                        .update({"password": pw_new_hashed}) \
                                        .eq("username", current_user) \
                                        .execute()
                                    
                                    st.success("✅ Đổi mật khẩu thành công!")
                                    st.balloons()
                                    
                                    #5. Xử lý đăng xuất để người dùng login lại với pass mới
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
            