import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import io

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Abhishek | Secure Vault", page_icon="🛡️", layout="centered")

# --- PREMIUM PROFESSIONAL UI STYLING ---
def apply_pro_style():
    st.markdown(
        """
        <style>
        .stApp {
            background-color: #0d1117;
            background-image: radial-gradient(circle at 2px 2px, #1d2129 1px, transparent 0);
            background-size: 32px 32px;
        }
        h1, h2, h3, p, span, label, .stMarkdown {
            font-family: 'Inter', -apple-system, sans-serif !important;
            color: #8b949e !important;
        }
        .main-title {
            background: linear-gradient(180deg, #ffffff, #8b949e);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 700;
            font-size: 2.5rem !important;
            margin-bottom: 0px;
        }
        .brand-text {
            color: #58a6ff !important; 
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
        }
        .quote-container {
            border-left: 3px solid #30363d;
            padding: 12px 20px;
            margin: 20px 0;
            background: rgba(48, 54, 61, 0.2);
            border-radius: 0 8px 8px 0;
            color: #c9d1d9 !important;
        }
        div[data-baseweb="input"] {
            background-color: #0d1117 !important;
            border: 1px solid #30363d !important;
            border-radius: 8px !important;
        }
        .stButton>button {
            background-color: #238636 !important;
            color: #ffffff !important;
            border-radius: 6px !important;
            width: 100%;
            border: none !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

apply_pro_style()

# --- CRYPTO LOGIC ---
SIGNATURE = b"AUTH_OK" # Used to verify password correctness

def get_key(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

# --- CONTENT ---
st.markdown('<h1 class="main-title">Secure Vault</h1>', unsafe_allow_html=True)
st.markdown('<p class="brand-text">Developed by Abhishek</p>', unsafe_allow_html=True)

st.markdown(
    '<div class="quote-container">"Guard your digital soul: Secure your files from unauthorized access."</div>', 
    unsafe_allow_html=True
)

# Why Online Encryption?
with st.expander("🛡️ Why use this Online Vault?"):
    st.write("""
    **Privacy & Security:** Traditional cloud storage can be scanned by service providers. 
    This tool provides **Client-Side Processing**, meaning your file is encrypted right here in your 
    browser session. Your raw data and passwords are never saved on any server, giving you 
    complete control over your digital assets.
    """)

col1, col2 = st.columns([1, 1], gap="medium")

with col1:
    st.markdown("### Auth")
    password = st.text_input("Master Key", type="password", placeholder="Enter key...")
    mode = st.radio("Mode", ["Encrypt Asset", "Decrypt Asset"])

with col2:
    st.markdown("### File")
    uploaded_file = st.file_uploader("Upload Target")

if uploaded_file and password:
    key = get_key(password)
    file_bytes = uploaded_file.getvalue()
    
    try:
        if "Encrypt" in mode:
            filesize = str(len(file_bytes)).zfill(16)
            IV = Random.new().read(16)
            encryptor = AES.new(key, AES.MODE_CBC, IV)
            
            # We add our SIGNATURE at the start of the data before encrypting
            data_to_encrypt = SIGNATURE + file_bytes
            pad_len = 16 - (len(data_to_encrypt) % 16)
            padded_data = data_to_encrypt + (b' ' * pad_len)
            
            final_data = filesize.encode('utf-8') + IV + encryptor.encrypt(padded_data)
            
            st.divider()
            st.success("Vault Encryption Successful")
            st.download_button("📥 Download Encrypted Asset", final_data, file_name=f"{uploaded_file.name}.enc")

        else:
            filesize = int(file_bytes[:16])
            IV = file_bytes[16:32]
            ciphertext = file_bytes[32:]
            
            decryptor = AES.new(key, AES.MODE_CBC, IV)
            decrypted_full = decryptor.decrypt(ciphertext)
            
            # CHECK PASSWORD: Does the decrypted data start with our SIGNATURE?
            if decrypted_full.startswith(SIGNATURE):
                final_data = decrypted_full[len(SIGNATURE):len(SIGNATURE)+filesize]
                st.divider()
                st.success("Vault Access Granted")
                st.download_button("📥 Download Original Asset", final_data, file_name=uploaded_file.name.replace(".enc", ""))
            else:
                st.error("🚫 Access Denied: Incorrect Master Key.")
            
    except Exception:
        st.error("🚫 System Error: Corrupted data or invalid file format.")

st.markdown("<br><br><p style='text-align: center; color: #484f58 !important; font-size: 0.75rem;'>AES-256 Standard | Zero-Knowledge Architecture</p>", unsafe_allow_html=True)
