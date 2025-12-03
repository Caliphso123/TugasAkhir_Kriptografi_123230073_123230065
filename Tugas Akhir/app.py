from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from config import Config
import base64
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, flash
from models import db, User, Note
from crypto_utils import (
    hash_password, 
    verify_password, 
    derive_key,            
    hash_user_id, 
    generate_salt,
    encrypt_data,
    decrypt_data,
    generate_secret_code,
    hash_secret_code,
    verify_secret_code,
    derive_shared_key 
)
from stegano_utils import (
    encode_stegano,        
    decode_stegano         
)
import jwt
import datetime
import os
from io import BytesIO
import secrets
import traceback
from cryptography.exceptions import InvalidTag

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

def create_auth_token(user_id):
    """Membuat JWT token untuk sesi"""
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    except Exception as e:
        return str(e)


@app.route('/register', methods=['POST'])
def register_user(): 
    
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return render_template('register.html', error="Username dan password diperlukan!")

    if User.query.filter_by(username=username).first():
        return render_template('register.html', error="Username sudah terdaftar!")

    password_hash = hash_password(password)
    
    user_salt = generate_salt()

    new_user = User(
        username=username, 
        password_hash=password_hash,
        user_salt=user_salt,
    )
    db.session.add(new_user)
    
    try:
        db.session.commit() 
        new_user.id_hash = hash_user_id(new_user.id)
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        print(f"Database error during registration: {e}")
        return render_template('register.html', error="Registrasi gagal karena masalah database.")

    return redirect(url_for('login_page', success="Registrasi berhasil! Silakan Login."))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error="Username dan password wajib diisi.")

        user = User.query.filter_by(username=username).first()

        if user and verify_password(user.password_hash, password):
            try:
                user_master_key = derive_key(password, user.user_salt)
                
                session['umk'] = base64.b64encode(user_master_key).decode('utf-8')
                session['user_id'] = user.id
                
                return redirect(url_for('dashboard')) 
                
            except Exception as e:
                print(f"FATAL LOGIN ERROR (KDF/Session): {e}") 
                return render_template('login.html', error="Terjadi kesalahan server. Coba lagi.")

        else:
            return render_template('login.html', error="Username atau password salah.")
    
    success_message = request.args.get('success')
    return render_template('login.html', success=success_message)

@app.route('/note/create', methods=['POST'])
def create_note():
    if 'user_id' not in session or 'umk' not in session:
        return jsonify({"message": "Akses ditolak. Silakan login kembali."}), 403
    
    data = request.get_json()
    note_content = data.get('content')
    
    if not note_content:
        return jsonify({"message": "Konten catatan tidak boleh kosong."}), 400

    user_id = session.get('user_id')
    
    try:
        umk_b64 = session['umk']
        umk = base64.b64decode(umk_b64) 
    except Exception:
        return jsonify({"message": "Sesi kunci UMK rusak atau hilang."}), 403

    user = User.query.get(user_id)
    if not user:
         return jsonify({"message": "User tidak ditemukan"}), 404

    note_content_bytes = note_content.encode('utf-8')

    try:
        encrypted_data_tuple = encrypt_data(umk, note_content_bytes)
        encrypted_content = encrypted_data_tuple[0]
        nonce = encrypted_data_tuple[1]
        
        snippet_content = note_content_bytes[:30]
        encrypted_title_tuple = encrypt_data(umk, snippet_content)
        encrypted_title = encrypted_title_tuple[0]

    except Exception as e:
        print(f"Enkripsi gagal: {e}")
        return jsonify({"message": f"Enkripsi gagal: {e}"}), 500
        
    new_note = Note(
        user_id_hash=user.id_hash, 
        
        encrypted_content=encrypted_content,
        nonce=nonce,
        encrypted_title_snippet=encrypted_title
    )
    db.session.add(new_note)
    db.session.commit()

    return jsonify({
        "message": "Catatan berhasil dibuat (Terenkripsi)",
        "note_id": new_note.id
    }), 201

@app.route('/note/<int:note_id>', methods=['GET'])
def view_note(note_id):
    if 'umk' not in session:
        return jsonify({"message": "Akses ditolak. Silakan login kembali."}), 403
        
    note = Note.query.get_or_404(note_id)
    
    try:
        umk_b64 = session['umk']
        umk = base64.b64decode(umk_b64)
    except Exception as e:
        return jsonify({"message": "Sesi kunci rusak atau hilang."}), 403

    try:
        decrypted_content = decrypt_data(
            key=umk, 
            encrypted_content=note.encrypted_content, 
            nonce=note.nonce
        )

        if note.original_filename:
            content_to_return = base64.b64encode(decrypted_content).decode('utf-8')
        else:
            content_to_return = decrypted_content.decode('utf-8')
            
    except Exception as e:
        return jsonify({"message": "Gagal mendekripsi data. Kunci salah atau integritas data rusak.", "error": str(e)}), 400

    return jsonify({
        "note_id": note.id,
        "original_filename": note.original_filename,
        "created_at": note.created_at.isoformat(),
        "content": content_to_return
    })

@app.route('/admin/notes', methods=['GET'])
def admin_view_metadata():
    """Admin hanya dapat melihat metadata, bukan konten."""
    
    notes = Note.query.all()
    
    output = []
    for note in notes:
        output.append({
            "note_id": note.id,
            "user_id_hash": note.user_id_hash, 
            "created_at": note.created_at.isoformat(),
            "data_type": note.data_type,
            "content_status": "TERENKRIPSI (TIDAK DAPAT DIAKSES OLEH ADMIN)" 
        })
    return jsonify(output)

@app.route('/')
def index():
    return redirect(url_for('register_page'))

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/ui/register', methods=['POST'])
def ui_register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return render_template('register.html', message="Username dan password diperlukan!")

    if User.query.filter_by(username=username).first():
        return render_template('register.html', message="Username sudah terdaftar!")

    password_hash = hash_password(password)
    user_salt = generate_salt()
    
    new_user = User(
        username=username, 
        password_hash=password_hash,
        user_salt=user_salt
    )
    db.session.add(new_user)
    
    try:
        db.session.commit()
    except:
        db.session.rollback()
        return render_template('register.html', message="Terjadi kesalahan database!")

    new_user.id_hash = hash_user_id(new_user.id)
    db.session.commit()

    return render_template('register.html', message="Registrasi berhasil! Silakan login.")


@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'umk' not in session:
        return redirect(url_for('login_page')) 

    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    all_notes = Note.query.filter(
        Note.user_id == user_id,
        Note.deleted_at.is_(None)
    ).all()
    
    decrypted_text_notes = []
    decrypted_file_notes = []
    decrypted_stegano_notes = [] 
    
    try:
        umk_b64 = session['umk']
        user_master_key = base64.b64decode(umk_b64)
    except Exception as e:
        print(f"Error decoding UMK: {e}")
        session.pop('umk', None)
        session.pop('user_id', None)
        return redirect(url_for('login_page'))

    for note in all_notes:
        decrypted_content = None
        
        try:
            if note.data_type != 'STEGANO_SHARE':
                decrypted_content = decrypt_data(
                    user_master_key, 
                    note.encrypted_content, 
                    note.nonce
                ).decode('utf-8', errors='ignore')
            
        except Exception as e:
            decrypted_content = f"!! ERROR DEKRIPSI: Kunci atau Data Salah."
            print(f"Dekripsi gagal untuk catatan ID {note.id}: {e}")

        note_data = {
            'id': note.id,
            'original_filename': note.original_filename,
            'content': decrypted_content,
            'created_at': note.created_at,
            'data_type': note.data_type, 
            'encrypted_content': note.encrypted_content if note.data_type == 'STEGANO_SHARE' else None
        }

        if note.data_type == 'STEGANO_SHARE':
            decrypted_stegano_notes.append(note_data) 
        elif note.original_filename:
            decrypted_file_notes.append(note_data)
        else:
            decrypted_text_notes.append(note_data)
    
    for note_dict in decrypted_stegano_notes:
        if 'encrypted_content' in note_dict and note_dict['encrypted_content']:
            try:
                base64_string = base64.b64encode(note_dict['encrypted_content']).decode('utf-8')
            except Exception as e:
                print(f"Gagal mengonversi Base64: {e}")
                base64_string = ""

            note_dict['base64_stego_image'] = base64_string
        else:
            note_dict['base64_stego_image'] = ""

    return render_template('dashboard.html', 
                            user=user, 
                            text_notes=decrypted_text_notes,
                            file_notes=decrypted_file_notes,
                            stegano_notes=decrypted_stegano_notes)

@app.route('/note/new', methods=['GET'])
def new_note_page():

    if 'umk' not in session:
        return redirect(url_for('login_page')) 

    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    return render_template('create_note.html', user=user)

@app.route('/file/new', methods=['GET'])
def add_file_page():
    if 'umk' not in session:
        return redirect(url_for('login_page')) 

    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    return render_template('add_file.html', user=user)

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('umk', None)
    session.pop('user_id', None)

    return redirect(url_for('login_page'))

@app.shell_context_processor
def make_shell_context():
    from models import db, User, Note 
    return {'db': db, 'User': User, 'Note': Note, 'app': app}

@app.route('/ui/note/create', methods=['POST'])
def ui_create_note():
    if 'umk' not in session:
        return redirect(url_for('login_page')) 

    user_id = session.get('user_id')
    user_master_key = base64.b64decode(session['umk'])
    
    content = request.form.get('content')
    uploaded_file = request.files.get('file')
    
    note_content_to_encrypt = None
    filename_to_store = None 

    if content:
        note_content_to_encrypt = content.encode('utf-8')
        
    elif uploaded_file and uploaded_file.filename != '':
        note_content_to_encrypt = uploaded_file.read()
        filename_to_store = uploaded_file.filename
        
    else:
        return redirect(url_for('dashboard')) 
    
    try:
        encrypted_data_tuple = encrypt_data(user_master_key, note_content_to_encrypt)
    except Exception as e:
        print(f"Encryption failed: {e}")
        return render_template('dashboard.html', error="Gagal mengenkripsi data.")

    ciphertext = encrypted_data_tuple[0]
    nonce = encrypted_data_tuple[1]
    
    new_note = Note(
        user_id=user_id,
        encrypted_content=ciphertext,
        nonce=nonce, 
        original_filename=filename_to_store 
    )
    db.session.add(new_note)
    db.session.commit()

    return redirect(url_for('dashboard'))


@app.route('/ui/note/delete', methods=['POST'])
def ui_delete_note():
    if 'umk' not in session:
        return redirect(url_for('login_page')) 

    user_id = session.get('user_id')
    note_id = request.form.get('note_id')

    if not note_id:
        return redirect(url_for('dashboard')) 

    note_to_delete = Note.query.filter_by(id=note_id, user_id=user_id).first()

    if note_to_delete:
        note_to_delete.deleted_at = datetime.datetime.now(datetime.timezone.utc)
        note_to_delete.deleted_by_user_id = user_id
        
        db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/ui/note/download/<int:note_id>', methods=['GET'])
def ui_download_note(note_id):
    if 'umk' not in session:
        return redirect(url_for('login_page'))
    
    user_id = session.get('user_id')
    note = Note.query.filter_by(id=note_id, user_id=user_id, deleted_at=None).first_or_404()
    
    try:
        umk_b64 = session['umk']
        user_master_key = base64.b64decode(umk_b64)
    except Exception:
        return redirect(url_for('dashboard', error="Kunci sesi rusak."))

    if not note.original_filename:
        return redirect(url_for('dashboard', error="Catatan ini bukan file untuk diunduh."))

    try:
        decrypted_file_content = decrypt_data(
            key=user_master_key, 
            encrypted_content=note.encrypted_content, 
            nonce=note.nonce
        )

        from io import BytesIO
        file_stream = BytesIO(decrypted_file_content)
        
        return send_file(
            file_stream,
            as_attachment=True,
            download_name=note.original_filename,
            mimetype='application/octet-stream' 
        )

    except Exception as e:
        print(f"File download/dekripsi gagal: {e}")
        return redirect(url_for('dashboard', error=f"Gagal mendekripsi file: {str(e)}"))
    
@app.route('/share_stegano', methods=['POST'])
def share_stegano():
    if 'user_id' not in session:
        return redirect(url_for('login_page')) 
    
    sender_id = session.get('user_id')
    
    secret_message = request.form.get('secret_message')
    carrier_file = request.files.get('carrier_image')
    
    if not secret_message or not carrier_file:
        flash("Data tidak lengkap. Pesan rahasia dan gambar pembawa harus diisi.", 'danger')
        return redirect(url_for('share_stegano_page'))
    
    carrier_bytes = carrier_file.read()

    code_salt = secrets.token_bytes(16)
    secret_code = generate_secret_code(10) 

    try:
        shared_key = derive_shared_key(secret_code, code_salt)
        code_hash = hash_secret_code(secret_code, code_salt) 
        
    except Exception as e:
        print(f"Error KDF/Hashing: {e}")
        flash(f"Gagal generate kunci: {e}", 'danger')
        return redirect(url_for('share_stegano_page'))

    try:
        secret_message_bytes = secret_message.encode('utf-8')
        encrypted_tuple = encrypt_data(shared_key, secret_message_bytes)
        encrypted_secret = encrypted_tuple[0]
        nonce = encrypted_tuple[1]
        stegano_image_bytes = encode_stegano(carrier_bytes, encrypted_secret)

    except Exception as e:
        print(f"Error Enkripsi/Stegano: {e}")
        flash(f"Enkripsi/Stegano gagal: {e}", 'danger')
        return redirect(url_for('share_stegano_page'))

    new_note = Note(
        user_id=sender_id, 
        encrypted_content=stegano_image_bytes,
        hidden_payload_bytes=encrypted_secret, 
        nonce=nonce, 
        code_salt=code_salt, 
        original_filename=f"stegano_{carrier_file.filename}", 
        data_type="STEGANO_SHARE", 
        secret_code_hash=code_hash
    )
    
    try:
        db.session.add(new_note)
        db.session.commit()
        return render_template('stegano_success.html', secret_code=secret_code)

    except Exception as e:
        db.session.rollback()
        print("\n" * 5)
        print("!!!" * 10)
        print("!!! GAGAL MENYIMPAN/MEMPROSES STEGANOGRAFI !!!")
        traceback.print_exc() 
        print(f"Detail Error: {e}")
        
        flash(f"Gagal memproses Stegano: {e}", 'danger')
        return redirect(url_for('share_stegano_page'))

@app.route('/view_secret_stegano_public/<int:note_id>', methods=['POST'])
def view_secret_stegano_public(note_id):
    note = Note.query.get_or_404(note_id)
    data = request.get_json()
    if not data or 'input_secret_code' not in data:
        return jsonify({"message": "Permintaan tidak valid."}, 400)
    input_code = data.get('input_secret_code')
    encrypted_secret = note.hidden_payload_bytes
    if not encrypted_secret:
        print("DIAGNOSTIK: note.hidden_payload_bytes KOSONG.")
        return jsonify({"message": "Pesan rahasia terenkripsi tidak ditemukan di database. (Payload kosong)."}, 404)
        
    print(f"DIAGNOSTIK: Payload terenkripsi ditemukan, panjang: {len(encrypted_secret)} bytes.")

    if not verify_secret_code(input_code, note.secret_code_hash, note.code_salt):
        print("DIAGNOSTIK: Verifikasi Kode Rahasia Gagal. (Kemungkinan hash/salt tidak konsisten).")
        return jsonify({"message": "Kode rahasia salah atau tidak valid."}, 403)
    
    try:
        if not note.code_salt:
            print("DIAGNOSTIK: code_salt KOSONG.")
            return jsonify({"message": "Data kunci tidak lengkap (Salt hilang)."}, 500)

        shared_key = derive_shared_key(input_code, salt=note.code_salt) 
        
        print(f"DIAGNOSTIK: Shared Key dibuat dengan Code Salt: {note.code_salt.hex()}")

    except Exception as e:
        print(f"ERROR Derivasi Kunci: {e}")
        traceback.print_exc()
        return jsonify({"message": "Gagal menurunkan kunci enkripsi."}, 500)

    try:
        decrypted_secret_bytes = decrypt_data(
            shared_key, 
            encrypted_secret, 
            note.nonce 
        )
        
        decrypted_secret = decrypted_secret_bytes.decode('utf-8')
        
        if not decrypted_secret:
            return jsonify({"message": "Sukses, tapi pesan rahasia yang dienkripsi ternyata kosong."}, 200)

        return jsonify({"message": "Sukses", "secret_content": decrypted_secret}), 200

    except InvalidTag:
        print("!!! DEKRIPSI GAGAL: InvalidTag. Data di DB mungkin rusak atau KDF MISMATH!!!")
        return jsonify({"message": "Gagal mendekripsi pesan (Kode Rahasia Salah / Data Rusak)."}, 403)
    
    except UnicodeDecodeError:
        print("!!! DEKRIPSI GAGAL: Output bukan UTF-8 (Data Rusak) !!!")
        return jsonify({"message": "Gagal mendekripsi pesan (Data Rusak)."}, 400)
        
    except Exception as e:
        print(f"ERROR Dekripsi Umum: {e}")
        traceback.print_exc()
        return jsonify({"message": f"Terjadi kesalahan: {e}"}, 400)
    
@app.route('/ui/share_stegano_page', methods=['GET'])
def share_stegano_page():
    """Menampilkan halaman form untuk membuat catatan Steganografi."""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('share_stegano_page.html')

if __name__ == '__main__':
    db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'securevault.db')
    
    with app.app_context():
        if not os.path.exists(db_path):
            db.create_all()
            print("Database 'securevault.db' berhasil dibuat dan siap.")
        else:
            print("Database 'securevault.db' sudah ada. Server berjalan.")

    app.run(debug=True)