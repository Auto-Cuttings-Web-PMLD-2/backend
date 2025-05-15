from flask import Blueprint, request, jsonify, url_for
from app.models import Project
from app.models import User
from app import db
from ultralytics import YOLO
from PIL import Image

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token
from flask_jwt_extended import jwt_required, get_jwt_identity
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from app.utils import send_reset_email
from werkzeug.security import _hash_internal

import torch
import os
import shutil
import time
import uuid
import logging

# Helper function
def clear_prediction_folder():
    pred_path = os.path.join("runs", "segment", "predict")
    if os.path.exists(pred_path):
        shutil.rmtree(pred_path)
        
def generate_reset_token(email, expires_sec=120):
    s = URLSafeTimedSerializer(current_app.config['JWT_SECRET_KEY'])
    return s.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, max_age=120):
    s = URLSafeTimedSerializer(current_app.config['JWT_SECRET_KEY'])
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=max_age)
    except Exception:
        return None
    return email

def load_model():
    model = YOLO("AI_Models/best.pt")
    return model


# BP AUTOCUTTING
analyze_bp = Blueprint("analyze", __name__)
logging.basicConfig(level=logging.DEBUG)

@analyze_bp.route("/analyze", methods=["POST"])
# @jwt_required()
def analyze():
    UPLOAD_FOLDER = 'temp_images'
    SEGMENTED_FOLDER = 'static/segmented'

    # Muat model YOLO
    model = load_model()

    # Cek apakah ada file gambar dalam request
    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400

    # Ambil gambar dari request
    image_file = request.files['image']

    # Buat folder jika belum ada
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(SEGMENTED_FOLDER, exist_ok=True)

    # Simpan gambar yang diupload
    input_filename = f"{uuid.uuid4().hex}.jpg"
    input_path = os.path.join(UPLOAD_FOLDER, input_filename)
    image_file.save(input_path)

    # Buka gambar untuk perhitungan total pixel
    original_image = Image.open(input_path)
    total_pixels = original_image.size[0] * original_image.size[1]

    # Bersihkan folder hasil prediksi
    clear_prediction_folder()

    # Proses prediksi model
    start_time = time.time()
    results = model.predict(source=input_path, save=True, save_txt=True, save_conf=True)
    end_time = time.time()

    endResult = {}

    # Proses hasil prediksi
    for r in results:
        sandStoneCount = 0
        siltStoneCount = 0
        class_pixel_counts = {"sandstone": 0, "siltstone": 0}

        for box in r.boxes:
            cls_id = int(box.cls[0])
            if cls_id == 0:
                sandStoneCount += 1
            elif cls_id == 1:
                siltStoneCount += 1

        if r.masks is not None:
            masks = r.masks.data
            classes = r.boxes.cls
            for i, mask in enumerate(masks):
                cls_id = int(classes[i])
                label = model.names[cls_id]
                pixel_count = mask.sum().item()
                if label in class_pixel_counts:
                    class_pixel_counts[label] += pixel_count

        # Dapatkan gambar segmented
        segmented_folder = os.path.join("runs", "segment", "predict")
        segmented_image_name = sorted(os.listdir(segmented_folder))[0]
        segmented_input_path = os.path.join(segmented_folder, segmented_image_name)

        output_filename = f"{uuid.uuid4().hex}.jpg"
        segmented_save_path = os.path.join(SEGMENTED_FOLDER, output_filename)
        Image.open(segmented_input_path).save(segmented_save_path)

        # URL untuk gambar segmented
        segmented_url = url_for('static', filename=f'segmented/{output_filename}', _external=True)

        # Hasil analisis
        endResult.update({
            "sandStoneCount": sandStoneCount,
            "sandStoneCoverage": class_pixel_counts["sandstone"] / total_pixels,
            "siltStoneCount": siltStoneCount,
            "siltStoneCoverage": class_pixel_counts["siltstone"] / total_pixels,
            "inferenceTime": end_time - start_time,
            "segmentedImageURL": segmented_url
        })

    return jsonify(endResult)



# =====================================================================
# BP MANAGE PROJECTS
project_bp = Blueprint("project", __name__)
logging.basicConfig(level=logging.DEBUG)


# READ ALL - Hanya menampilkan project milik user yang login
@project_bp.route("/projects", methods=["GET"])
@jwt_required()
def get_all_projects():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({"message": "User tidak ditemukan"}), 404

    projects = Project.query.filter_by(user_id=user.id).all()

    result = [
        {
            "id": p.id,
            "name": p.name,
            "sandStoneCount": p.sandStoneCount,
            "sandStoneCoverage": p.sandStoneCoverage,
            "siltStoneCount": p.siltStoneCount,
            "siltStoneCoverage": p.siltStoneCoverage,
            "segmentedImageURL": p.segmentedImageURL,
            "user_id": p.user_id
        } for p in projects
    ]

    return jsonify(result), 200


# READ ONE - Dengan verifikasi kepemilikan
@project_bp.route("/projects/<int:id>", methods=["GET"])
@jwt_required()
def get_project(id):
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({"message": "User tidak ditemukan"}), 404

    project = Project.query.get_or_404(id)

    if project.user_id != user.id:
        return jsonify({"message": "Anda tidak berhak mengakses project ini"}), 403

    return jsonify({
        "id": project.id,
        "name": project.name,
        "sandStoneCount": project.sandStoneCount,
        "sandStoneCoverage": project.sandStoneCoverage,
        "siltStoneCount": project.siltStoneCount,
        "siltStoneCoverage": project.siltStoneCoverage,
        "segmentedImageURL": project.segmentedImageURL,
        "user_id": project.user_id
    }), 200


# CREATE - Menyimpan project untuk user yang login
@project_bp.route("/projects", methods=["POST"])
@jwt_required()
def create_project():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({"message": "User tidak ditemukan"}), 404

    data = request.json

    new_project = Project(
        name=data['name'],
        sandStoneCount=data['sandStoneCount'],
        sandStoneCoverage=data['sandStoneCoverage'],
        siltStoneCount=data['siltStoneCount'],
        siltStoneCoverage=data['siltStoneCoverage'],
        segmentedImageURL=data['segmentedImageURL'],
        user_id=user.id
    )

    db.session.add(new_project)
    db.session.commit()

    return jsonify({
        "message": "Project berhasil dibuat",
        "project_id": new_project.id
    }), 201


# UPDATE - Hanya jika project dimiliki oleh user
@project_bp.route("/projects/<int:id>", methods=["PUT"])
@jwt_required()
def update_project(id):
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({"message": "User tidak ditemukan"}), 404

    project = Project.query.get_or_404(id)

    if project.user_id != user.id:
        return jsonify({"message": "Anda tidak berhak mengubah project ini"}), 403

    data = request.json

    project.name = data.get('name', project.name)
    project.sandStoneCount = data.get('sandStoneCount', project.sandStoneCount)
    project.sandStoneCoverage = data.get('sandStoneCoverage', project.sandStoneCoverage)
    project.siltStoneCount = data.get('siltStoneCount', project.siltStoneCount)
    project.siltStoneCoverage = data.get('siltStoneCoverage', project.siltStoneCoverage)
    project.segmentedImageURL = data.get('segmentedImageURL', project.segmentedImageURL)

    db.session.commit()

    return jsonify({"message": "Project berhasil diperbarui"}), 200


# DELETE - Hanya jika project dimiliki oleh user
@project_bp.route("/projects/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_project(id):
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({"message": "User tidak ditemukan"}), 404

    project = Project.query.get_or_404(id)

    if project.user_id != user.id:
        return jsonify({"message": "Anda tidak berhak menghapus project ini"}), 403

    db.session.delete(project)
    db.session.commit()

    return jsonify({"message": "Project berhasil dihapus"}), 200


# =====================================================================
# BP AUTHENTICATION

auth_bp = Blueprint('auth', __name__)

# Route untuk Registrasi (Sign Up)
@auth_bp.route('/signup', methods=['POST'])
def signup():    
    data = request.get_json()

    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    # Periksa apakah pengguna sudah ada
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'message': 'Email sudah terdaftar'}), 400

    # hashed_password = generate_password_hash(password)
    print(password)
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256:600000")
    
    # Membuat pengguna baru
    new_user = User(email=email, username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Pengguna berhasil dibuat!'}), 201


# Route untuk Login
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    print(password)
    print(user.password)
    print("Check:", check_password_hash(user.password, password))

    if not user:
        return jsonify({'message': 'Email atau password salah'}), 401

    # print(user.password)
    # print(password)
    # Verifikasi password dengan fungsi bawaan
    if not check_password_hash(user.password, password):
        return jsonify({'message': 'Email atau password salah'}), 401

    access_token = create_access_token(identity=user.email)
    return jsonify({'message': 'Login berhasil!', 'access_token': access_token}), 200


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Email tidak ditemukan'}), 404

    token = generate_reset_token(email)
    reset_link = f'http://localhost:3000/reset-password/{token}' 

    send_reset_email(email, reset_link)

    return jsonify({'message': 'Link reset password telah dikirim ke email Anda'})


@auth_bp.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        return jsonify({'message': 'Token tidak valid atau sudah kadaluarsa'}), 400

    data = request.get_json()
    new_password = data.get('new_password')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Pengguna tidak ditemukan'}), 404

    # user.password = generate_password_hash(new_password)
    user.password = generate_password_hash(new_password, method="pbkdf2:sha256:600000")
    db.session.commit()

    return jsonify({'message': 'Password berhasil diubah'})



# =====================================================================
# BP MANAGE USERS
user_bp = Blueprint("user", __name__)
logging.basicConfig(level=logging.DEBUG)

# CREATE
@user_bp.route("/users", methods=["POST"])
def add_user():
    data = request.json
    user = User(
        email=data.get('email'),
        username=data.get('username'),
        password=data.get('password'),
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({
        "message": "User added successfully",
        "data": data
    }), 201


# READ ALL
@user_bp.route("/users", methods=["GET"])
def get_all_users():
    users = User.query.all()
    result = []
    for u in users:
        result.append({
            "id": u.id,
            "email": u.email,
            "username": u.username,
            "password": u.password
        })
    return jsonify(result)


# READ ONE
@user_bp.route("/users/<int:id>", methods=["GET"])
def get_user(id):
    user = User.query.get_or_404(id)
    return jsonify({
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "password": user.password
    })


# UPDATE
@user_bp.route("/users/<int:id>", methods=["PUT"])
def update_user(id):
    user = User.query.get_or_404(id)
    data = request.json

    user.email = data.get('email', user.email)
    user.username = data.get('username', user.username)
    user.password = data.get('password', user.password)

    db.session.commit()
    return jsonify({"message": "User updated successfully"})


# DELETE
@user_bp.route("/users/<int:id>", methods=["DELETE"])
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"})

