import json
import os
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import uuid

# Crear la instancia de la aplicación Flask
app = Flask(__name__)

# Configuración para JWT
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Cambiar esto en producción
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

# Nombre del archivo JSON que actúa como BD
DB_FILE = 'db.json'
USERS_FILE = 'users.json'

# --- Funciones Auxiliares para Manejar el JSON ---

def cargar_datos():
    if not os.path.exists(DB_FILE):
        guardar_datos({"tareas": []})
        return {"tareas": []}
    try:
        with open(DB_FILE, 'r') as f:
            contenido = f.read()
            if not contenido:
                return {"tareas": []}
            f.seek(0)
            datos = json.load(f)
            if 'tareas' not in datos or not isinstance(datos['tareas'], list):
                 return {"tareas": []}
            return datos
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error al cargar {DB_FILE}: {e}")
        return {"tareas": []}

def guardar_datos(datos):
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(datos, f, indent=4)
    except IOError as e:
        print(f"Error al guardar en {DB_FILE}: {e}")

def cargar_usuarios():
    if not os.path.exists(USERS_FILE):
        guardar_usuarios({"usuarios": []})
        return {"usuarios": []}
    try:
        with open(USERS_FILE, 'r') as f:
            contenido = f.read()
            if not contenido:
                return {"usuarios": []}
            f.seek(0)
            datos = json.load(f)
            if 'usuarios' not in datos or not isinstance(datos['usuarios'], list):
                 return {"usuarios": []}
            return datos
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error al cargar {USERS_FILE}: {e}")
        return {"usuarios": []}

def guardar_usuarios(datos):
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(datos, f, indent=4)
    except IOError as e:
        print(f"Error al guardar en {USERS_FILE}: {e}")

# --- Endpoints de Autenticación ---

@app.route('/auth/registro', methods=['POST'])
def registro():
    if not request.is_json:
        return jsonify({"error": "La solicitud debe ser JSON"}), 400
    
    datos_usuario = request.get_json()
    
    if not datos_usuario or 'username' not in datos_usuario or 'password' not in datos_usuario:
        return jsonify({"error": "Se requiere username y password"}), 400
    
    usuarios_data = cargar_usuarios()
    usuarios = usuarios_data.get('usuarios', [])
    
    # Verificar si el usuario ya existe
    for usuario in usuarios:
        if usuario.get('username') == datos_usuario['username']:
            return jsonify({"error": "El usuario ya existe"}), 409
    
    # Crear nuevo usuario
    nuevo_usuario = {
        "id": str(uuid.uuid4()),
        "username": datos_usuario['username'],
        "password": generate_password_hash(datos_usuario['password']),
        "email": datos_usuario.get('email', '')
    }
    
    usuarios.append(nuevo_usuario)
    usuarios_data['usuarios'] = usuarios
    guardar_usuarios(usuarios_data)
    
    return jsonify({"mensaje": "Usuario registrado exitosamente", "id": nuevo_usuario['id']}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"error": "La solicitud debe ser JSON"}), 400
    
    datos_login = request.get_json()
    
    if not datos_login or 'username' not in datos_login or 'password' not in datos_login:
        return jsonify({"error": "Se requiere username y password"}), 400
    
    usuarios_data = cargar_usuarios()
    usuarios = usuarios_data.get('usuarios', [])
    
    # Buscar usuario
    usuario_encontrado = None
    for usuario in usuarios:
        if usuario.get('username') == datos_login['username']:
            usuario_encontrado = usuario
            break
    
    if not usuario_encontrado or not check_password_hash(usuario_encontrado['password'], datos_login['password']):
        return jsonify({"error": "Usuario o contraseña incorrectos"}), 401
    
    # Crear token JWT
    access_token = create_access_token(identity=usuario_encontrado['id'])
    return jsonify({"access_token": access_token, "token_type": "Bearer"}), 200

# --- Endpoints de Tareas (protegidos) ---

@app.route('/tareas', methods=['GET'])
@jwt_required()
def get_tareas():
    current_user = get_jwt_identity()
    datos = cargar_datos()
    # Aquí podrías filtrar tareas por usuario si decides implementar esa relación
    return jsonify(datos.get('tareas', []))

@app.route('/tareas/<int:tarea_id>', methods=['GET'])
@jwt_required()
def get_tarea(tarea_id):
    current_user = get_jwt_identity()
    datos = cargar_datos()
    tarea_encontrada = None
    for tarea in datos.get('tareas', []):
        if tarea.get('id') == tarea_id:
            tarea_encontrada = tarea
            break

    if tarea_encontrada:
        return jsonify(tarea_encontrada)
    else:
        return jsonify({"error": "Tarea no encontrada"}), 404

@app.route('/tareas', methods=['POST'])
@jwt_required()
def add_tarea():
    current_user = get_jwt_identity()
    
    if not request.is_json:
        return jsonify({"error": "La solicitud debe ser JSON"}), 400

    nueva_tarea_data = request.get_json()

    if not nueva_tarea_data or 'descripcion' not in nueva_tarea_data or not nueva_tarea_data['descripcion']:
        return jsonify({"error": "Falta el campo 'descripcion' o está vacío"}), 400

    datos = cargar_datos()
    tareas = datos.get('tareas', [])
    if not isinstance(tareas, list):
        tareas = []

    # Generar un nuevo ID
    if tareas:
        max_id = 0
        for tarea in tareas:
            if isinstance(tarea.get('id'), int) and tarea['id'] > max_id:
                max_id = tarea['id']
        nuevo_id = max_id + 1
    else:
        nuevo_id = 1

    # Crear la nueva tarea con el usuario que la creó
    nueva_tarea = {
        "id": nuevo_id,
        "descripcion": nueva_tarea_data['descripcion'],
        "completada": nueva_tarea_data.get('completada', False),
        "usuario_id": current_user
    }

    tareas.append(nueva_tarea)
    datos['tareas'] = tareas
    guardar_datos(datos)

    return jsonify(nueva_tarea), 201

@app.route('/tareas/<int:tarea_id>', methods=['PUT'])
@jwt_required()
def update_tarea(tarea_id):
    current_user = get_jwt_identity()
    
    if not request.is_json:
        return jsonify({"error": "La solicitud debe ser JSON"}), 400
    
    update_data = request.get_json()
    datos = cargar_datos()
    tareas = datos.get('tareas', [])
    
    tarea_encontrada = None
    index = -1
    
    for i, tarea in enumerate(tareas):
        if tarea.get('id') == tarea_id:
            # Verificar que el usuario es dueño de la tarea
            if tarea.get('usuario_id') != current_user:
                return jsonify({"error": "No tienes permiso para modificar esta tarea"}), 403
            tarea_encontrada = tarea
            index = i
            break
    
    if not tarea_encontrada:
        return jsonify({"error": "Tarea no encontrada"}), 404
    
    # Actualizar los campos permitidos
    if 'descripcion' in update_data:
        tarea_encontrada['descripcion'] = update_data['descripcion']
    if 'completada' in update_data:
        tarea_encontrada['completada'] = update_data['completada']
    
    tareas[index] = tarea_encontrada
    datos['tareas'] = tareas
    guardar_datos(datos)
    
    return jsonify(tarea_encontrada)

@app.route('/tareas/<int:tarea_id>', methods=['DELETE'])
@jwt_required()
def delete_tarea(tarea_id):
    current_user = get_jwt_identity()
    
    datos = cargar_datos()
    tareas = datos.get('tareas', [])
    
    tarea_encontrada = None
    index = -1
    
    for i, tarea in enumerate(tareas):
        if tarea.get('id') == tarea_id:
            # Verificar que el usuario es dueño de la tarea
            if tarea.get('usuario_id') != current_user:
                return jsonify({"error": "No tienes permiso para eliminar esta tarea"}), 403
            index = i
            break
    
    if index == -1:
        return jsonify({"error": "Tarea no encontrada"}), 404
    
    del tareas[index]
    datos['tareas'] = tareas
    guardar_datos(datos)
    
    return jsonify({"mensaje": "Tarea eliminada exitosamente"}), 200

# --- Manejo de errores JWT ---
@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        "error": "Token inválido",
        "mensaje": str(error)
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        "error": "Token expirado",
        "mensaje": "Por favor, inicia sesión nuevamente"
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        "error": "No autorizado",
        "mensaje": "Se requiere un token de acceso"
    }), 401

# --- Ejecución de la App ---
if __name__ == '__main__':
    # Crear los archivos si no existen al iniciar
    cargar_datos()
    cargar_usuarios()
    app.run(debug=True, port=5000)