import json
import os
from flask import Flask, request, jsonify

# Crear la instancia de la aplicación Flask
app = Flask(__name__)

# Nombre del archivo JSON que actúa como BD
DB_FILE = 'db.json'

# --- Funciones Auxiliares para Manejar el JSON ---

def cargar_datos():
    if not os.path.exists(DB_FILE):
        guardar_datos({"tareas": []})
        return {"tareas": []}
    # Usamos 'r+' para poder leer y escribir, y 'a+' si queremos crear si no existe,
    # pero 'r' es suficiente si garantizamos creación en el if anterior.
    # Es crucial manejar el caso de archivo vacío.
    try:
        with open(DB_FILE, 'r') as f:
            contenido = f.read()
            if not contenido: # Si el archivo está vacío
                return {"tareas": []}
            # Volvemos al inicio del archivo antes de intentar leer JSON
            f.seek(0)
            datos = json.load(f)
            # Asegurarnos que la clave 'tareas' existe y es una lista
            if 'tareas' not in datos or not isinstance(datos['tareas'], list):
                 return {"tareas": []} # Devolver estructura válida si el formato es incorrecto
            return datos
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error al cargar {DB_FILE}: {e}")
        # Si hay error, es más seguro devolver una estructura vacía/por defecto
        return {"tareas": []}


def guardar_datos(datos):
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(datos, f, indent=4)
    except IOError as e:
        print(f"Error al guardar en {DB_FILE}: {e}")

# --- Endpoints API ---

# Endpoint para OBTENER TODAS las tareas (GET /tareas)
@app.route('/tareas', methods=['GET'])
def get_tareas():
    datos = cargar_datos()
    # Devolvemos la lista de tareas, asegurándonos de que existe
    return jsonify(datos.get('tareas', []))

# Endpoint para OBTENER UNA tarea por ID (GET /tareas/<id>)
@app.route('/tareas/<int:tarea_id>', methods=['GET'])
def get_tarea(tarea_id):
    datos = cargar_datos()
    tarea_encontrada = None
    # Iteramos sobre la lista de tareas obtenida con .get para seguridad
    for tarea in datos.get('tareas', []):
        if tarea.get('id') == tarea_id: # Usamos .get para evitar KeyError si 'id' no existe
            tarea_encontrada = tarea
            break

    if tarea_encontrada:
        return jsonify(tarea_encontrada)
    else:
        return jsonify({"error": "Tarea no encontrada"}), 404

# Endpoint para CREAR una nueva tarea (POST /tareas)
@app.route('/tareas', methods=['POST'])
def add_tarea():
    if not request.is_json:
        return jsonify({"error": "La solicitud debe ser JSON"}), 400

    nueva_tarea_data = request.get_json()

    if not nueva_tarea_data or 'descripcion' not in nueva_tarea_data or not nueva_tarea_data['descripcion']:
         # Verificamos que hay datos, que 'descripcion' existe y no está vacía
        return jsonify({"error": "Falta el campo 'descripcion' o está vacío"}), 400

    datos = cargar_datos()
    # Aseguramos que 'tareas' es una lista, incluso si cargar_datos falló parcialmente
    tareas = datos.get('tareas', [])
    if not isinstance(tareas, list): # Doble chequeo por si el JSON estaba corrupto
        tareas = []

    # Generar un nuevo ID
    if tareas:
        # Asegurarnos de que los IDs son numéricos antes de calcular el máximo
        max_id = 0
        for tarea in tareas:
            if isinstance(tarea.get('id'), int) and tarea['id'] > max_id:
                max_id = tarea['id']
        nuevo_id = max_id + 1
    else:
        nuevo_id = 1

    # Crear la nueva tarea
    nueva_tarea = {
        "id": nuevo_id,
        "descripcion": nueva_tarea_data['descripcion'],
        # Usamos .get con valor por defecto False para 'completada'
        "completada": nueva_tarea_data.get('completada', False)
    }

    tareas.append(nueva_tarea)
    datos['tareas'] = tareas # Actualizamos la lista en la estructura de datos
    guardar_datos(datos) # Guardamos la estructura completa

    return jsonify(nueva_tarea), 201


# --- Ejecución de la App ---
if __name__ == '__main__':
    # Crear el archivo db.json si no existe al iniciar
    cargar_datos()
    app.run(debug=True, port=5000) # Especificar puerto es opcional, por defecto es 5000
