// index.js

// ---------------------------------
// DEPENDENCIAS
// ---------------------------------
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const swaggerUi = require('swagger-ui-express');
const db = require('./db'); // Asegúrate que tu archivo db.js esté configurado
const swaggerSpec = require('./swagger'); // Tu archivo swagger.js
require('dotenv').config();

// ---------------------------------
// CONFIGURACIÓN INICIAL
// ---------------------------------
const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(express.json());

// ---------------------------------
// MIDDLEWARE DE AUTENTICACIÓN
// ---------------------------------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        return res.status(401).json({ message: 'No se proporcionó token de autenticación.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(403).json({ message: 'El token ha expirado.' });
            }
            return res.status(403).json({ message: 'Token no válido.' });
        }
        req.user = user; // user ahora tiene { id: ..., rol: ... }
        next();
    });
};


// ---------------------------------
// SWAGGER DOCUMENTATION
// ---------------------------------
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// -----------------------------------------------------------------------------
// --- ENDPOINTS DE AUTENTICACIÓN ---
// -----------------------------------------------------------------------------



/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: Registra un nuevo usuario (como cliente)
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: Usuario registrado con éxito
 */
app.post('/api/register', async (req, res) => {
    // IMPORTANTE: El 'rol' se quita del req.body y se fuerza a 'cliente'
    const { nombre, email, password } = req.body;
    const rol = "cliente"; // Corrección de seguridad
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const query = 'INSERT INTO Usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)';
        const [result] = await db.query(query, [nombre, email, hashedPassword, rol]);
        res.status(201).json({ message: 'Usuario registrado con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al registrar el usuario', error: error.message });
    }
});

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Inicia sesión y obtiene un token JWT
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login exitoso, devuelve un token
 *       401:
 *         description: Credenciales inválidas
 */
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await db.query('SELECT * FROM Usuarios WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
        // Incluimos el ID y el ROL en el token
        const token = jwt.sign({ id: user.id, rol: user.rol }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login exitoso', token });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor', error: error.message });
    }
});

// TEMPORAL: Endpoint para registrar un usuario administrador (ELIMINAR DESPUÉS DE USAR)
/**
 * @swagger
 * /api/admin/register:
 *   post:
 *     summary: Registra un nuevo usuario como administrador (Solo Admin puede usarlo)
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: Usuario administrador registrado con éxito
 *       500:
 *         description: Error al registrar el usuario administrador
 */
app.post('/api/admin/register', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { nombre, email, password } = req.body;
    const rol = "admin";
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const query = 'INSERT INTO Usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)';
        const [result] = await db.query(query, [nombre, email, hashedPassword, rol]);
        res.status(201).json({ message: 'Usuario administrador registrado con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al registrar el usuario administrador', error: error.message });
    }
});


// -----------------------------------------------------------------------------
// --- ENDPOINTS DE SUCURSALES ---
// -----------------------------------------------------------------------------



/**
 * @swagger
 * /api/sucursales:
 *   get:
 *     summary: Obtiene todas las sucursales
 *     tags: [Sucursales]
 *     responses:
 *       200:
 *         description: Lista de sucursales
 */
app.get('/api/sucursales', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM Sucursales');
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener las sucursales', error: error.message });
    }
});

/**
 * @swagger
 * /api/sucursales:
 *   post:
 *     summary: Crea una nueva sucursal (Solo Admin)
 *     tags: [Sucursales]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               direccion:
 *                 type: string
 *     responses:
 *       201:
 *         description: Sucursal creada
 *       401:
 *         description: No autorizado
 */
// Ruta protegida
app.post('/api/sucursales', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { nombre, direccion } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Sucursales (nombre, direccion) VALUES (?, ?)', [nombre, direccion]);
        res.status(201).json({ message: 'Sucursal creada con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear la sucursal', error: error.message });
    }
});

/**
 * @swagger
 * /api/sucursales/{id}:
 *   get:
 *     summary: Obtiene una sucursal por ID
 *     tags: [Sucursales]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Detalles de la sucursal
 *       404:
 *         description: Sucursal no encontrada
 */
app.get('/api/sucursales/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Sucursales WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Sucursal no encontrada' });
        }
        res.json(results[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener la sucursal', error: error.message });
    }
});

/**
 * @swagger
 * /api/sucursales/{id}:
 *   put:
 *     summary: Actualiza una sucursal (Solo Admin)
 *     tags: [Sucursales]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               direccion:
 *                 type: string
 *     responses:
 *       200:
 *         description: Sucursal actualizada
 */
app.put('/api/sucursales/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    const { nombre, direccion } = req.body;
    try {
        await db.query('UPDATE Sucursales SET nombre = ?, direccion = ? WHERE id = ?', [nombre, direccion, id]);
        res.json({ message: 'Sucursal actualizada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar la sucursal', error: error.message });
    }
});

/**
 * @swagger
 * /api/sucursales/{id}:
 *   delete:
 *     summary: Elimina una sucursal (Solo Admin)
 *     tags: [Sucursales]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Sucursal eliminada
 */
app.delete('/api/sucursales/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Sucursales WHERE id = ?', [id]);
        res.json({ message: 'Sucursal eliminada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar la sucursal', error: error.message });
    }
});


// -----------------------------------------------------------------------------
// --- ENDPOINTS DE SERVICIOS (CATÁLOGO GENERAL) ---
// -----------------------------------------------------------------------------



/**
 * @swagger
 * /api/servicios:
 *   get:
 *     summary: Obtiene todos los servicios del catálogo
 *     tags: [Servicios]
 *     responses:
 *       200:
 *         description: Lista de servicios
 */
app.get('/api/servicios', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM Servicios');
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener los servicios', error: error.message });
    }
});

/**
 * @swagger
 * /api/servicios:
 *   post:
 *     summary: Crea un nuevo servicio en el catálogo (Solo Admin)
 *     tags: [Servicios]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               descripcion:
 *                 type: string
 *               precio_base:
 *                 type: number
 *               categoria_id:
 *                 type: integer
 *     responses:
 *       201:
 *         description: Servicio creado
 */
app.post('/api/servicios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { nombre, descripcion, precio_base, categoria_id } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Servicios (nombre, descripcion, precio_base, categoria_id) VALUES (?, ?, ?, ?)', [nombre, descripcion, precio_base, categoria_id]);
        res.status(201).json({ message: 'Servicio creado con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear el servicio', error: error.message });
    }
});

/**
 * @swagger
 * /api/servicios/{id}:
 *   get:
 *     summary: Obtiene un servicio por ID
 *     tags: [Servicios]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Detalles del servicio
 *       404:
 *         description: Servicio no encontrado
 */
app.get('/api/servicios/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Servicios WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Servicio no encontrado' });
        }
        res.json(results[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener el servicio', error: error.message });
    }
});

/**
 * @swagger
 * /api/servicios/{id}:
 *   put:
 *     summary: Actualiza un servicio del catálogo (Solo Admin)
 *     tags: [Servicios]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               descripcion:
 *                 type: string
 *               precio_base:
 *                 type: number
 *               categoria_id:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Servicio actualizado
 */
app.put('/api/servicios/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    const { nombre, descripcion, precio_base, categoria_id } = req.body;
    try {
        await db.query('UPDATE Servicios SET nombre = ?, descripcion = ?, precio_base = ?, categoria_id = ? WHERE id = ?', [nombre, descripcion, precio_base, categoria_id, id]);
        res.json({ message: 'Servicio actualizado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar el servicio', error: error.message });
    }
});

/**
 * @swagger
 * /api/servicios/{id}:
 *   delete:
 *     summary: Elimina un servicio del catálogo (Solo Admin)
 *     tags: [Servicios]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Servicio eliminado
 */
app.delete('/api/servicios/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Servicios WHERE id = ?', [id]);
        res.json({ message: 'Servicio eliminado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar el servicio', error: error.message });
    }
});


// -----------------------------------------------------------------------------
// --- ENDPOINTS DE CATEGORIAS ---
// -----------------------------------------------------------------------------


/**
 * @swagger
 * /api/categorias:
 *   get:
 *     summary: Obtiene todas las categorías
 *     tags: [Categorias]
 *     responses:
 *       200:
 *         description: Lista de categorías
 */
app.get('/api/categorias', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM Categorias');
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener las categorías', error: error.message });
    }
});

/**
 * @swagger
 * /api/categorias:
 *   post:
 *     summary: Crea una nueva categoría (Solo Admin)
 *     tags: [Categorias]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *     responses:
 *       201:
 *         description: Categoría creada
 */
app.post('/api/categorias', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { nombre } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Categorias (nombre) VALUES (?)', [nombre]);
        res.status(201).json({ message: 'Categoría creada con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear la categoría', error: error.message });
    }
});

/**
 * @swagger
 * /api/categorias/{id}:
 *   get:
 *     summary: Obtiene una categoría por ID
 *     tags: [Categorias]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Detalles de la categoría
 *       404:
 *         description: Categoría no encontrada
 */
app.get('/api/categorias/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Categorias WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Categoría no encontrada' });
        }
        res.json(results[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener la categoría', error: error.message });
    }
});

/**
 * @swagger
 * /api/categorias/{id}:
 *   put:
 *     summary: Actualiza una categoría (Solo Admin)
 *     tags: [Categorias]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *     responses:
 *       200:
 *         description: Categoría actualizada
 */
app.put('/api/categorias/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    const { nombre } = req.body;
    try {
        await db.query('UPDATE Categorias SET nombre = ? WHERE id = ?', [nombre, id]);
        res.json({ message: 'Categoría actualizada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar la categoría', error: error.message });
    }
});

/**
 * @swagger
 * /api/categorias/{id}:
 *   delete:
 *     summary: Elimina una categoría (Solo Admin)
 *     tags: [Categorias]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Categoría eliminada
 */
app.delete('/api/categorias/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Categorias WHERE id = ?', [id]);
        res.json({ message: 'Categoría eliminada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar la categoría', error: error.message });
    }
});

// -----------------------------------------------------------------------------
// --- ENDPOINTS DE USUARIOS ---
// -----------------------------------------------------------------------------



/**
 * @swagger
 * /api/usuarios:
 *   get:
 *     summary: Obtiene todos los usuarios (Solo Admin)
 *     tags: [Usuarios]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de usuarios (sin contraseñas)
 */
app.get('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    try {
        const [results] = await db.query('SELECT id, nombre, email, rol FROM Usuarios');
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener los usuarios', error: error.message });
    }
});

/**
 * @swagger
 * /api/usuarios/{id}:
 *   get:
 *     summary: Obtiene un usuario por ID (Solo Admin)
 *     tags: [Usuarios]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Detalles del usuario
 *       404:
 *         description: Usuario no encontrado
 */
app.get('/api/usuarios/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT id, nombre, email, rol FROM Usuarios WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        res.json(results[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener el usuario', error: error.message });
    }
});

/**
 * @swagger
 * /api/usuarios/{id}:
 *   put:
 *     summary: Actualiza un usuario (Solo Admin)
 *     tags: [Usuarios]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               email:
 *                 type: string
 *               rol:
 *                 type: string
 *     responses:
 *       200:
 *         description: Usuario actualizado
 */
app.put('/api/usuarios/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    const { nombre, email, rol } = req.body;
    try {
        await db.query('UPDATE Usuarios SET nombre = ?, email = ?, rol = ? WHERE id = ?', [nombre, email, rol, id]);
        res.json({ message: 'Usuario actualizado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar el usuario', error: error.message });
    }
});

/**
 * @swagger
 * /api/usuarios/{id}:
 *   delete:
 *     summary: Elimina un usuario (Solo Admin)
 *     tags: [Usuarios]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Usuario eliminado
 */
app.delete('/api/usuarios/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Usuarios WHERE id = ?', [id]);
        res.json({ message: 'Usuario eliminado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar el usuario', error: error.message });
    }
});


// -----------------------------------------------------------------------------
// --- ENDPOINTS DE CITAS ---
// -----------------------------------------------------------------------------



/**
 * @swagger
 * /api/citas:
 *   get:
 *     summary: Obtiene todas las citas (Solo Admin/Empleados)
 *     tags: [Citas]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de citas
 */
app.get('/api/citas', authenticateToken, async (req, res) => {
    try {
        if (req.user.rol === 'cliente') {
            const [results] = await db.query('SELECT * FROM Citas WHERE cliente_id = ?', [req.user.id]);
            res.json(results);
        } else {
            const [results] = await db.query('SELECT * FROM Citas');
            res.json(results);
        }
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener las citas', error: error.message });
    }
});

/**
 * @swagger
 * /api/citas:
 *   post:
 *     summary: Agenda una nueva cita (Cliente logueado)
 *     tags: [Citas]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sucursal_id:
 *                 type: integer
 *                 description: ID de la sucursal.
 *               servicio_id:
 *                 type: integer
 *                 description: ID del servicio deseado.
 *               fecha_hora:
 *                 type: string
 *                 format: date-time
 *                 description: "Formato ISO 8601: YYYY-MM-DDTHH:MM:SS"
 *               empleado_id:
 *                 type: integer
 *                 description: "(Opcional) ID del empleado si se prefiere uno específico."
 *               especificaciones_cliente:
 *                 type: string
 *                 description: "(Opcional) Notas adicionales del cliente."
 *             required:
 *               - sucursal_id
 *               - servicio_id
 *               - fecha_hora
 *     responses:
 *       201:
 *         description: Cita agendada con éxito
 *       400:
 *         description: Error en los datos de entrada
 *       401:
 *         description: No autorizado (falta token)
 *       403:
 *         description: Token no válido
 *       409:
 *         description: Conflicto de horario. No hay disponibilidad.
 *       500:
 *         description: Error al agendar la cita
 */
app.post('/api/citas', authenticateToken, async (req, res) => {
    const cliente_id = req.user.id; // ¡Más seguro! ID viene del token
    const { sucursal_id, servicio_id, fecha_hora, empleado_id, especificaciones_cliente } = req.body;
    const estado = 'pendiente';

    // Validación básica de entrada
    if (!sucursal_id || !servicio_id || !fecha_hora) {
        return res.status(400).json({ message: 'sucursal_id, servicio_id y fecha_hora son requeridos' });
    }

    try {
        let empleadoAsignadoId = null;

        // --- Lógica de validación de 20 minutos ---
        const checkAvailability = async (id_empleado) => {
            const query = `
                SELECT id FROM citas 
                WHERE empleado_id = ? 
                AND estado != 'cancelada'
                AND ABS(TIMESTAMPDIFF(MINUTE, fecha_hora, ?)) < 20
            `;
            const [citasConflictivas] = await db.query(query, [id_empleado, fecha_hora]);
            return citasConflictivas.length === 0; // Retorna true si está disponible, false si no
        };

        if (empleado_id && empleado_id > 0) {
            // --- CASO 1: El cliente pidió un empleado específico ---
            
            // 1. Verificar si este empleado puede hacer este servicio
            const [puedeHacerlo] = await db.query(
                'SELECT * FROM empleado_servicios WHERE empleado_id = ? AND servicio_id = ?', 
                [empleado_id, servicio_id]
            );

            if (puedeHacerlo.length === 0) {
                 return res.status(409).json({ message: 'El empleado seleccionado no realiza ese servicio.' });
            }

            // 2. Verificar si ese empleado está disponible en el intervalo de 20 mins
            const isAvailable = await checkAvailability(empleado_id);
            if (!isAvailable) {
                return res.status(409).json({ message: 'Error al agendar cita, esta hora ya esta ocupada' });
            }

            // Si pasó ambas pruebas, se le asigna
            empleadoAsignadoId = empleado_id;

        } else {
            // --- CASO 2: El cliente quiere "cualquier" empleado ---

            // 1. Obtener lista de empleados CAPACES de hacer el servicio en esa sucursal
            const [empleadosCapaces] = await db.query(
                `SELECT e.id FROM empleados e
                 JOIN empleado_servicios es ON e.id = es.empleado_id
                 WHERE e.sucursal_id = ? AND es.servicio_id = ?`,
                [sucursal_id, servicio_id]
            );
            
            if (empleadosCapaces.length === 0) {
                return res.status(409).json({ message: 'No hay empleados en esta sucursal que realicen dicho servicio.' });
            }
            const idsCapaces = empleadosCapaces.map(e => e.id);

            // 2. Encontrar el primer empleado capaz que esté disponible en el intervalo
            for (const idCapaz of idsCapaces) {
                const isAvailable = await checkAvailability(idCapaz);
                if (isAvailable) {
                    empleadoAsignadoId = idCapaz;
                    break; // Encontramos uno, salimos del bucle
                }
            }

            if (!empleadoAsignadoId) {
                return res.status(409).json({ message: 'Error al agendar cita, esta hora ya esta ocupada' });
            }
        }

        // --- Inserción Final ---
        // Si llegamos aquí, 'empleadoAsignadoId' tiene un ID válido y disponible
        
        const query = `INSERT INTO Citas 
            (cliente_id, empleado_id, sucursal_id, servicio_id, fecha_hora, estado, especificaciones_cliente) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`;
        
        const [result] = await db.query(query, [
            cliente_id, 
            empleadoAsignadoId, 
            sucursal_id, 
            servicio_id, 
            fecha_hora, 
            estado, 
            especificaciones_cliente
        ]);

        res.status(201).json({ message: 'Cita agendada con éxito', id: result.insertId, empleado_asignado: empleadoAsignadoId });

    } catch (error) {
        console.error(error); // Muestra el error en tu consola
        res.status(500).json({ message: 'Error al agendar la cita', error: error.message });
    }
});


/**
 * @swagger
 * /api/citas/{id}:
 *   get:
 *     summary: Obtiene una cita por ID (Protegido)
 *     tags: [Citas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Detalles de la cita
 *       404:
 *         description: Cita no encontrada
 */
app.get('/api/citas/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Citas WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Cita no encontrada' });
        }
        const cita = results[0];
        if (req.user.rol === 'cliente' && req.user.id !== cita.cliente_id) {
            return res.status(403).json({ message: 'Acceso denegado. No eres el propietario de esta cita.' });
        }
        res.json(cita);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener la cita', error: error.message });
    }
});

/**
 * @swagger
 * /api/citas/{id}:
 *   put:
 *     summary: Actualiza el estado de una cita (Admin/Empleado)
 *     tags: [Citas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               estado:
 *                 type: string
 *                 enum: [pendiente, confirmada, completada, cancelada]
 *     responses:
 *       200:
 *         description: Cita actualizada
 */
app.put('/api/citas/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'empleado') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador o empleado.' });
    }
    const { id } = req.params;
    const { estado } = req.body;
    try {
        await db.query('UPDATE Citas SET estado = ? WHERE id = ?', [estado, id]);
        res.json({ message: 'Estado de la cita actualizado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar la cita', error: error.message });
    }
});

/**
 * @swagger
 * /api/citas/{id}:
 *   delete:
 *     summary: Cancela una cita (actualiza estado a 'cancelada') (Protegido)
 *     tags: [Citas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Cita cancelada
 */
app.delete('/api/citas/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Citas WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Cita no encontrada' });
        }
        const cita = results[0];
        if (req.user.rol === 'cliente' && req.user.id !== cita.cliente_id) {
            return res.status(403).json({ message: 'Acceso denegado. No eres el propietario de esta cita.' });
        }
        await db.query('UPDATE Citas SET estado = "cancelada" WHERE id = ?', [id]);
        res.json({ message: 'Cita cancelada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al cancelar la cita', error: error.message });
    }
});

// -----------------------------------------------------------------------------
// --- ENDPOINTS DE RESEÑAS ---
// -----------------------------------------------------------------------------

/**
 * @swagger
 * /api/reseñas:
 *   get:
 *     summary: Obtiene todas las reseñas
 *     tags: [Reseñas]
 *     responses:
 *       200:
 *         description: Lista de reseñas
 */
app.get('/api/reseñas', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM Reseñas');
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener las reseñas', error: error.message });
    }
});

/**
 * @swagger
 * /api/reseñas:
 *   post:
 *     summary: Crea una nueva reseña (Cliente logueado)
 *     tags: [Reseñas]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               cita_id:
 *                 type: integer
 *               empleado_id:
 *                 type: integer
 *               sucursal_id:
 *                 type: integer
 *               calificacion_empleado:
 *                 type: integer
 *               calificacion_sucursal:
 *                 type: integer
 *               comentario:
 *                 type: string
 *     responses:
 *       201:
 *         description: Reseña creada
 */
app.post('/api/reseñas', authenticateToken, async (req, res) => {
    const cliente_id = req.user.id; // ID del token
    const { cita_id, empleado_id, sucursal_id, calificacion_empleado, calificacion_sucursal, comentario } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Reseñas (cita_id, cliente_id, empleado_id, sucursal_id, calificacion_empleado, calificacion_sucursal, comentario) VALUES (?, ?, ?, ?, ?, ?, ?)', [cita_id, cliente_id, empleado_id, sucursal_id, calificacion_empleado, calificacion_sucursal, comentario]);
        res.status(201).json({ message: 'Reseña creada con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear la reseña', error: error.message });
    }
});

/**
 * @swagger
 * /api/reseñas/{id}:
 *   get:
 *     summary: Obtiene una reseña por ID
 *     tags: [Reseñas]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Detalles de la reseña
 *       404:
 *         description: Reseña no encontrada
 */
app.get('/api/reseñas/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Reseñas WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Reseña no encontrada' });
        }
        res.json(results[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener la reseña', error: error.message });
    }
});

/**
 * @swagger
 * /api/reseñas/{id}:
 *   put:
 *     summary: Actualiza una reseña (Solo dueño o Admin)
 *     tags: [Reseñas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               calificacion_empleado:
 *                 type: integer
 *               calificacion_sucursal:
 *                 type: integer
 *               comentario:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reseña actualizada
 */
app.put('/api/reseñas/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { calificacion_empleado, calificacion_sucursal, comentario } = req.body;
    try {
        const [results] = await db.query('SELECT * FROM Reseñas WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Reseña no encontrada' });
        }
        const reseña = results[0];
        if (req.user.rol === 'cliente' && req.user.id !== reseña.cliente_id) {
            return res.status(403).json({ message: 'Acceso denegado. No eres el propietario de esta reseña.' });
        }
        await db.query('UPDATE Reseñas SET calificacion_empleado = ?, calificacion_sucursal = ?, comentario = ? WHERE id = ?', [calificacion_empleado, calificacion_sucursal, comentario, id]);
        res.json({ message: 'Reseña actualizada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar la reseña', error: error.message });
    }
});

/**
 * @swagger
 * /api/reseñas/{id}:
 *   delete:
 *     summary: Elimina una reseña (Solo dueño o Admin)
 *     tags: [Reseñas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Reseña eliminada
 */
app.delete('/api/reseñas/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Reseñas WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Reseña no encontrada' });
        }
        const reseña = results[0];
        if (req.user.rol === 'cliente' && req.user.id !== reseña.cliente_id) {
            return res.status(403).json({ message: 'Acceso denegado. No eres el propietario de esta reseña.' });
        }
        await db.query('DELETE FROM Reseñas WHERE id = ?', [id]);
        res.json({ message: 'Reseña eliminada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar la reseña', error: error.message });
    }
});

// -----------------------------------------------------------------------------
// --- ENDPOINTS DE GALERÍA DE SUCURSALES ---
// -----------------------------------------------------------------------------

/**
 * @swagger
 * /api/sucursales/{sucursal_id}/fotos:
 *   get:
 *     summary: Obtiene todas las fotos de una sucursal
 *     tags: [Galería de Sucursales]
 *     parameters:
 *       - in: path
 *         name: sucursal_id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Lista de fotos de la galería
 */
app.get('/api/sucursales/:sucursal_id/fotos', async (req, res) => {
    const { sucursal_id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Galeria_Sucursales WHERE sucursal_id = ?', [sucursal_id]);
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener la galería de la sucursal', error: error.message });
    }
});

/**
 * @swagger
 * /api/sucursales/{sucursal_id}/fotos:
 *   post:
 *     summary: Agrega una nueva foto a la galería de una sucursal (Admin)
 *     tags: [Galería de Sucursales]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sucursal_id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               url_imagen:
 *                 type: string
 *               descripcion:
 *                 type: string
 *     responses:
 *       201:
 *         description: Foto agregada a la galería
 */
app.post('/api/sucursales/:sucursal_id/fotos', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { sucursal_id } = req.params;
    const { url_imagen, descripcion } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Galeria_Sucursales (sucursal_id, url_imagen, descripcion) VALUES (?, ?, ?)', [sucursal_id, url_imagen, descripcion]);
        res.status(201).json({ message: 'Foto agregada a la galería con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al agregar la foto a la galería', error: error.message });
    }
});

/**
 * @swagger
 * /api/sucursales/{sucursal_id}/fotos/{foto_id}:
 *   delete:
 *     summary: Elimina una foto de la galería de una sucursal (Admin)
 *     tags: [Galería de Sucursales]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sucursal_id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: foto_id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Foto eliminada de la galería
 */
app.delete('/api/sucursales/:sucursal_id/fotos/:foto_id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { foto_id } = req.params;
    try {
        await db.query('DELETE FROM Galeria_Sucursales WHERE id = ?', [foto_id]);
        res.json({ message: 'Foto eliminada de la galería con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar la foto de la galería', error: error.message });
    }
});

// -----------------------------------------------------------------------------
// --- ENDPOINTS DE SERVICIOS POR SUCURSAL ---
// -----------------------------------------------------------------------------

/**
 * @swagger
 * /api/sucursales/{sucursal_id}/servicios:
 *   get:
 *     summary: Obtiene todos los servicios de una sucursal
 *     tags: [Servicios por Sucursal]
 *     parameters:
 *       - in: path
 *         name: sucursal_id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Lista de servicios de la sucursal
 */
app.get('/api/sucursales/:sucursal_id/servicios', async (req, res) => {
    const { sucursal_id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Sucursal_Servicios WHERE sucursal_id = ?', [sucursal_id]);
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener los servicios de la sucursal', error: error.message });
    }
});

/**
 * @swagger
 * /api/sucursales/{sucursal_id}/servicios/{servicio_id}:
 *   post:
 *     summary: Asigna un servicio a una sucursal con un precio específico (Admin)
 *     tags: [Servicios por Sucursal]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sucursal_id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: servicio_id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               precio_especifico:
 *                 type: number
 *               url_imagen:
 *                 type: string
 *               disponible:
 *                 type: boolean
 *     responses:
 *       201:
 *         description: Servicio asignado a la sucursal
 */
app.post('/api/sucursales/:sucursal_id/servicios/:servicio_id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { sucursal_id, servicio_id } = req.params;
    const { precio_especifico, url_imagen, disponible } = req.body;
    try {
        await db.query('INSERT INTO Sucursal_Servicios (sucursal_id, servicio_id, precio_especifico, url_imagen, disponible) VALUES (?, ?, ?, ?, ?)', [sucursal_id, servicio_id, precio_especifico, url_imagen, disponible]);
        res.status(201).json({ message: 'Servicio asignado a la sucursal con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al asignar el servicio a la sucursal', error: error.message });
    }
});

/**
 * @swagger
 * /api/sucursales/{sucursal_id}/servicios/{servicio_id}:
 *   put:
 *     summary: Actualiza un servicio de una sucursal (Admin)
 *     tags: [Servicios por Sucursal]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sucursal_id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: servicio_id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               precio_especifico:
 *                 type: number
 *               url_imagen:
 *                 type: string
 *               disponible:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Servicio de la sucursal actualizado
 */
app.put('/api/sucursales/:sucursal_id/servicios/:servicio_id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { sucursal_id, servicio_id } = req.params;
    const { precio_especifico, url_imagen, disponible } = req.body;
    try {
        await db.query('UPDATE Sucursal_Servicios SET precio_especifico = ?, url_imagen = ?, disponible = ? WHERE sucursal_id = ? AND servicio_id = ?', [precio_especifico, url_imagen, disponible, sucursal_id, servicio_id]);
        res.json({ message: 'Servicio de la sucursal actualizado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar el servicio de la sucursal', error: error.message });
    }
});

/**
 * @swagger
 * /api/sucursales/{sucursal_id}/servicios/{servicio_id}:
 *   delete:
 *     summary: Elimina un servicio de una sucursal (Admin)
 *     tags: [Servicios por Sucursal]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sucursal_id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: servicio_id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Servicio eliminado de la sucursal
 */
app.delete('/api/sucursales/:sucursal_id/servicios/:servicio_id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { sucursal_id, servicio_id } = req.params;
    try {
        await db.query('DELETE FROM Sucursal_Servicios WHERE sucursal_id = ? AND servicio_id = ?', [sucursal_id, servicio_id]);
        res.json({ message: 'Servicio eliminado de la sucursal con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar el servicio de la sucursal', error: error.message });
    }
});

// -----------------------------------------------------------------------------
// --- ENDPOINTS DE PROMOCIONES ---
// -----------------------------------------------------------------------------

/**
 * @swagger
 * /api/promociones:
 *   get:
 *     summary: Obtiene todas las promociones
 *     tags: [Promociones]
 *     responses:
 *       200:
 *         description: Lista de promociones
 */
app.get('/api/promociones', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM Promociones');
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener las promociones', error: error.message });
    }
});

/**
 * @swagger
 * /api/promociones:
 *   post:
 *     summary: Crea una nueva promoción (Admin)
 *     tags: [Promociones]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sucursal_id:
 *                 type: integer
 *               nombre:
 *                 type: string
 *               descripcion:
 *                 type: string
 *               tipo_descuento:
 *                 type: string
 *               valor:
 *                 type: number
 *               fecha_inicio:
 *                 type: string
 *                 format: date
 *               fecha_fin:
 *                 type: string
 *                 format: date
 *     responses:
 *       201:
 *         description: Promoción creada
 */
app.post('/api/promociones', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { sucursal_id, nombre, descripcion, tipo_descuento, valor, fecha_inicio, fecha_fin } = req.body;
    try {
        const [result] = await db.query('INSERT INTO Promociones (sucursal_id, nombre, descripcion, tipo_descuento, valor, fecha_inicio, fecha_fin) VALUES (?, ?, ?, ?, ?, ?, ?)', [sucursal_id, nombre, descripcion, tipo_descuento, valor, fecha_inicio, fecha_fin]);
        res.status(201).json({ message: 'Promoción creada con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear la promoción', error: error.message });
    }
});

/**
 * @swagger
 * /api/promociones/{id}:
 *   get:
 *     summary: Obtiene una promoción por ID
 *     tags: [Promociones]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Detalles de la promoción
 *       404:
 *         description: Promoción no encontrada
 */
app.get('/api/promociones/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Promociones WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Promoción no encontrada' });
        }
        res.json(results[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener la promoción', error: error.message });
    }
});

/**
 * @swagger
 * /api/promociones/{id}:
 *   put:
 *     summary: Actualiza una promoción (Admin)
 *     tags: [Promociones]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sucursal_id:
 *                 type: integer
 *               nombre:
 *                 type: string
 *               descripcion:
 *                 type: string
 *               tipo_descuento:
 *                 type: string
 *               valor:
 *                 type: number
 *               fecha_inicio:
 *                 type: string
 *                 format: date
 *               fecha_fin:
 *                 type: string
 *                 format: date
 *     responses:
 *       200:
 *         description: Promoción actualizada
 */
app.put('/api/promociones/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    const { sucursal_id, nombre, descripcion, tipo_descuento, valor, fecha_inicio, fecha_fin } = req.body;
    try {
        await db.query('UPDATE Promociones SET sucursal_id = ?, nombre = ?, descripcion = ?, tipo_descuento = ?, valor = ?, fecha_inicio = ?, fecha_fin = ? WHERE id = ?', [sucursal_id, nombre, descripcion, tipo_descuento, valor, fecha_inicio, fecha_fin, id]);
        res.json({ message: 'Promoción actualizada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar la promoción', error: error.message });
    }
});

/**
 * @swagger
 * /api/promociones/{id}:
 *   delete:
 *     summary: Elimina una promoción (Admin)
 *     tags: [Promociones]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Promoción eliminada
 */
app.delete('/api/promociones/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    try {
        await db.query('DELETE FROM Promociones WHERE id = ?', [id]);
        res.json({ message: 'Promoción eliminada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar la promoción', error: error.message });
    }
});

// -----------------------------------------------------------------------------
// --- ENDPOINTS DE LEALTAD DE CLIENTES ---
// -----------------------------------------------------------------------------

/**
 * @swagger
 * /api/lealtad:
 *   get:
 *     summary: Obtiene todos los registros de lealtad de clientes (Admin)
 *     tags: [Lealtad de Clientes]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de registros de lealtad
 */
app.get('/api/lealtad', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    try {
        const [results] = await db.query('SELECT * FROM Lealtad_Clientes');
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener los registros de lealtad', error: error.message });
    }
});

/**
 * @swagger
 * /api/lealtad/cliente/{cliente_id}/sucursal/{sucursal_id}:
 *   get:
 *     summary: Obtiene el registro de lealtad de un cliente en una sucursal (Protegido)
 *     tags: [Lealtad de Clientes]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: cliente_id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: sucursal_id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Registro de lealtad del cliente
 *       404:
 *         description: Registro no encontrado
 */
app.get('/api/lealtad/cliente/:cliente_id/sucursal/:sucursal_id', authenticateToken, async (req, res) => {
    const { cliente_id, sucursal_id } = req.params;
    if (req.user.rol === 'cliente' && req.user.id !== parseInt(cliente_id)) {
        return res.status(403).json({ message: 'Acceso denegado. No puedes ver registros de lealtad de otros clientes.' });
    }
    try {
        const [results] = await db.query('SELECT * FROM Lealtad_Clientes WHERE cliente_id = ? AND sucursal_id = ?', [cliente_id, sucursal_id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Registro de lealtad no encontrado' });
        }
        res.json(results[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener el registro de lealtad', error: error.message });
    }
});

/**
 * @swagger
 * /api/lealtad/cliente/{cliente_id}/sucursal/{sucursal_id}:
 *   put:
 *     summary: Actualiza las visitas de un cliente en una sucursal (Admin/Empleado)
 *     tags: [Lealtad de Clientes]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: cliente_id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: sucursal_id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:  
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               visitas_actuales:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Visitas actualizadas
 *       201:
 *         description: Nuevo registro de lealtad creado
 */app.put('/api/lealtad/cliente/:cliente_id/sucursal/:sucursal_id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin' && req.user.rol !== 'empleado') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador o empleado.' });
    }
    const { cliente_id, sucursal_id } = req.params;
    const { visitas_actuales } = req.body;
    try {
        const [results] = await db.query('SELECT * FROM Lealtad_Clientes WHERE cliente_id = ? AND sucursal_id = ?', [cliente_id, sucursal_id]);
        if (results.length === 0) {
            await db.query('INSERT INTO Lealtad_Clientes (cliente_id, sucursal_id, visitas_actuales) VALUES (?, ?, ?)', [cliente_id, sucursal_id, visitas_actuales]);
            res.status(201).json({ message: 'Nuevo registro de lealtad creado con éxito' });
        } else {
            await db.query('UPDATE Lealtad_Clientes SET visitas_actuales = ? WHERE cliente_id = ? AND sucursal_id = ?', [visitas_actuales, cliente_id, sucursal_id]);
            res.json({ message: 'Visitas actualizadas con éxito' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar las visitas', error: error.message });
    }
});

// -----------------------------------------------------------------------------
// --- ENDPOINTS DE EMPLEADOS ---
// -----------------------------------------------------------------------------

/**
 * @swagger
 * /api/empleados:
 *   post:
 *     summary: Crea un nuevo empleado (Solo Admin)
 *     tags: [Empleados]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               sucursal_id:
 *                 type: integer
 *               especialidad:
 *                 type: string
 *     responses:
 *       201:
 *         description: Empleado creado
 */
app.post('/api/empleados', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { nombre, email, password, sucursal_id, especialidad } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const query = 'INSERT INTO Usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)';
        const [result] = await db.query(query, [nombre, email, hashedPassword, 'empleado']);
        const usuario_id = result.insertId;

        const query2 = 'INSERT INTO Empleados (usuario_id, sucursal_id, especialidad) VALUES (?, ?, ?)';
        await db.query(query2, [usuario_id, sucursal_id, especialidad]);

        res.status(201).json({ message: 'Empleado creado con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear el empleado', error: error.message });
    }
});

/**
 * @swagger
 * /api/empleados:
 *   get:
 *     summary: Obtiene todos los empleados (Cualquier usuario logueado)
 *     tags: [Empleados]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de empleados
 */
app.get('/api/empleados', authenticateToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM Empleados');
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener los empleados', error: error.message });
    }
});

/**
 * @swagger
 * /api/empleados/{id}:
 *   get:
 *     summary: Obtiene un empleado por ID (Solo Admin)
 *     tags: [Empleados]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Detalles del empleado
 *       404:
 *         description: Empleado no encontrado
 */
app.get('/api/empleados/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM Empleados WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Empleado no encontrado' });
        }
        res.json(results[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener el empleado', error: error.message });
    }
});

/**
 * @swagger
 * /api/empleados/{id}:
 *   put:
 *     summary: Actualiza un empleado (Solo Admin)
 *     tags: [Empleados]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sucursal_id:
 *                 type: integer
 *               especialidad:
 *                 type: string
 *     responses:
 *       200:
 *         description: Empleado actualizado
 */
app.put('/api/empleados/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    const { sucursal_id, especialidad } = req.body;
    try {
        await db.query('UPDATE Empleados SET sucursal_id = ?, especialidad = ? WHERE id = ?', [sucursal_id, especialidad, id]);
        res.json({ message: 'Empleado actualizado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar el empleado', error: error.message });
    }
});

/**
 * @swagger
 * /api/empleados/{id}:
 *   delete:
 *     summary: Elimina un empleado (Solo Admin)
 *     tags: [Empleados]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Empleado eliminado
 */
app.delete('/api/empleados/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT usuario_id FROM Empleados WHERE id = ?', [id]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'Empleado no encontrado' });
        }
        const usuario_id = results[0].usuario_id;
        await db.query('DELETE FROM Empleados WHERE id = ?', [id]);
        await db.query('DELETE FROM Usuarios WHERE id = ?', [usuario_id]);
        res.json({ message: 'Empleado eliminado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar el empleado', error: error.message });
    }
});

/**
 * @swagger
 * /api/empleados/{id}/servicios:
 *   post:
 *     summary: Asigna un servicio a un empleado (Solo Admin)
 *     tags: [Empleados]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               servicio_id:
 *                 type: integer
 *     responses:
 *       201:
 *         description: Servicio asignado al empleado
 */
app.post('/api/empleados/:id/servicios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id } = req.params;
    const { servicio_id } = req.body;
    try {
        await db.query('INSERT INTO empleado_servicios (empleado_id, servicio_id) VALUES (?, ?)', [id, servicio_id]);
        res.status(201).json({ message: 'Servicio asignado al empleado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al asignar el servicio al empleado', error: error.message });
    }
});

/**
 * @swagger
 * /api/empleados/{id}/servicios/{servicio_id}:
 *   delete:
 *     summary: Elimina un servicio de un empleado (Solo Admin)
 *     tags: [Empleados]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: servicio_id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Servicio eliminado del empleado
 */
app.delete('/api/empleados/:id/servicios/:servicio_id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    const { id, servicio_id } = req.params;
    try {
        await db.query('DELETE FROM empleado_servicios WHERE empleado_id = ? AND servicio_id = ?', [id, servicio_id]);
        res.json({ message: 'Servicio eliminado del empleado con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar el servicio del empleado', error: error.message });
    }
});



// ---------------------------------
// INICIAR SERVIDOR
// ---------------------------------
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
    console.log(`Documentación de Swagger disponible en http://localhost:${PORT}/api-docs`);
});