// db.js
const mysql = require('mysql2/promise');

// Crea un "pool" de conexiones a la base de datos
const pool = mysql.createPool({
  host: 'localhost',         // La dirección de tu servidor de BD
  user: 'root',              // Tu usuario de la BD
  password: '',   // La contraseña de tu usuario
  database: 'peluqueria_db', // El nombre de tu base de datos
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Exporta el pool para que pueda ser usado en otros archivos
module.exports = pool;