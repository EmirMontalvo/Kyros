// swagger.js

const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API Kyros',
      version: '1.0.0',
      description: 'Documentación de la API Kyros',
    },
    servers: [
      {
        url: 'http://localhost:3000',
        description: 'Servidor de desarrollo',
      },
    ],
    tags: [
        {
          name: 'Autenticación',
          description: 'Endpoints para registro y login de usuarios',
        },
        {
          name: 'Citas',
          description: 'Gestión de citas (Lógica principal)',
        },
        {
          name: 'Sucursales',
          description: 'API para la gestión de sucursales',
        },
        {
          name: 'Servicios',
          description: 'Gestión del catálogo general de servicios',
        },
        {
          name: 'Categorias',
          description: 'Gestión de categorías de servicios',
        },
        {
          name: 'Usuarios',
          description: 'Gestión de usuarios (para administradores)',
        },
        {
          name: 'Reseñas',
          description: 'Endpoints para la gestión de reseñas',
        },
        {
          name: 'Galería de Sucursales',
          description: 'Gestión de la galería de fotos de las sucursales',
        },
        {
          name: 'Servicios por Sucursal',
          description: 'Gestión de los servicios específicos de cada sucursal',
        },
        {
          name: 'Promociones',
          description: 'Gestión de promociones',
        },
        {
          name: 'Lealtad de Clientes',
          description: 'Gestión de la lealtad de los clientes',
        },
        {
          name: 'Empleados',
          description: 'Gestión de empleados',
        },
    ],
    
    // --- ESTA ES LA PARTE IMPORTANTE ---
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Pega tu token JWT aquí (obtenido de /api/login)'
        }
      }
    },
    // (Opcional) Si quieres que TODAS las rutas tengan el candado por defecto.
    // Lo hemos puesto manualmente en index.js, así que esto no es estrictamente necesario,
    // pero es una buena práctica.
    security: [ 
      {
        bearerAuth: []
      }
    ]
    // --- FIN DE LA PARTE IMPORTANTE ---

  },
  apis: ['./index.js'], // Esto apunta a tu index.js para leer los JSDoc
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = swaggerSpec;