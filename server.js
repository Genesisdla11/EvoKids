// Importar módulos necesarios
const express = require('express'); // Framework web para Node.js
const sqlite3 = require('sqlite3').verbose(); // Driver para SQLite3
const path = require('path'); // Módulo para trabajar con rutas de archivos
const session = require('express-session'); // Middleware para gestión de sesiones
const flash = require('connect-flash'); // Middleware para mensajes flash
// const bcrypt = require('bcrypt'); // Opcional: Descomentar si decides usar hashing de contraseñas para seguridad real

// Inicializar la aplicación Express
const app = express();
const PORT = process.env.PORT || 3000; // Puerto en el que se ejecutará el servidor (por defecto 3000)

// --- Configuración de la Base de Datos SQLite ---
// Abre la base de datos. Si no existe, la crea.
// 'terapia.db' se creará en el directorio raíz del proyecto (donde está server.js).
const db = new sqlite3.Database(path.join(__dirname, 'terapia.db'), (err) => {
    if (err) {
        // Si hay un error al abrir la base de datos, lo registramos.
        console.error('Error al abrir la base de datos:', err.message);
    } else {
        console.log('Conectado a la base de datos SQLite.');
        // Crea la tabla de usuarios si no existe.
        // 'id': clave primaria, autoincremental.
        // 'nombre_usuario': texto único y no nulo.
        // 'contrasena': texto no nulo (¡en una app real, debe ser hasheada!).
        // 'es_padre': entero (0 para falso, 1 para verdadero), por defecto 0.
        db.run(`CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_usuario TEXT UNIQUE NOT NULL,
            contrasena TEXT NOT NULL,
            es_padre INTEGER DEFAULT 0
        )`, (err) => {
            if (err) {
                console.error('Error al crear la tabla de usuarios:', err.message);
            } else {
                console.log('Tabla de usuarios verificada/creada.');
            }
        });
    }
});

// --- Configuración de Express ---
// Configura EJS como el motor de plantillas.
app.set('view engine', 'ejs');
// Especifica la carpeta donde se encuentran las vistas (plantillas EJS).
app.set('views', path.join(__dirname, 'views'));

// Middleware para servir archivos estáticos (CSS, JS del cliente, imágenes desde la carpeta 'public').
app.use(express.static(path.join(__dirname, 'public')));

// Middleware para parsear datos de formularios HTML (body-parser para url-encoded bodies).
// Esto es crucial para poder acceder a los datos que el usuario envía en un formulario POST (req.body).
app.use(express.urlencoded({ extended: true }));
// Middleware para parsear JSON (útil si vas a manejar JSON en el futuro, por ejemplo, APIs REST).
app.use(express.json());

// Configuración de sesiones.
// 'secret': Una cadena secreta usada para firmar la cookie de sesión.
//          ¡IMPORTANTE: Cambia 'mi_clave_secreta_super_segura_12345' a una cadena larga y aleatoria en producción!
// 'resave': No guarda la sesión si no ha sido modificada.
// 'saveUninitialized': Guarda las sesiones que son nuevas pero no han sido modificadas.
// 'cookie.maxAge': Duración de la cookie de sesión (1 hora en milisegundos).
app.use(session({
    secret: 'mi_clave_secreta_super_segura_12345', // ¡Cambia esto a una cadena larga y aleatoria!
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60 * 60 * 1000 } // 1 hora
}));

// Configuración de mensajes flash.
// Esto añade el método 'req.flash()' que podemos usar para establecer mensajes temporales.
app.use(flash());

// Middleware personalizado para pasar mensajes flash y el estado de autenticación a todas las vistas.
// 'res.locals' es un objeto que contiene variables que estarán disponibles en todas las plantillas EJS renderizadas.
app.use((req, res, next) => {
    res.locals.messages = req.flash(); // Pasa todos los mensajes flash a 'messages'
    // Determina si el usuario está autenticado basándose en si hay un 'userId' en la sesión.
    res.locals.isAuthenticated = req.session.userId ? true : false;
    next(); // Continúa con la siguiente función middleware o ruta
});

// --- Middleware de Autenticación (Protección de Rutas) ---
// Esta función se puede usar en cualquier ruta que requiera que el usuario esté logueado.
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next(); // El usuario está autenticado, continuar con la siguiente función de la ruta
    } else {
        // Si no está autenticado, establece un mensaje de error y redirige al login.
        req.flash('error', 'Necesitas iniciar sesión para acceder a esta página.');
        res.redirect('/login');
    }
}

// --- Rutas de la Aplicación ---

// Ruta para la página de inicio ('/')
app.get('/', (req, res) => {
    res.render('index'); // Renderiza la plantilla 'index.ejs'
});

// Ruta para mostrar el formulario de registro (GET /register)
app.get('/register', (req, res) => {
    // Si el usuario ya está logueado, lo redirigimos para que no se registre de nuevo.
    if (req.session.userId) {
        return res.redirect('/dashboard'); // Redirige al dashboard si ya está logueado
    }
    res.render('register'); // Renderiza la plantilla 'register.ejs'
});

// Ruta para procesar el envío del formulario de registro (POST /register)
app.post('/register', (req, res) => {
    // Obtiene los datos del formulario (username, password, is_parent checkbox).
    const { username, password, is_parent } = req.body;
    // Convierte el valor del checkbox 'on' a 1 (true) o 0 (false) para la DB.
    const es_padre = is_parent === 'on' ? 1 : 0;

    // Validaciones básicas de campos vacíos.
    if (!username || !password) {
        // req.flash('error', 'Por favor, completa todos los campos.'); // Comentado para depuración
        return res.redirect('/register');
    }

    // Verificar si el nombre de usuario ya existe en la base de datos.
    db.get('SELECT * FROM usuarios WHERE nombre_usuario = ?', [username], (err, row) => {
        if (err) {
            console.error('Error al consultar usuario:', err.message);
            // req.flash('error', 'Ocurrió un error en el servidor. Inténtalo de nuevo.'); // Comentado para depuración
            return res.redirect('/register');
        }
        if (row) {
            // req.flash('error', 'El nombre de usuario ya existe. Por favor, elige otro.'); // Comentado para depuración
            return res.redirect('/register');
        }

        // --- IMPORTANTE: En una aplicación real, aquí deberías hashear la contraseña ---
        // Usar bcrypt para hashear la contraseña antes de guardarla.
        // Ejemplo (después de instalar 'bcrypt' con 'npm install bcrypt'):
        // const hashedPassword = bcrypt.hashSync(password, 10); // '10' es el número de rondas de salting
        // const insertSql = 'INSERT INTO usuarios (nombre_usuario, contrasena, es_padre) VALUES (?, ?, ?)';
        // db.run(insertSql, [username, hashedPassword, es_padre], function(err) { ... });

        // Por ahora, guardamos la contraseña en texto plano (SOLO PARA DESARROLLO).
        const insertSql = 'INSERT INTO usuarios (nombre_usuario, contrasena, es_padre) VALUES (?, ?, ?)';
        db.run(insertSql, [username, password, es_padre], function(err) {
            if (err) {
                console.error('Error al insertar usuario:', err.message);
                // req.flash('error', 'Ocurrió un error al registrar el usuario. Inténtalo de nuevo.'); // Comentado para depuración
                return res.redirect('/register');
            }
            console.log(`Usuario ${username} registrado con ID: ${this.lastID}`);
            // req.flash('success', '¡Registro exitoso! Ya puedes iniciar sesión.'); // Comentado para depuración
            res.redirect('/login'); // Redirige al login después del registro exitoso
        });
    });
});

// --- Rutas para Inicio de Sesión ---

// Ruta para mostrar el formulario de inicio de sesión (GET /login)
app.get('/login', (req, res) => {
    // Si el usuario ya está logueado, lo redirigimos al dashboard.
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login'); // Renderiza la plantilla 'login.ejs'
});

// Ruta para procesar el envío del formulario de inicio de sesión (POST /login)
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Validaciones básicas de campos vacíos.
    if (!username || !password) {
        req.flash('error', 'Por favor, ingresa tu nombre de usuario y contraseña.');
        return res.redirect('/login');
    }

    // Buscar el usuario en la base de datos por nombre de usuario.
    db.get('SELECT * FROM usuarios WHERE nombre_usuario = ?', [username], (err, user) => {
        if (err) {
            console.error('Error al consultar usuario para login:', err.message);
            req.flash('error', 'Ocurrió un error en el servidor. Inténtalo de nuevo.');
            return res.redirect('/login');
        }

        // Si el usuario no existe O la contraseña no coincide.
        // --- IMPORTANTE: En una aplicación real, usarías bcrypt.compare(password, user.contrasena) aquí. ---
        if (!user || user.contrasena !== password) {
            req.flash('error', 'Nombre de usuario o contraseña incorrectos.');
            return res.redirect('/login');
        }

        // Inicio de sesión exitoso:
        // Guarda información del usuario en la sesión.
        req.session.userId = user.id;
        req.session.username = user.nombre_usuario;
        req.session.isParent = user.es_padre === 1; // Guarda el rol booleano

        req.flash('success', `¡Bienvenido, ${user.nombre_usuario}! Has iniciado sesión.`);
        console.log(`Usuario ${user.nombre_usuario} (ID: ${user.id}) ha iniciado sesión.`);
        res.redirect('/dashboard'); // Redirige al dashboard después de iniciar sesión
    });
});

// Ruta para cerrar sesión (GET /logout)
app.get('/logout', (req, res) => {
    // Destruye la sesión del usuario.
    req.session.destroy(err => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            // req.flash('error', 'No se pudo cerrar la sesión correctamente.'); // Comentado para depuración
        } else {
            // req.flash('success', 'Has cerrado sesión.'); // Comentado para depuración
        }
        res.redirect('/'); // Redirige a la página de inicio después de cerrar sesión
    });
});

// --- NUEVA RUTA: Dashboard (Ejemplo de página protegida) ---
// Esta ruta usa el middleware 'isAuthenticated' para asegurar que solo usuarios logueados accedan.
app.get('/dashboard', isAuthenticated, (req, res) => {
    // Renderiza la plantilla 'dashboard.ejs' y le pasa las variables de sesión.
    res.render('dashboard', {
        username: req.session.username,
        isParent: req.session.isParent
    });        
});


// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
    console.log(`Presiona Ctrl+C para detener el servidor.`);
});
