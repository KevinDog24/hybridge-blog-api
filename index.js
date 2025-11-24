// index.js

// ───── 1. Imports base ─────
require('dotenv').config();                 // Lee variables de entorno (.env)
const express = require('express');
const posts = require('./posts');           // Datos en memoria: publicaciones
const authors = require('./authors');       // Datos en memoria: autores
const db = require('./models');             // Sequelize (User vive aquí)

// ───── 2. Imports de autenticación ─────
const passport      = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const jwt           = require('jsonwebtoken');
const bcrypt        = require('bcryptjs');

// ───── 3. Inicializar app ─────
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para parsear JSON del body
app.use(express.json());

// Inicializar Passport en Express
app.use(passport.initialize());

/* ────────────────────────────────────────
   4. Estrategias de Passport
   ──────────────────────────────────────── */

/* 4.1 Estrategia Local (login con email + password) */
passport.use(
  'local',
  new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
      session: false
    },
    async (email, password, done) => {
      try {
        // Buscar usuario por email en la tabla Users
        const user = await db.User.findOne({ where: { email } });
        if (!user) {
          return done(null, false, { message: 'Usuario no existe' });
        }

        // Comparar password plano vs hash guardado
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) {
          return done(null, false, { message: 'Contraseña incorrecta' });
        }

        // Login exitoso
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

/* 4.2 Estrategia JWT (proteger rutas con token) */
passport.use(
  'jwt',
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
      session: false
    },
    async (payload, done) => {
      try {
        // payload.id lo pusimos nosotros al generar el token
        const user = await db.User.findByPk(payload.id);
        if (!user) {
          return done(null, false);
        }
        return done(null, user);
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

// Middleware reusable para proteger rutas
const requireAuth = passport.authenticate('jwt', { session: false });

/* ────────────────────────────────────────
   5. Rutas de autenticación (signup, login, profile)
   ──────────────────────────────────────── */

/** Registro de usuario */
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: 'Nombre, email y contraseña son requeridos' });
    }

    // Hashear contraseña
    const hash = await bcrypt.hash(password, 10);

    const user = await db.User.create({
      name,
      email,
      password: hash
    });

    res.status(201).json({ id: user.id, email: user.email });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/** Login → genera token JWT */
app.post(
  '/api/login',
  passport.authenticate('local', { session: false }),
  (req, res) => {
    const payload = { id: req.user.id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: '1h'
    });

    res.json({ token, token_type: 'Bearer' });
  }
);

/** Ruta protegida de ejemplo: perfil */
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    name: req.user.name,
    msg: 'Acceso concedido'
  });
});

/* ────────────────────────────────────────
   6. Ruta base
   ──────────────────────────────────────── */

app.get('/', (req, res) => {
  res.json({ message: 'Bienvenido a la API de Blog Posts' });
});

/* ────────────────────────────────────────
   7. CRUD de POSTS (en memoria)
   ──────────────────────────────────────── */

// GET - Obtener todos los posts
app.get('/api/posts', (req, res) => {
  res.json(posts);
});

// GET - Obtener un post por ID
app.get('/api/posts/:id', (req, res) => {
  const id = Number(req.params.id);
  const post = posts.find(p => p.id === id);

  if (!post) {
    return res.status(404).json({ error: 'Post no encontrado' });
  }

  res.json(post);
});

// POST - Crear un nuevo post (PROTEGIDO)
app.post('/api/posts', requireAuth, (req, res) => {
  const { title, content, author } = req.body;

  if (!title || !content || !author) {
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  }

  const newPost = {
    id: posts.length + 1,
    title,
    content,
    author,
    date: new Date()
  };

  posts.push(newPost);
  res.status(201).json(newPost);
});

// PATCH - Actualizar un post por ID (PROTEGIDO)
app.patch('/api/posts/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const post = posts.find(p => p.id === id);

  if (!post) {
    return res.status(404).json({ error: 'Post no encontrado' });
  }

  const { title, content, author } = req.body;

  if (title !== undefined) post.title = title;
  if (content !== undefined) post.content = content;
  if (author !== undefined) post.author = author;

  res.json(post);
});

// DELETE - Eliminar un post por ID (PROTEGIDO)
app.delete('/api/posts/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const index = posts.findIndex(p => p.id === id);

  if (index === -1) {
    return res.status(404).json({ error: 'Post no encontrado' });
  }

  posts.splice(index, 1);
  res.json({ message: 'Post eliminado correctamente' });
});

/* ────────────────────────────────────────
   8. CRUD de AUTORES (en memoria)
   ──────────────────────────────────────── */

// GET - Obtener todos los autores
app.get('/api/authors', (req, res) => {
  res.json(authors);
});

// GET - Obtener un autor por ID
app.get('/api/authors/:id', (req, res) => {
  const author = authors.find(a => a.id === Number(req.params.id));
  if (!author) {
    return res.status(404).json({ error: 'Autor no encontrado' });
  }
  res.json(author);
});

// POST - Crear un nuevo autor (PROTEGIDO)
app.post('/api/authors', requireAuth, (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Nombre requerido' });
  }

  const newAuthor = {
    id: authors.length + 1,
    name
  };

  authors.push(newAuthor);
  res.status(201).json(newAuthor);
});

// PATCH - Actualizar un autor por ID (PROTEGIDO)
app.patch('/api/authors/:id', requireAuth, (req, res) => {
  const author = authors.find(a => a.id === Number(req.params.id));
  if (!author) {
    return res.status(404).json({ error: 'Autor no encontrado' });
  }

  author.name = req.body.name || author.name;
  res.json(author);
});

// DELETE - Eliminar un autor por ID (PROTEGIDO)
app.delete('/api/authors/:id', requireAuth, (req, res) => {
  const index = authors.findIndex(a => a.id === Number(req.params.id));
  if (index === -1) {
    return res.status(404).json({ error: 'Autor no encontrado' });
  }

  authors.splice(index, 1);
  res.json({ message: 'Autor eliminado correctamente' });
});

/* ────────────────────────────────────────
   9. Arrancar servidor
   ──────────────────────────────────────── */

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
