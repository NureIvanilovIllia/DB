const jsonServer = require("json-server");
const auth = require('json-server-auth');
const cors = require('cors');
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();

const app = jsonServer.create();
app.db = router.db;

const JWT_SECRET = 'myUltraSuperSecretKey!changeMe123456!s3cr3t!';

app.use(cors());
app.use(jsonServer.bodyParser);

// ======== Хелпер: получение user_id из токена =========
function getUserIdFromToken(req) {
  try {
    const jwt = require('jsonwebtoken');
    const authHeader = req.headers.authorization;
    if (!authHeader) return null;
    const token = authHeader.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded.sub;
  } catch {
    return null;
  }
}

// ============ Регистрация =============
app.post('/custom-register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Username, email and password are required' });
  }

  // Check uniqueness
  const existingUsername = app.db.get('usersN').find({ username }).value();
  const existingEmail = app.db.get('usersN').find({ email }).value();

  if (existingUsername) {
    return res.status(400).json({ message: 'Username already exists' });
  }
  if (existingEmail) {
    return res.status(400).json({ message: 'Email already exists' });
  }

  // Hash password
  const bcrypt = require('bcryptjs');
  const hashedPassword = await bcrypt.hash(password, 10);

  // Найти максимальный id среди пользователей
  const users = app.db.get('usersN').value();
  let nextId = 1;
  if (users.length > 0) {
    nextId = Math.max(...users.map(u => typeof u.id === 'number' ? u.id : 0)) + 1;
  }

  // Create user
  const user = {
    id: nextId, // теперь id идет по порядку!
    username,
    email,
    password: hashedPassword
  };

  app.db.get('usersN').push(user).write();

  // Generate JWT
  const jwt = require('jsonwebtoken');
  const accessToken = jwt.sign(
    { email: user.email, sub: user.id },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
  res.status(201).json({
    accessToken,
    user: { id: user.id, email: user.email, username: user.username }
  });
});

// ============ Логин ============
app.post('/custom-login', (req, res) => {
  const { username, email, password } = req.body;
  let user;

  if (username) {
    user = app.db.get('usersN').find({ username }).value();
  } else if (email) {
    user = app.db.get('usersN').find({ email }).value();
  }

  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  const bcrypt = require('bcryptjs');
  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) {
    return res.status(400).json({ message: 'Invalid password' });
  }

  const jwt = require('jsonwebtoken');
  const accessToken = jwt.sign(
    { email: user.email, sub: user.id },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
  res.json({
    accessToken,
    user: { id: user.id, email: user.email, username: user.username }
  });
});

// ============ Обновление и получение профиля пользователя (User) ============
app.patch('/user/me', (req, res) => {
  const userId = getUserIdFromToken(req);
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  const updates = req.body;
  const user = app.db.get('usersN').find({ id: userId }).value();
  if (!user) return res.status(404).json({ message: 'User not found' });

  Object.assign(user, updates);
  app.db.get('usersN').find({ id: userId }).assign(user).write();
  res.json(user);
});

app.get('/user/me', (req, res) => {
  const userId = getUserIdFromToken(req);
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  const user = app.db.get('usersN').find({ id: userId }).value();
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json(user);
});

// ============ Personal_User_Data endpoints ============
app.patch('/personal-user-data/me', (req, res) => {
  const userId = getUserIdFromToken(req);
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  let pud = app.db.get('personalUserDataN').find({ user_id: userId }).value();
  if (!pud) {
    pud = {
      personal_user_data_id: Date.now(),
      user_id: userId,
      ...req.body
    };
    app.db.get('personalUserDataN').push(pud).write();
  } else {
    Object.assign(pud, req.body);
    app.db.get('personalUserDataN').find({ user_id: userId }).assign(pud).write();
  }
  res.json(pud);
});

app.get('/personal-user-data/me', (req, res) => {
  const userId = getUserIdFromToken(req);
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  const pud = app.db.get('personalUserDataN').find({ user_id: userId }).value();
  if (!pud) return res.status(404).json({ message: 'Personal data not found' });
  res.json(pud);
});

// ============ Membership endpoints ============
app.get('/memberships/me', (req, res) => {
  const userId = getUserIdFromToken(req);
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  const membership = app.db.get('membershipsN').find({ user_id: userId }).value();
  if (!membership) return res.status(404).json({ message: 'Membership not found' });
  res.json(membership);
});


// ============ Обновление последней записи UserTargetCalculation =============
app.put('/userTargetCalculations/update-last', (req, res) => {
  const userId = getUserIdFromToken(req);
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  const userCalculations = app.db
    .get('userTargetCalculationsN')
    .filter({ user_id: userId })
    .sortBy('calculatedTargetDate')
    .value();

  if (!userCalculations.length) {
    return res.status(404).json({ message: 'No target calculations found for this user' });
  }

  const lastCalc = userCalculations[userCalculations.length - 1];

  const updatedCalc = {
    ...lastCalc,
    ...req.body,
  };

  app.db
    .get('userTargetCalculationsN')
    .find({ id: lastCalc.id })
    .assign(updatedCalc)
    .write();

  res.json(updatedCalc);
});

// ============ Остальные ручки ============
app.use(auth);
app.use(middlewares);
app.use(router);
app.listen(process.env.PORT || 3000, () => {
    console.log("JSON Server is running");
});
