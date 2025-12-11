import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const app = express();
app.use(cors());
app.use(express.json());

// -----------------------------
//  BASE DE DATOS (SIN .env)
// -----------------------------
const db = await mysql.createConnection({
    host: "bi4tjudnguq6holaxx1c-mysql.services.clever-cloud.com",
    user: "ucftg5pmhxve8vw5",
    password: "OZaKPFSRyQQyDWaJIOhD",
    database: "bi4tjudnguq6holaxx1c",
    port: 3306
});

console.log("Conectado a MySQL ✔");

const JWT_SECRET = "superclave123";

// =============================================
//     CREAR AUTOMÁTICAMENTE USUARIO ADMIN
// =============================================
async function createAdminUser() {
    const adminEmail = "admin@gmail.com";
    const adminPass = "1234";

    // ver si ya existe
    const [rows] = await db.execute(
        "SELECT * FROM users WHERE email = ?",
        [adminEmail]
    );

    if (rows.length > 0) {
        console.log("El admin ya existe ✔");
        return;
    }

    // si no existe → crearlo
    const hashed = await bcrypt.hash(adminPass, 10);

    await db.execute(
        "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)",
        [adminEmail, hashed, "Administrador", "admin"]
    );

    console.log("Usuario admin creado automáticamente ✔");
}

// Ejecutar función
createAdminUser();

// -----------------------------
//   LOGIN
// -----------------------------
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const [rows] = await db.execute(
        "SELECT * FROM users WHERE email = ?",
        [email]
    );

    if (rows.length === 0) return res.status(401).json({ error: "Usuario no encontrado" });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "2h" });

    res.json({ token, user });
});

// ---------------------------------
//   MIDDLEWARE PROTECCIÓN
// ---------------------------------
function auth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.sendStatus(401);

    try {
        const token = header.split(" ")[1];
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.sendStatus(401);
    }
}

// ---------------------------------
//  CRUD DE USUARIOS (ADMIN)
// ---------------------------------
app.get("/users", auth, async (req, res) => {
    const [rows] = await db.execute("SELECT id, email, full_name, role FROM users");
    res.json(rows);
});

app.post("/users", auth, async (req, res) => {
    const { email, password, full_name, role } = req.body;

    const hashed = await bcrypt.hash(password, 10);

    await db.execute(
        "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)",
        [email, hashed, full_name, role]
    );

    res.json({ message: "Usuario creado" });
});

app.put("/users/:id", auth, async (req, res) => {
    const { full_name, role } = req.body;

    await db.execute(
        "UPDATE users SET full_name=?, role=? WHERE id=?",
        [full_name, role, req.params.id]
    );

    res.json({ message: "Usuario actualizado" });
});

app.delete("/users/:id", auth, async (req, res) => {
    await db.execute("DELETE FROM users WHERE id=?", [req.params.id]);
    res.json({ message: "Usuario eliminado" });
});

// =============================================
//     RUTA PRINCIPAL PARA QUE RENDER MUESTRE ALGO
// =============================================
app.get("/", (req, res) => {
    res.send("API funcionando ✔");
});

// =============================================
//        INICIAR SERVIDOR
// =============================================
app.listen(3000, () => console.log("API lista en puerto 3000"));
