const express = require('express');
const pool = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer'); // สำหรับอัปโหลดไฟล์
const path = require('path'); // สำหรับจัดการเส้นทางไฟล์
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const port = 4000;

// กำหนดโฟลเดอร์สำหรับเก็บไฟล์ที่อัปโหลด
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// เปิดให้เข้าถึงไฟล์จากโฟลเดอร์ 'uploads'
app.use('/uploads', express.static('uploads'));

// ฟังก์ชันสำหรับตรวจสอบ token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // รับ token จาก header

    if (!token) return res.sendStatus(401); // ถ้าไม่มี token ส่ง status 401

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // ถ้า token ไม่ถูกต้อง ส่ง status 403

        req.user = user; // เก็บข้อมูล user ไว้ใน req
        next(); // ดำเนินการต่อไป
    });
};

// ฟังก์ชันสำหรับการลงทะเบียนผู้ใช้ใหม่
app.post('/register', async (req, res) => {
    const { email, password, name } = req.body;

    try {
        const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'Email นี้ถูกใช้ไปแล้ว' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (email, password, name) VALUES (?, ?, ?)', [email, hashedPassword, name]);
        res.status(201).json({ message: 'ลงทะเบียนผู้ใช้สำเร็จ' });
    } catch (error) {
        console.error('Error during user registration:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการลงทะเบียน' });
    }
});

// ฟังก์ชันสำหรับการเข้าสู่ระบบ
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [results] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        const user = results[0];

        if (!user) {
            return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });
        }

        const accessToken = jwt.sign(
            { id: user.id, email: user.email },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '20h' }
        );
        res.json({ token: accessToken });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ' });
    }
});

// ฟังก์ชันสำหรับการโพสต์
app.post('/api/posts', authenticateToken, upload.single('image'), async (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.id; // รับ user ID จาก token
    const image_url = req.file ? `/uploads/${req.file.filename}` : null; // URL ของไฟล์ที่อัปโหลด

    try {
        // SQL query สำหรับเพิ่มข้อมูลลงในตาราง post02
        const query = 'INSERT INTO post02 (title, content, author, image_url, user_id) VALUES (?, ?, ?, ?, ?)';
        await pool.query(query, [title, content, req.user.email, image_url, userId]); // เพิ่ม user_id

        res.status(201).json({ message: 'เพิ่มโพสต์สำเร็จ', title, content, author: req.user.email, image_url });
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเพิ่มโพสต์' });
    }
});


// เส้นทางสำหรับดึงโพสต์ทั้งหมดของผู้ใช้ที่ล็อกอิน
app.get('/api/posts', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id; // รับ user ID จาก token
        const [results] = await pool.query("SELECT * FROM post02 WHERE user_id = ?", [userId]); // ดึงเฉพาะโพสต์ของผู้ใช้
        res.json(results); // ส่งข้อมูลกลับไปยัง client
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงโพสต์' });
    }
});


// เส้นทางสำหรับการลบโพสต์
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    const postId = req.params.id; // รับ ID ของโพสต์ที่ต้องการลบ
    try {
        // ตรวจสอบว่าโพสต์นี้เป็นของผู้ใช้หรือไม่
        const [post] = await pool.query("SELECT * FROM post02 WHERE id = ? AND user_id = ?", [postId, req.user.id]);
        if (post.length === 0) {
            return res.status(403).json({ message: 'คุณไม่มีสิทธิ์ลบโพสต์นี้' });
        }

        // ลบโพสต์
        await pool.query("DELETE FROM post02 WHERE id = ?", [postId]);
        res.status(200).json({ message: 'ลบโพสต์สำเร็จ' });
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการลบโพสต์' });
    }
});



// เส้นทางสำหรับการแก้ไขโพสต์
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
    const postId = req.params.id; // รับ ID ของโพสต์ที่ต้องการแก้ไข
    const { title, content } = req.body; // รับข้อมูลใหม่จาก body

    try {
        // ตรวจสอบว่าโพสต์นี้เป็นของผู้ใช้หรือไม่
        const [post] = await pool.query("SELECT * FROM post02 WHERE id = ? AND user_id = ?", [postId, req.user.id]);
        if (post.length === 0) {
            return res.status(403).json({ message: 'คุณไม่มีสิทธิ์แก้ไขโพสต์นี้' });
        }

        // อัปเดตโพสต์
        await pool.query("UPDATE post02 SET title = ?, content = ? WHERE id = ?", [title, content, postId]);
        res.status(200).json({ message: 'แก้ไขโพสต์สำเร็จ' });
    } catch (error) {
        console.error('Error updating post:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการแก้ไขโพสต์' });
    }
});

// เส้นทางสำหรับอัปเดตโปรไฟล์ผู้ใช้ (ต้องยืนยันตัวตน)
app.post('/updateProfile', authenticateToken, upload.single('profilePicture'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, email, number } = req.body; // ดึงข้อมูลจาก form

        // ตรวจสอบข้อมูลที่รับเข้ามา
        if (!name || !email) {
            return res.status(400).json({ message: 'กรุณากรอกชื่อและอีเมลให้ครบถ้วน' });
        }

        let profilePicturePath = '';
        if (req.file) {
            profilePicturePath = `/uploads/${req.file.filename}`;
        }

        // สร้างคำสั่ง SQL เพื่ออัปเดตข้อมูล
        let updateQuery = 'UPDATE users SET name = ?, email = ?';
        const queryParams = [name, email];

        // ถ้ามีเบอร์โทรศัพท์ให้เพิ่มเข้าไปในคำสั่งอัปเดต
        if (number) {
            updateQuery += ', number = ?';
            queryParams.push(number);
        }

        // ถ้ามีรูปโปรไฟล์ให้เพิ่มเข้าไปในคำสั่งอัปเดต
        if (profilePicturePath) {
            updateQuery += ', picture = ?';
            queryParams.push(profilePicturePath);
        }

        updateQuery += ' WHERE id = ?';
        queryParams.push(userId);

        // อัปเดตข้อมูลผู้ใช้
        await pool.query(updateQuery, queryParams);

        res.status(200).json({ message: 'อัปเดตข้อมูลสำเร็จ' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการอัปเดตโปรไฟล์' });
    }
});

// เส้นทางสำหรับดึงข้อมูลผู้ใช้งานที่เข้าสู่ระบบ (ต้องยืนยันตัวตน)
app.get('/account', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // ดึงข้อมูลผู้ใช้จากฐานข้อมูลโดยใช้ userId จาก token
        const [results] = await pool.query("SELECT email, name, picture, number FROM users WHERE id = ?", [userId]);

        if (results.length === 0) {
            return res.status(404).json({ error: "ไม่พบผู้ใช้" });
        }

        res.json(results[0]); // ส่งข้อมูลผู้ใช้กลับไปยัง client
    } catch (err) {
        console.log('Error fetching user account:', err);
        res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้" });
    }
});

// เริ่มเซิร์ฟเวอร์
app.listen(port, () => {
    console.log(`เซิร์ฟเวอร์กำลังทำงานที่พอร์ต ${port}`);
});
