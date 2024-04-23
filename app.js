const express = require('express');
const app = express();
const session = require('express-session');
const bodyParser = require('body-parser');
const port = 3000;
const conn = require("./configdb");
const nodemailer = require('nodemailer');
const req = require('express/lib/request');
const flash = require('express-flash');
const crypto = require('crypto');
const moment = require('moment');


const options = {
    dotfiles: 'ignore',
    etag: false,  
    extensions: ['htm', 'html'],  
    index: false,
    maxAge: '1d',
    redirect: false,
    setHeaders: function (res, path, stat) {
      res.set('x-timestamp', Date.now())
    }
}

// Pengaturan template engine
app.set('view engine', 'ejs');

// Middleware untuk parsing data yang dikirimkan melalui body
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Middleware untuk mengatur direktori tampilan statis
app.use(express.static('public'));

app.use(flash());
// Middleware untuk session
app.use(session({
    secret: 'sya131', // Ganti dengan kunci rahasia yang aman
    resave: false,
    saveUninitialized: true
}));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'nfsyalza@gmail.com',
      pass: 'atmp lfce lugq yjew',
    },
  });

// Rute Login
app.get('/', (req, res) => {
    console.log('Berada di Halaman Login');
    const errorMessage = req.flash('error')[0];
    const successMessage = req.flash('success')[0];
    res.render('login', { title: 'Login Page', error: errorMessage, success: successMessage });
});
// Rute untuk memproses permintaan login
app.post('/', (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role) {
        return res.status(400).send('Bad Request');
    }

    if (role === 'admin') {

        // Periksa data login di tabel admin
        const sql = 'SELECT * FROM admin WHERE username = ? AND password = ?';
        const values = [username, password];

        conn.query(sql, values, (err, results) => {
            if (err) {
                console.error(err);
                console.log("Terjadi Kesalahan Saat Login")
                res.status(500).send('Terjadi kesalahan saat login.');
            }
            if (results.length > 0) {
                req.session.role = 'admin'; // Simpan peran admin ke dalam sesi
                console.log("Berhasil masuk ke halaman dashboard")
                return res.redirect('/homeAdmin'); // Redirect ke halaman admin jika login berhasil
            } else {
                req.flash('error', 'Username atau password atau role salah. Coba lagi!');
                return res.redirect('/');
            }
        });
    } else if (role === 'kasir') {
        // Periksa data login di tabel kasir
        conn.query('SELECT * FROM kasir WHERE username = ? AND password = ?', [username, password], (err, results) => {
            if (err) {
                console.error('Error executing query:', err);
                return res.status(500).send('Internal Server Error');
            }

            if (results.length > 0) {
                req.session.role = 'kasir'; // Simpan peran kasir ke dalam sesi
                req.session.username = username;
                return res.redirect('/penjualan'); // Redirect ke halaman kasir jika login berhasil
            } else {
                req.flash('error', 'Username atau password atau role salah. Coba lagi!');
                return res.redirect('/');
            }
        });
    } else {
        return res.status(400).send('Bad Request');
    }
});

// Rute forgot password
app.get('/forgotpass', (req, res) => {
    const message = "Enter your email address";
    console.log('Berada di Halaman Forgot Password');
    res.render('forgotPass', {title: 'Forgot Password', message } );
});
// Route untuk penanganan reset password admin
app.post('/forgotpass', async (req, res) => {
    try {
        const userEmail = req.body.email;

        // Query ke database untuk memeriksa apakah email ada dalam tabel admin
        const query = 'SELECT * FROM admin WHERE email = ?';
        conn.query(query, [userEmail], async (err, results) => {
            if (err) {
                console.error('Error saat mengambil data dari database:', err);
                req.flash('error', 'Gagal memeriksa email.');
                return res.redirect('/forgotPassword-admin');
            }

            // Jika email tidak ditemukan dalam database
            if (results.length === 0) {
                req.flash('error', 'Email tidak terdaftar sebagai admin.');
                return res.redirect('/forgotPassword-admin');
            }

            // Generate token unik untuk reset password
            const token = crypto.randomBytes(20).toString('hex');

            // Simpan token reset ke dalam database
            const insertQuery = 'INSERT INTO admin_reset_tokens (email, token, expiration_time) VALUES (?, ?, NOW() + INTERVAL 24 HOUR)';
            conn.query(insertQuery, [userEmail, token], (err, results) => {
                if (err) {
                    console.error('Error saat menyimpan data ke database:', err);
                    req.flash('error', 'Gagal menyimpan token reset.');
                    return res.redirect('/forgotPassword-admin');
                }
                const expirationTime = moment().add(24, 'hours');
                console.log('Token reset berhasil disimpan untuk email:', userEmail);
                console.log('Waktu Kadaluarsa Token (Disimpan):', expirationTime.format());

                // Konstruksi resetLink
                const resetLink = `http://localhost:3000/resetPass/${token}`;

                // Konfigurasi mailOptions dengan email penerima dan resetLink
                const mailOptions = {
                    from: 'nfsyalza@gmail.com',
                    to: userEmail,
                    subject: 'Reset Password',
                    text: `Untuk mereset password Anda, klik tautan berikut: ${resetLink}`,
                    html: `<p>Untuk mereset password Anda, klik tautan berikut: <a href="${resetLink}">${resetLink}</a></p>`,
                };

                // Kirim email
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error('Error saat mengirim email:', error);
                        req.flash('error', 'Gagal mengirim email reset password.');
                    } else {
                        console.log('Email terkirim:', info.response);
                        req.flash('success', 'Email reset password berhasil dikirim.');
                    }
                    // Redirect ke halaman forgot password
                    res.redirect('/forgotPass');
                });
            });
        });

    } catch (error) {
        console.error(error.message);
        req.flash('error', 'Gagal mengirim email reset password.');
        res.redirect('/forgotPass');
    }
});


// Rute reset password
app.get('/resetPass/:token', (req, res) => {
    const token = req.params.token;
  
    try {
        // Mendapatkan token dari database
        const querySelect = 'SELECT * FROM admin_reset_tokens WHERE token = ?';
        conn.query(querySelect, [token], (err, resultSelect) => {
            if (err) {
                console.error('Error querying database:', err);
                return res.status(500).send('Internal Server Error');
            }
            
            if (!resultSelect || resultSelect.length === 0) {
                console.log('Token tidak ditemukan atau tidak valid.');
                req.flash('error', 'Token tidak valid.');
                return res.render('resetPass', { title: 'Reset Password', token: null, email: null });
            }

            // Ambil email dari hasil query
            const email = resultSelect[0].email;

            // Render halaman reset password dengan token dan email
            res.render('resetPass', { title: 'Reset Password', token: token, email: email });
        });
    } catch (error) {
        console.error('Error saat menampilkan halaman reset password:', error);
        req.flash('error', 'Terjadi kesalahan saat memeriksa token reset password.');
        // Redirect to a different page or render the current page with flash message
        res.render('resetPass', { title: 'Reset Password', token: null, email: null });
    } finally {
        // Clear flash messages after rendering the page
        req.flash();
    }
});

app.post('/resetPass/:token', async (req, res) => {
    const { token, email, newPassword } = req.body;
    console.log('Token yang diterima:', token);
    console.log('Data formulir:', req.body);

    console.log('Isi req.body:', req.body);

    try {
        // Memeriksa validitas token
        const querySelect = 'SELECT * FROM admin_reset_tokens WHERE token = ?';
        console.log('Mencari token dengan query:', querySelect);
        conn.query(querySelect, [token], (err, resultSelect) => {
            if (err) {
                console.error('Error querying database:', err);
                return res.status(500).send('Internal Server Error');
            }
            
            console.log('Hasil pencarian token:', resultSelect);

            if (!resultSelect || resultSelect.length === 0) {
                console.log('Token tidak ditemukan atau tidak valid.');
                return res.render('resetPass', { title: 'Reset Password', token: null, email: null });
            }

            // Ambil email dari hasil query
            const email = resultSelect[0].email;

            console.log('Email yang diambil dari hasil query:', email);
            console.log('Nilai newPassword sebelum update:', newPassword);


            if (email === null || email === undefined) {
                console.log('Email tidak ditemukan atau tidak valid dalam hasil query.');
                return res.render('resetPass', { title: 'Reset Password', token: null, email: null });
            }

            console.log(newPassword)
            // Mengupdate password admin
            console.log('Mengupdate password dengan query:', 'UPDATE admin SET password = ? WHERE email = ?');
            const queryUpdate = 'UPDATE admin SET password = ? WHERE email = ?';
            conn.query(queryUpdate, [newPassword, email], (err, resultUpdate) => {
                if (err) {
                    console.error('Error updating password:', err);
                    return res.status(500).send('Internal Server Error');
                }
                
                console.log('Hasil update password:', resultUpdate);

                if (resultUpdate && resultUpdate.affectedRows !== undefined && resultUpdate.affectedRows === 1) {
                    console.log('Password berhasil diupdate.');
                    return res.render('resetPass', { title: 'Reset Password', token: token, email: email });
                } else {
                    console.log('Gagal mengupdate password.');
                    return res.render('resetPass', { title: 'Reset Password', token: null, email: null });
                }
            });
        });
    } catch (error) {
        console.error('Error memeriksa validitas token reset dan mengupdate password:', error);
        console.error('Error stack trace:', error.stack);
        return res.status(500).send('Internal Server Error');
    }
});


// Rute untuk halaman admin
app.get('/homeAdmin', (req, res) => {
    if (req.session.role === 'admin') {
        console.log('Berhasil berada di halaman dashboard');
        res.render('homeAdmin', { title: 'Home Kasir Page' });
    } else {
        res.status(403).send('Forbidden');
    }
});

// Rute untuk halaman kasir
app.get('/homeKasir', (req, res) => {
    if (req.session.role === 'kasir') {
        console.log('Berhasil berada di halaman dashboard');
        res.render('homeKasir', { title: 'Home Kasir Page' });
    } else {
        res.status(403).send('Forbidden');
    }
});

//Rute halaman data barang
app.get('/barang', (req, res) => {
    if (req.session.role === 'admin') {
        const sql = 'SELECT kode_barang, nama_barang, harga, stok FROM barang';
        conn.query(sql, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
        console.log('Berhasil berada di halaman data barang');
        res.render('barang', { title: 'Data Barang', barang: results, isAdmin: true });
    });
    // Jika bukan admin
    } else if (req.session.role === 'kasir') {
        const sql = 'SELECT kode_barang, nama_barang, harga, stok FROM barang';
            conn.query(sql, (err, results) => {
                if (err) {
                    console.error('Error querying database:', err);
                    res.status(500).send('Internal Server Error');
                    return;
                }
                console.log('Berhasil berada di halaman data barang');
                res.render('barang', { title: 'Data Barang Page', barang: results, isAdmin: false });
            });
    } else {
        res.redirect('/login');
    }
  });

// Rute untuk menambah data barang
app.post('/barang/add', (req, res) => {
    if (req.session.role === 'admin') {
        const { kode_barang, nama_barang, harga, stok } = req.body;

        // Pastikan semua data barang yang diperlukan tersedia
        if (!kode_barang || !nama_barang || !harga || !stok) {
            return res.status(400).send('Bad Request');
        }

        // Query untuk menambahkan data barang ke database
        const sql = 'INSERT INTO barang (kode_barang, nama_barang, harga, stok) VALUES (?, ?, ?, ?)';
        const values = [kode_barang, nama_barang, harga, stok];

        conn.query(sql, values, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            console.log('Data barang berhasil ditambahkan:', results);
            // Redirect kembali ke halaman data barang setelah menambahkan barang
            res.redirect('/barang');
        });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
});

// Rute untuk mengupdate data barang
app.post('/barang/update/:kode_barang', (req, res) => {
    if (req.session.role === 'admin') {
        const { nama_barang, harga, stok } = req.body;
        const kode_barang = req.params.kode_barang;

        // Pastikan semua data barang yang diperlukan tersedia
        if (!kode_barang || !nama_barang || !harga || !stok) {
            return res.status(400).send('Bad Request');
        }

        // Query untuk update data barang ke database
        const sql = 'UPDATE barang SET nama_barang = ?, harga = ?, stok = ? WHERE  kode_barang = ?';
        const values = [nama_barang, harga, stok, kode_barang];

        conn.query(sql, values, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            console.log('Data barang berhasil diupdate:', results);
            // Redirect kembali ke halaman data barang setelah menambahkan barang
            res.redirect('/barang');
        });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
});

//Rute untuk menghapus data barang
app.post('/barang/delete/:kode_barang', (req, res) => {
    if (req.session.role === 'admin') {
        const kode_barang = req.params.kode_barang;

        const sql = 'DELETE from barang WHERE kode_barang = ?';
        conn.query(sql, kode_barang, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            console.log('Data barang berhasil dihapus:', results);
            // Redirect kembali ke halaman data barang setelah menambahkan barang
            res.redirect('/barang');
        });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
});

app.get('/dataKasir', (req, res) => {
    if (req.session.role === 'admin') {
        const sql = 'SELECT username, nama_lengkap, telepon, alamat FROM kasir';
        conn.query(sql, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
        console.log('Berhasil berada di halaman data kasir');
        res.render('dataKasir', { title: 'Data Kasir',  kasir: results });
    });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
  });

// Rute untuk menambah data kasir
app.post('/dataKasir/add', (req, res) => {
    if (req.session.role === 'admin') {
        const { username, nama_lengkap, telepon, alamat, password } = req.body;


        // Pastikan semua data kasir yang diperlukan tersedia
        if (!username || !nama_lengkap || !telepon || !alamat || !password) {
            return res.status(400).send('Bad Request');
        }
        // Query untuk menambahkan data kasir ke database
        const sql = 'INSERT INTO kasir (username, nama_lengkap, telepon, alamat, password) VALUES (?, ?, ?, ?, ?)';
        const values = [username, nama_lengkap, telepon, alamat, password];

        conn.query(sql, values, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            console.log('Data kasir berhasil ditambahkan:', results);
            // Redirect kembali ke halaman data kasir setelah menambahkan data
            res.redirect('/dataKasir');
        });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
});

// Rute untuk melakukan update kasir
app.post('/dataKasir/update/:username', (req, res) => {
    if (req.session.role === 'admin') {
        const username = req.params.username;
        const { nama_lengkap, telepon, alamat } = req.body;

        // Lakukan update data kasir ke dalam database
        const sql = 'UPDATE kasir SET nama_lengkap = ?, telepon = ?, alamat = ? WHERE username = ?';
        conn.query(sql, [nama_lengkap, telepon, alamat, username], (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            // Jika pengguna dengan username yang diberikan tidak ditemukan
            if (results.affectedRows === 0) {
                res.status(404).send('Pengguna tidak ditemukan.');
                return;
            }
            // Redirect kembali ke halaman data kasir setelah data kasir berhasil diupdate
            res.redirect('/dataKasir');
        });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
});

//Rute untuk menghapus data barang
app.post('/dataKasir/delete/:username', (req, res) => {
    if (req.session.role === 'admin') {
        const username = req.params.username;

        const sql = 'DELETE from kasir WHERE username = ?';
        conn.query(sql, [username], (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            console.log('Data barang berhasil dihapus:', results);
            // Redirect kembali ke halaman data kasir setelah menambahkan data kasir
            res.redirect('/dataKasir');
        });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
});

// Rute untuk menampilkan form reset password kasir
app.get('/dataKasir/reset-password/:username', (req, res) => {
    const username = req.params.username;
    const sql = 'SELECT * FROM kasir WHERE username = ?';
    conn.query(sql, [username], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            res.status(500).send('Internal Server Error');
            return;
        }
        // Jika pengguna dengan username yang diberikan tidak ditemukan
        if (results.length === 0) {
            res.status(404).send('Pengguna tidak ditemukan.');
            return;
        }
        res.render('resetPassword', { title: 'Reset password page', user: results[0] });
    });
});

// Rute untuk menangani reset password kasir
app.post('/dataKasir/reset-password/:username', (req, res) => {
    const username = req.params.username;
    const newPassword = req.body.newPassword;

    // Lakukan update password ke dalam database
    const sql = 'UPDATE kasir SET password = ? WHERE username = ?';
    conn.query(sql, [newPassword, username], (err, result) => {
        if (err) {
            console.error('Error querying database:', err);
            res.status(500).send('Internal Server Error');
            return;
        }

        // Check if the password was successfully updated
        if (result.affectedRows > 0) {
            console.log(`Password for user ${username} reset successfully.`);
            // Mengalihkan kembali ke halaman data kasir
            res.redirect('/dataKasir');
        } else {
            console.log(`Failed to reset password for user ${username}. User not found.`);
            res.status(404).send('Pengguna tidak ditemukan.');
        }
    });
});

//Rute halaman laporan member
app.get('/lapMember', (req, res) => {
    if (req.session.role === 'admin') {
        const sql = 'SELECT kode_member, nama, telepon, alamat FROM member';
        conn.query(sql, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
        console.log('Berhasil berada di halaman data member');
        res.render('lapMember', { title: 'Data Member',  member: results });
    });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
  });

app.get('/lapMember/print', (req, res) => {
    if (req.session.role === 'admin' || req.session.role === 'kasir') { 
        const sql = 'SELECT kode_member, nama, telepon, alamat FROM member';
        conn.query(sql, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
        console.log('Berhasil berada di halaman data member');
        res.render('lapMember-print', { title: 'Data Member',  member: results });
    });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
  });


//Rute halaman stok barang
app.get('/lapStok', (req, res) => {
    if (req.session.role === 'admin' || req.session.role === 'kasir') { 
        const sql = 'SELECT kode_barang, nama_barang, stok FROM barang';
        conn.query(sql, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
        console.log('Berhasil berada di halaman laporan stok barang');
        res.render('lapStok', { title: 'Laporan Stok Barang',  stok: results, role: req.session.role });
    });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
  });

app.get('/lapStok/print', (req, res) => {
    if (req.session.role === 'admin' || req.session.role === 'kasir') { 
        const sql = 'SELECT kode_barang, nama_barang, stok FROM barang';
        conn.query(sql, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
        console.log('Berhasil berada di halaman laporan stok barang');
        res.render('lapStok-print', { title: 'Laporan Stok Barang',  stok: results, role: req.session.role });
    });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
});

//Rute halaman laporan penjualan
app.get('/lapPenjualan', (req, res) => {
    if (req.session.role === 'admin') {
        const sql = 'SELECT tgl, kode_transaksi, kasir, kode_barang, nama_barang, qty, harga, total FROM transaksi';
        conn.query(sql, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
        console.log('Berhasil berada di halaman laporan stok barang');
        res.render('lapPenjualan', { title: 'Laporan Penjualan', penjualan: results,  isAdmin: true  });
    });
}   else if (req.session.role === 'kasir') {
    const sql = 'SELECT tgl, kode_transaksi, kasir, kode_barang, nama_barang, qty, harga, total FROM transaksi where kasir = ?';
    conn.query(sql, [req.session.username], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            res.status(500).send('Internal Server Error');
            return; 
        }
    console.log('Berhasil berada di halaman laporan stok barang');
    res.render('lapPenjualan', { title: 'Laporan Penjualan', penjualan: results,  isAdmin: false });
});
    } else {
        res.status(403).send('Forbidden');
    }
});
  
const keranjang = [];
// function generateUniqueTransactionID(req) {
//     // Mendapatkan nomor urut transaksi terakhir dari sesi atau database
//     let lastNumber = req.session.lastTransactionNumber || 0;
//     let nextNumber = lastNumber + 1;
//     req.session.lastTransactionNumber = nextNumber; // Menyimpan nomor urut untuk digunakan di transaksi berikutnya

    
//     let nextID = "PJ" + ("000" + nextNumber).slice(-3);
//     return nextID;
// }
function generateUniqueTransactionID(req, lastNumber) {
    let nextNumber = lastNumber + 1;
    req.session.lastTransactionNumber = nextNumber; // Menyimpan nomor urut untuk digunakan di transaksi berikutnya
    
    let nextID = "PJ" + ("000" + nextNumber).slice(-3);
    return nextID;
}

//Rute input penjulan pada form dan masukan ke keranjang
app.post('/penjualan/add', (req, res) => {
    // Tangkap data dari form
    const { kode_barang, qty } = req.body;
     // Validasi data
     if (!kode_barang || !qty) {
        res.status(400).send('Semua kolom harus diisi');
        return;
    }

    const kasir = req.session.username || 'Kasir Tidak Tersedia';
    if (!req.session.username) {
        console.error('Session username tidak tersedia');
        res.status(500).send('Internal Server Error');
        return;
    }

    const tgl = new Date().toISOString().slice(0, 10); // Ambil tanggal penjualan saat ini
    
    // const lastIDQuery = 'SELECT MAX(kode_transaksi) AS lastID FROM transaksi';
    // conn.query(lastIDQuery, (err, results) => {
    //     if (err) {
    //         console.error('Error querying database:', err);
    //         res.status(500).send('Internal Server Error');
    //         return;
    //     }

    //     // Mengambil angka dari kode transaksi terakhir
    //     let lastID = results[0].lastID;
    //     let nextID = generateUniqueTransactionID(req);

        // Query untuk mendapatkan informasi barang dari database berdasarkan kode_barang yang dipilih
        const sql = 'SELECT nama_barang, harga FROM barang WHERE kode_barang = ?';
        conn.query(sql, [kode_barang], (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }

            // Pastikan ada hasil dari query
            if (results.length > 0) {
                const { nama_barang, harga } = results[0];
                const total = harga * qty;


            // // Membuat kode transaksi baru jika belum ada
            // if (!req.session.currentTransactionID) {
            //     req.session.currentTransactionID = generateUniqueTransactionID(req);
            // }
            // const nextID = req.session.currentTransactionID;
                // Mendapatkan nomor urut terakhir dari database
            const lastIDQuery = 'SELECT MAX(SUBSTRING_INDEX(kode_transaksi, "PJ", -1)) AS lastID FROM transaksi';
            conn.query(lastIDQuery, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }

            // Mengambil nomor urut dari kode transaksi terakhir
            let lastNumber = parseInt(results[0].lastID) || 0;

            // Generate unique transaction ID based on the last number
            const nextID = generateUniqueTransactionID(req, lastNumber);
            
            // Buat objek untuk item penjualan
            const item = {
                kode_penjualan: nextID,
                kasir: kasir,
                tgl: tgl,
                kode_barang: kode_barang,
                nama_barang: nama_barang,
                harga: harga,
                qty: qty,
                total: total
            };
            // Simpan keranjang di dalam sesi
            if (!req.session.keranjang) {
                req.session.keranjang = [];
            }
            req.session.keranjang.push(item);

            // Console log untuk memeriksa data masuk ke keranjang
            console.log('Data berhasil dimasukkan ke dalam keranjang:', item);

            res.redirect('/penjualan'); // Redirect pengguna kembali ke halaman penjualan
        });
        } else {
            res.status(404).send('Kode barang tidak ditemukan dalam database');
        }
    });
});

app.get('/detail-barang', (req, res) => {
    const barangQuery = 'SELECT kode_barang, nama_barang, harga, stok FROM barang';
    conn.query(barangQuery, (err, barang) => {
        if (err) {
            console.error('Error querying database:', err);
            res.status(500).send('Internal Server Error');
            return;
        }
        res.json(barang);
    });
});


// Rute untuk menampilkan halaman penjualan
app.get('/penjualan', (req, res) => {
    const kasir = req.session.username || 'Kasir Tidak Tersedia';
    if (!req.session.username) {
        console.error('Session username tidak tersedia');
        res.status(500).send('Internal Server Error');
        return;
    }

    const tgl = new Date().toISOString().slice(0, 10); // Ambil tanggal penjualan saat ini

    // Query untuk mengambil semua kode member dari tabel member
    const memberQuery = 'SELECT kode_member FROM member';
    conn.query(memberQuery, (err, memberResults) => {
        if (err) {
            console.error('Error querying member database:', err);
            res.status(500).send('Internal Server Error');
            return;
        }

        // Ambil kode member dari hasil query
        const kodeMemberOptions = memberResults.map(result => result.kode_member);

         // Mengambil keranjang dari sesi
        const keranjang = req.session.keranjang || [];
        // Hitung subtotal dari keranjang
        const subtotal = keranjang.reduce((total, item) => total + item.total, 0);

        // Query untuk mengambil data barang dari database
        const barangQuery = 'SELECT kode_barang, nama_barang, harga FROM barang';
        conn.query(barangQuery, (err, barang) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }

            // // Membuat kode transaksi baru jika belum ada
            // if (!req.session.currentTransactionID) {
            //     req.session.currentTransactionID = generateUniqueTransactionID(req);
            // }
            // const nextID = req.session.currentTransactionID;

            const lastIDQuery = 'SELECT MAX(SUBSTRING_INDEX(kode_transaksi, "PJ", -1)) AS lastID FROM transaksi';
            conn.query(lastIDQuery, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }

            // Mengambil nomor urut dari kode transaksi terakhir
            let lastNumber = parseInt(results[0].lastID) || 0;

            // Generate unique transaction ID based on the last number
            const nextID = generateUniqueTransactionID(req, lastNumber);

        // Render halaman penjualan setelah mendapatkan kode transaksi
        res.render('penjualan', { 
            title: 'Penjualan', 
            kasir: kasir,
            kode_transaksi: nextID,
            tgl: tgl,
            kodeMemberOptions: kodeMemberOptions,
            barang: barang,
            keranjang: keranjang,
            subtotal: subtotal
        });
    });
});
});
});

// Rute untuk menyimpan dan mencetak stuk transaksi, termasuk pembayaran
app.post('/penjualan/save', (req, res) => {
    const keranjang = req.session.keranjang || [];

    // Validasi keranjang tidak boleh kosong
    if (keranjang.length === 0) {
        res.status(400).send('Keranjang kosong, tidak ada transaksi untuk disimpan');
        return;
    }

    // Hitung total harga dari semua item dalam keranjang
    let totalHarga = keranjang.reduce((total, item) => total + item.total, 0);
    
    let cekMember = false;
   // Jika checkbox member dicentang, terapkan diskon 30%
   if (req.body.isMember === 'on') {
    // Jika totalHarga belum mencapai syarat pembelian minimum, kembalikan response dengan alert
    if (totalHarga < 50000) {
        res.status(400).send('Pembelian belum memenuhi syarat untuk mendapatkan diskon. Minimal pembelian harus $50000.');
        return;
    }

    const diskon = 0.3; // 30% diskon untuk member
    totalHarga *= (1 - diskon); // Terapkan diskon

    cekMember = true;
    }


    // Jika totalHarga tidak diubah (tidak ada kode member), gunakan subtotal sebagai totalHarga
    const totalPembayaran = req.body.isMember === 'on' ? totalHarga : totalHarga;
    // Validasi pembayaran
    const inputCash = parseFloat(req.body.cash);

    console.log('Nilai inputCash:', inputCash);
    console.log('Total harga belanja:', totalPembayaran);

    if (isNaN(inputCash) || inputCash < totalPembayaran) {
        console.error('Jumlah uang yang dibayarkan tidak valid. Input Cash:', inputCash, ', Total Harga:', totalPembayaran);
        res.status(400).send('Jumlah uang yang dibayarkan tidak valid');
        return;
    }

    // Hitung kembalian
    const kembalian = inputCash - totalPembayaran;
    const totalToSave = req.body.isMember === 'on' ? totalPembayaran : totalPembayaran;

    // Data yang akan dimasukkan ke dalam tabel transaksi
    const values = keranjang.map(item => [
        item.tgl,
        item.kode_penjualan,
        item.kasir,
        item.kode_barang,
        item.nama_barang,
        item.qty,
        item.harga,
        totalToSave
    ]);

    // Penyimpanan data transaksi ke database
    const insertQuery = 'INSERT INTO transaksi (tgl, kode_transaksi, kasir, kode_barang, nama_barang, qty, harga, total) VALUES ?';
    conn.query(insertQuery, [values], (err, result) => {
        if (err) {
            console.error('Error saving transaction to database:', err);
            res.status(500).send('Internal Server Error');
            return;
        }
        console.log('Data transaksi berhasil disimpan ke database');

        // Setelah penyimpanan berhasil, cetak stuk transaksi
        const tanggalTransaksi = new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' });
        const kasir = req.session.username || 'Kasir Tidak Tersedia';

        // Mengambil informasi transaksi dari keranjang
        const transaksiInfo = keranjang.map(item => {
            return `${item.kode_penjualan} - ${item.nama_barang} (${item.qty}) - ${item.total} IDR`;
        }).join('\n');

        // Data untuk struk penjualan
        const strukData = {
            kodeTransaksi: keranjang[0].kode_penjualan,
            tanggalTransaksi: tanggalTransaksi,
            kasir: kasir,
            transaksiInfo: transaksiInfo,
            totalBayar: totalHarga, // totalHarga digunakan untuk menampilkan total sebelum diskon
            pembayaran: inputCash,
            kembalian: kembalian
        };

        // Mengosongkan keranjang setelah transaksi berhasil disimpan
        req.session.keranjang = [];

        // Render halaman struk penjualan
        res.render('strukPenjualan', { data: strukData,  cekMember: cekMember });
    });
});

//Rute untuk menghapus data keranjang
app.post('/keranjang/delete/:kode_barang', (req, res) => {
        const kode_barang = req.params.kode_barang;

        const index = req.session.keranjang.findIndex(item => item.kode_barang === kode_barang);    

        if (index !== -1) {
            req.session.keranjang.splice(index, 1);
            console.log('Item berhasil dihapus dari keranjang');
            res.sendStatus(200);
    } else {
        console.log('Item tidak ditemukan dalam keranjang');
        res.sendStatus(404);
    }
});

//Rute halaman data member
app.get('/member', (req, res) => {  
    if (req.session.role === 'kasir') {
        const sql = 'SELECT kode_member, nama, telepon, alamat FROM member';
        conn.query(sql, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
        console.log('Berhasil berada di halaman data member');
        res.render('member', { title: 'Data Member',  member: results });
    });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
  });

// Rute untuk menambah data member
app.post('/member/add', (req, res) => {
    if (req.session.role === 'kasir') {
        const { kode_member, nama, telepon, alamat } = req.body;


        // Pastikan semua data member yang diperlukan tersedia
        if (!kode_member || !nama || !telepon || !alamat) {
            return res.status(400).send('Bad Request');
        }
        // Query untuk menambahkan data member ke database
        const sql = 'INSERT INTO member (kode_member, nama, telepon, alamat) VALUES (?, ?, ?, ?)';
        const values = [kode_member, nama, telepon, alamat];

        conn.query(sql, values, (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            console.log('Data member berhasil ditambahkan:', results);
            res.redirect('/member');
        });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
});

// Rute untuk melakukan update member
app.post('/member/update/:kode_member', (req, res) => {
    if (req.session.role === 'kasir') {
        const kode_member = req.params.kode_member;
        const { nama, telepon, alamat } = req.body;

        // Lakukan update data member ke dalam database
        const sql = 'UPDATE member SET nama = ?, telepon = ?, alamat = ? WHERE kode_member = ?';
        conn.query(sql, [nama, telepon, alamat, kode_member], (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            // Jika pengguna dengan kode_member yang diberikan tidak ditemukan
            if (results.affectedRows === 0) {
                res.status(404).send('Member tidak ditemukan.');
                return;
            }
            // Redirect kembali ke halaman member setelah member berhasil diupdate
            res.redirect('/member');
        });
    } else {
        // Jika bukan admin
        res.status(403).send('Forbidden');
    }
});

//Rute untuk menghapus data member
app.post('/member/delete/:kode_member', (req, res) => {
    if (req.session.role === 'kasir') {
        const kode_member = req.params.kode_member;

        const sql = 'DELETE from member WHERE kode_member = ?';
        conn.query(sql, [kode_member], (err, results) => {
            if (err) {
                console.error('Error querying database:', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            console.log('Data member berhasil dihapus:', results);
            // Redirect kembali ke halaman data kasir setelah menambahkan data kasir
            res.redirect('/member');
        });
    } else {
        res.status(403).send('Forbidden');
    }
});


app.use('/', (req, res)=>{
  res.status(404)
  res.send('page not found :404')
});
app.listen(port, () =>{
  console.log(`Example app listening on port ${port}`)
});