const bcrypt = require('bcrypt');

bcrypt.hash('yourpassword', 10, (err, hash) => {
  console.log('Hashed password:', hash);
});


$2b$10$KIX/8K0vZQgLHgUfsMRWeuByv82TjhmqF.qQcTNVm/xCrj3VqG1a6
✅ Bcrypt-Hashed Password for 123456