# simple Argon2 usage

CASE: Authorization failed

```powershell
PS C:\programming_directory\rust_projects\practice\hashing> cargo run
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.02s
     Running `target\debug\hashing.exe`
Enter password: fate-grand-order
Hashed password: $argon2id$v=19$m=19456,t=2,p=1$/EFsMr7RGghRsqytnvP0lA$JNVgbtYoy/tK9zuRIOfGJ5RbudAIna4Ggq15JtaGQG4
Original password you entered: fate-grand-order
You are authorized: false
```

CASE: Authorization success

```powershell
PS C:\programming_directory\rust_projects\practice\hashing> cargo run
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.03s
     Running `target\debug\hashing.exe`
Enter password: password
Hashed password: $argon2id$v=19$m=19456,t=2,p=1$gkCd8O7cMy+lRPAtCPEwRQ$yUnFzyWXzXxwL7kDt5uMYkJQ1/jjzDGmVmfb494aBo0
Original password you entered: password
You are authorized: true
```

utilize Argon2 with your web app

example by Actix Web (extracted from a part of my acix project)

### dependencies

```toml
[dependecies]
actix-web = "4.9.0"
bb8 = "0.8.5"
bb8-postgres = "0.8.1"
tokio = { version = "1", features = ["full"] }
postgres = "0.19.8"
tokio-postgres = "0.7.11"
argon2 = "0.5.3"
rand_core = { version = "0.6.4", features = ["getrandom"] }
serde_json = "1.0.127"
log = "0.4.22"
```

### signup logic

```Rust
use actix_web::{
    HttpResponse,
    Responder, HttpRequest, web
};
use tokio_postgres::NoTls;
use bb8_postgres::{
    PostgresConnectionManager,
    bb8::Pool
};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SignupRequest {
    name: String,
    email: String,
    password: String,
}

pub async fn signup(
    req: web::Json<SignupRequest>,
    pool: web::Data<Pool<PostgresConnectionManager<NoTls>>>
) -> impl Responder {
    // database connection pool
    let conn = match pool.get().await {
        Ok(conn) => conn,
        Err(err) => {
            logger::log(logger::Header::ERROR, &err.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    // argon2 password hashing logic
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = argon2.hash_password(&req.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(err) => {
            logger::log(logger::Header::ERROR, &err.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    // insert hashed password as user info into the table `users`
    match conn.execute(
        "INSERT INTO users (name, password, email) VALUES ($1, $2, $3)",
        &[&req.name, &hashed_password, &req.email]
    ).await {
        Ok(row) => {
            logger::log(logger::Header::SUCCESS, "Successfully signed up")
            return HttpResponse::Ok().finish();
        },
        Err(err) => {
            logger::log(logger::Header::ERROR, &err.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    }
}
```
