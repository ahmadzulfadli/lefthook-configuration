# Semgrep Rules — Go

Rules for detecting security vulnerabilities and code quality issues in Go projects. Supports net/http, Gin, Echo, Fiber, gorilla/mux, chi, GORM, sqlx, and database/sql.

## Rules

| File | Rule ID | Severity | Category |
|------|---------|----------|----------|
| `sql-injection.yaml` | `go-tainted-sql-injection` | ERROR | Security |
| `sql-injection.yaml` | `go-sql-string-formatting` | ERROR | Security |
| `secrets.yaml` | `go-hardcoded-credential` | ERROR | Security |
| `secrets.yaml` | `go-hardcoded-credential-in-func` | ERROR | Security |
| `secrets.yaml` | `go-hardcoded-jwt-secret` | ERROR | Security |
| `code-quality.yaml` | `go-ignored-error` | WARNING | Code Quality |
| `code-quality.yaml` | `go-use-structured-logger` | WARNING | Code Quality |
| `code-quality.yaml` | `go-defer-in-loop` | WARNING | Code Quality |
| `code-quality.yaml` | `go-goroutine-without-recover` | WARNING | Code Quality |
| `code-quality.yaml` | `go-context-background-in-handler` | WARNING | Code Quality |

---

## 1. SQL Injection Rules (`sql-injection.yaml`)

### 1.1 `go-tainted-sql-injection`

Uses **taint analysis** to track data flow from HTTP request input to SQL execution sinks.

**CWE:** CWE-89 | **OWASP:** A03:2021 - Injection

**Supported frameworks (sources):**
- `net/http` — `r.URL.Query().Get()`, `r.FormValue()`, `r.Header.Get()`, `r.PathValue()`
- `Gin` — `c.Query()`, `c.Param()`, `c.PostForm()`, `c.GetHeader()`
- `Echo` — `c.QueryParam()`, `c.Param()`, `c.FormValue()`
- `Fiber` — `c.Query()`, `c.Params()`, `c.FormValue()`
- `gorilla/mux` — `mux.Vars(r)["key"]`
- `chi` — `chi.URLParam(r, "key")`

**Supported sinks:** `database/sql`, `sqlx`, `GORM`

####  Invalid (will be detected)

```go
// net/http — fmt.Sprintf for SQL
func GetUser(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    //  DETECTED
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    rows, _ := db.Query(query)
}

// Gin — string concatenation
func SearchUsers(c *gin.Context) {
    keyword := c.Query("keyword")
    //  DETECTED
    query := "SELECT * FROM users WHERE name LIKE '%" + keyword + "%'"
    db.Raw(query).Scan(&users)
}

// Echo — user input in Exec
func DeleteUser(c echo.Context) error {
    id := c.Param("id")
    //  DETECTED
    query := fmt.Sprintf("DELETE FROM users WHERE id = %s", id)
    db.Exec(query)
    return c.JSON(200, nil)
}
```

####  Valid (will not be detected)

```go
// Parameterized query
func GetUser(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    //  SAFE
    row := db.QueryRow("SELECT * FROM users WHERE name = $1", name)
}

// GORM parameter binding
func SearchUsers(c *gin.Context) {
    keyword := c.Query("keyword")
    //  SAFE
    db.Where("name LIKE ?", "%"+keyword+"%").Find(&users)
}

// Integer conversion as sanitizer
func GetUserByID(w http.ResponseWriter, r *http.Request) {
    idStr := r.URL.Query().Get("id")
    //  SAFE - strconv.Atoi is a sanitizer
    id, err := strconv.Atoi(idStr)
    if err != nil {
        http.Error(w, "invalid id", 400)
        return
    }
    db.QueryRow("SELECT * FROM users WHERE id = $1", id)
}
```

---

### 1.2 `go-sql-string-formatting`

Simple pattern detection for `fmt.Sprintf` used directly inside SQL function calls.

####  Invalid

```go
//  DETECTED
rows, _ := db.Query(fmt.Sprintf("SELECT * FROM %s WHERE id = %d", table, id))
db.Raw(fmt.Sprintf("SELECT * FROM users WHERE status = '%s'", status)).Scan(&users)
db.Where(fmt.Sprintf("name = '%s'", name)).Find(&users)
```

####  Valid

```go
//  SAFE
rows, _ := db.Query("SELECT * FROM users WHERE id = $1", id)
db.Raw("SELECT * FROM users WHERE status = ?", status).Scan(&users)
db.Where("name = ?", name).Find(&users)
```

---

## 2. Secrets Rules (`secrets.yaml`)

### 2.1 `go-hardcoded-credential`

**CWE:** CWE-798 | **OWASP:** A07:2021

####  Invalid

```go
//  DETECTED
var dbPassword = "MyS3cretP@ss!"
const apiKey = "sk-1234567890abcdef"
authToken := "eyJhbGciOiJIUzI1NiJ9.xxxxx"
```

####  Valid

```go
//  SAFE
dbPassword := os.Getenv("DB_PASSWORD")
var apiKey = ""
secret := viper.GetString("app.secret")
```

---

### 2.2 `go-hardcoded-credential-in-func`

Detects hardcoded connection strings in database/cache open functions.

####  Invalid

```go
//  DETECTED
db, _ := sql.Open("postgres", "host=localhost user=admin password=secret dbname=mydb")
db, _ := sqlx.Connect("mysql", "root:password@tcp(127.0.0.1:3306)/test")
rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", Password: "redis-pass"})
```

####  Valid

```go
//  SAFE
dsn := os.Getenv("DATABASE_URL")
db, _ := sql.Open("postgres", dsn)
rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", Password: ""})
```

---

### 2.3 `go-hardcoded-jwt-secret`

**CWE:** CWE-798, CWE-321 | **OWASP:** A02:2021

####  Invalid

```go
//  DETECTED
tokenString, _ := token.SignedString([]byte("my-super-secret-key"))
jwtSecret := []byte("hardcoded-signing-key-12345")
```

####  Valid

```go
//  SAFE
jwtSecret := []byte(os.Getenv("JWT_SECRET"))
tokenString, _ := token.SignedString(jwtSecret)
```

---

## 3. Code Quality Rules (`code-quality.yaml`)

### 3.1 `go-ignored-error`

**CWE:** CWE-390

####  Invalid

```go
//  DETECTED - error ignored with blank identifier
result, _ := db.Exec("INSERT INTO users ...")
data, _ := os.ReadFile("config.json")
resp, _ := http.Get("https://api.example.com/data")
```

####  Valid

```go
//  SAFE - error handled
result, err := db.Exec("INSERT INTO users ...")
if err != nil {
    return fmt.Errorf("insert user: %w", err)
}

//  SAFE - map lookup (excluded)
val, _ := myMap["key"]

//  SAFE - env lookup (excluded)
home, _ := os.LookupEnv("HOME")
```

---

### 3.2 `go-use-structured-logger`

####  Invalid

```go
func ProcessOrder(order *Order) error {
    //  DETECTED
    fmt.Println("Processing order:", order.ID)
    log.Printf("Order %s processed", order.ID)
    return nil
}
```

####  Valid

```go
//  SAFE - in main function
func main() {
    fmt.Println("Starting server...")
}

//  SAFE - structured logger
func ProcessOrder(order *Order) error {
    slog.Info("processing order", "order_id", order.ID)
    return nil
}
```

---

### 3.3 `go-defer-in-loop`

**CWE:** CWE-404

####  Invalid

```go
func ProcessFiles(paths []string) error {
    for _, path := range paths {
        f, _ := os.Open(path)
        //  DETECTED - defer won't execute until function returns
        defer f.Close()
    }
    return nil
}
```

####  Valid

```go
func ProcessFiles(paths []string) error {
    for _, path := range paths {
        if err := processFile(path); err != nil {
            return err
        }
    }
    return nil
}

func processFile(path string) error {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    defer f.Close() //  SAFE - outside loop
    return nil
}
```

---

### 3.4 `go-goroutine-without-recover`

**CWE:** CWE-248

####  Invalid

```go
//  DETECTED - no recover, panic crashes entire program
go func() {
    processJob(job)
}()
```

####  Valid

```go
//  SAFE - has recover
go func() {
    defer func() {
        if r := recover(); r != nil {
            log.Error().Interface("panic", r).Msg("worker recovered")
        }
    }()
    processJob(job)
}()
```

---

### 3.5 `go-context-background-in-handler`

####  Invalid

```go
func GetUser(w http.ResponseWriter, r *http.Request) {
    //  DETECTED - should use r.Context()
    ctx := context.Background()
    user, _ := userService.FindByID(ctx, id)
}
```

####  Valid

```go
func GetUser(w http.ResponseWriter, r *http.Request) {
    //  SAFE - uses request context
    ctx := r.Context()
    user, _ := userService.FindByID(ctx, id)
}
```

---

## How to Run

```bash
# All Go rules
semgrep --config semgrep/rules/go/ .

# Specific file
semgrep --config semgrep/rules/go/sql-injection.yaml .
semgrep --config semgrep/rules/go/secrets.yaml .
semgrep --config semgrep/rules/go/code-quality.yaml .
```
