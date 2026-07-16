# Semgrep Rules — Java/Spring Boot

Rules for detecting security vulnerabilities and code quality issues in Java/Spring Boot projects.

## Rules

| File | Rule ID | Severity | Category |
|------|---------|----------|----------|
| `sql-injection.yaml` | `tainted-sql-injection` | ERROR | Security |
| `sql-injection.yaml` | `spring-data-raw-native-query` | ERROR | Security |
| `secrets.yaml` | `java-hardcoded-password` | ERROR | Security |
| `secrets.yaml` | `spring-hardcoded-credential-properties` | WARNING | Security |
| `code-quality.yaml` | `java-empty-catch-block` | WARNING | Code Quality |
| `code-quality.yaml` | `java-use-logger-not-sysout` | WARNING | Code Quality |

---

## 1. SQL Injection Rules (`sql-injection.yaml`)

### 1.1 `tainted-sql-injection`

Uses **taint analysis** to track data flow from user input (Spring annotations) to SQL construction/execution sinks.

**CWE:** CWE-89 | **OWASP:** A03:2021 - Injection

**Sources:** `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`

**Sinks:** String concatenation → JDBC Statement, EntityManager, JdbcTemplate

####  Invalid (will be detected)

```java
@RestController
public class UserController {

    @GetMapping("/users")
    public List<User> getUsers(@RequestParam String name) {
        //  DETECTED - string concat with SQL keyword
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.queryForList(query);
    }

    @PostMapping("/search")
    public List<User> search(@RequestBody SearchRequest request) {
        //  DETECTED - String.format with user input
        String sql = String.format("SELECT * FROM users WHERE email = '%s'", request.getEmail());
        return entityManager.createNativeQuery(sql).getResultList();
    }

    @GetMapping("/user/{id}")
    public User getUser(@PathVariable String id) {
        //  DETECTED - StringBuilder with user input
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = ");
        sb.append(id);
        return stmt.executeQuery(sb.toString());
    }

    @DeleteMapping("/user")
    public void deleteUser(@RequestParam String userId) {
        //  DETECTED - += operator
        String sql = "DELETE FROM users WHERE id = ";
        sql += userId;
        jdbcTemplate.execute(sql);
    }
}
```

####  Valid (will not be detected)

```java
@RestController
public class UserController {

    @GetMapping("/users")
    public List<User> getUsers(@RequestParam String name) {
        //  SAFE - PreparedStatement with parameter binding
        PreparedStatement ps = connection.prepareStatement(
            "SELECT * FROM users WHERE name = ?"
        );
        ps.setString(1, name);
        return ps.executeQuery();
    }

    @PostMapping("/search")
    public List<User> search(@RequestBody SearchRequest request) {
        //  SAFE - JPA parameter binding
        return entityManager
            .createQuery("SELECT u FROM User u WHERE u.email = :email")
            .setParameter("email", request.getEmail())
            .getResultList();
    }

    @GetMapping("/user/{id}")
    public User getUser(@PathVariable Long id) {
        //  SAFE - Long type (safe type, automatically excluded)
        String query = "SELECT * FROM users WHERE id = " + id;
        return jdbcTemplate.queryForObject(query, User.class);
    }

    @GetMapping("/users/safe")
    public List<User> safeSearch(@RequestParam String input) {
        //  SAFE - sanitized via parseInt
        int id = Integer.parseInt(input);
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE id = " + id);
    }
}
```

---

### 1.2 `spring-data-raw-native-query`

Detects string concatenation in `@Query` annotations with `nativeQuery = true`.

####  Invalid

```java
public interface UserRepository extends JpaRepository<User, Long> {
    //  DETECTED - concatenation in @Query
    @Query(value = "SELECT * FROM users WHERE name = " + "'" + name + "'", nativeQuery = true)
    List<User> findByName(String name);
}
```

####  Valid

```java
public interface UserRepository extends JpaRepository<User, Long> {
    //  SAFE - named parameter
    @Query(value = "SELECT * FROM users WHERE name = :name", nativeQuery = true)
    List<User> findByName(@Param("name") String name);
}
```

---

## 2. Secrets Rules (`secrets.yaml`)

### 2.1 `java-hardcoded-password`

**CWE:** CWE-798 | **OWASP:** A07:2021

####  Invalid

```java
//  DETECTED
private String password = "MyS3cretP@ss!";
private static final String API_KEY = "sk-1234567890abcdef";
String authToken = "eyJhbGciOiJIUzI1NiJ9.xxxxx";
```

####  Valid

```java
//  SAFE - Spring placeholder
@Value("${db.password}")
private String password;

//  SAFE - empty string
private String secret = "";

//  SAFE - from environment
private String token = System.getenv("AUTH_TOKEN");
```

---

### 2.2 `spring-hardcoded-credential-properties`

Detects hardcoded credentials in `.properties` / `.yml` files.

####  Invalid

```properties
#  DETECTED
spring.datasource.password=MyS3cretP@ss
app.api-key=sk-1234567890abcdef
```

####  Valid

```properties
#  SAFE - environment variable
spring.datasource.password=${DB_PASSWORD}
app.api-key=${API_KEY}
```

---

## 3. Code Quality Rules (`code-quality.yaml`)

### 3.1 `java-empty-catch-block`

**CWE:** CWE-390

####  Invalid

```java
try {
    userRepository.findById(id).orElseThrow();
} catch (Exception e) {
    //  DETECTED - empty catch block
}
```

####  Valid

```java
try {
    userRepository.findById(id).orElseThrow();
} catch (Exception e) {
    //  SAFE - exception is logged
    log.error("Failed to get user: {}", id, e);
    throw new ServiceException("User not found", e);
}
```

---

### 3.2 `java-use-logger-not-sysout`

####  Invalid

```java
//  DETECTED
System.out.println("Processing order: " + order.getId());
System.err.println("Failed!");
e.printStackTrace();
```

####  Valid

```java
//  SAFE - SLF4J logger
log.info("Processing order: {}", order.getId());
log.error("Failed to process", e);
```

---

## How to Run

```bash
# All Java rules
semgrep --config semgrep/rules/java/ .

# Specific file
semgrep --config semgrep/rules/java/sql-injection.yaml .
```
