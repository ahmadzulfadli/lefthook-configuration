# Semgrep Custom Rules — Java/Spring Boot

A collection of Semgrep rules for detecting security vulnerabilities and code quality issues in Java/Spring Boot projects.

## Rules List

| File | Rule ID | Severity | Category |
|------|---------|----------|----------|
| `sql-injection.yaml` | `tainted-sql-injection` | ERROR | Security - SQL Injection |
| `sql-injection.yaml` | `spring-data-raw-native-query` | ERROR | Security - SQL Injection |
| `secrets.yaml` | `java-hardcoded-password` | ERROR | Security - Hardcoded Credentials |
| `secrets.yaml` | `spring-hardcoded-credential-properties` | WARNING | Security - Hardcoded Credentials |
| `code-quality.yaml` | `java-empty-catch-block` | WARNING | Code Quality |
| `code-quality.yaml` | `java-use-logger-not-sysout` | WARNING | Code Quality |

---

## 1. SQL Injection Rules (`sql-injection.yaml`)

### 1.1 `tainted-sql-injection`

Uses **taint analysis** to track data flow from user input (Spring annotations) to SQL construction/execution sinks.

**CWE:** CWE-89 | **OWASP:** A03:2021 - Injection

#### ❌ Invalid (will be detected)

```java
// String concatenation with user input
@RestController
public class UserController {

    @GetMapping("/users")
    public List<User> getUsers(@RequestParam String name) {
        // ❌ DETECTED - string concat with SQL keyword
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.queryForList(query);
    }

    @PostMapping("/search")
    public List<User> search(@RequestBody SearchRequest request) {
        // ❌ DETECTED - String.format with user input
        String sql = String.format("SELECT * FROM users WHERE email = '%s'", request.getEmail());
        return entityManager.createNativeQuery(sql).getResultList();
    }

    @GetMapping("/user/{id}")
    public User getUser(@PathVariable String id) {
        // ❌ DETECTED - StringBuilder with user input
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE id = ");
        sb.append(id);
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(sb.toString());
    }

    @DeleteMapping("/user")
    public void deleteUser(@RequestParam String userId) {
        // ❌ DETECTED - += operator
        String sql = "DELETE FROM users WHERE id = ";
        sql += userId;
        jdbcTemplate.execute(sql);
    }

    @GetMapping("/filter")
    public List<User> filter(@RequestHeader String sortColumn) {
        // ❌ DETECTED - concat method
        String query = "SELECT * FROM users ORDER BY ".concat(sortColumn);
        return jdbcTemplate.queryForList(query);
    }

    @GetMapping("/cookie-search")
    public List<User> cookieSearch(@CookieValue String filter) {
        // ❌ DETECTED - user input from cookie to JPA query
        entityManager.createQuery("SELECT u FROM User u WHERE " + filter);
    }
}
```

#### ✅ Valid (will not be detected)

```java
@RestController
public class UserController {

    @GetMapping("/users")
    public List<User> getUsers(@RequestParam String name) {
        // ✅ SAFE - PreparedStatement with parameter binding
        PreparedStatement ps = connection.prepareStatement(
            "SELECT * FROM users WHERE name = ?"
        );
        ps.setString(1, name);
        return ps.executeQuery();
    }

    @PostMapping("/search")
    public List<User> search(@RequestBody SearchRequest request) {
        // ✅ SAFE - JPA parameter binding
        return entityManager
            .createQuery("SELECT u FROM User u WHERE u.email = :email")
            .setParameter("email", request.getEmail())
            .getResultList();
    }

    @GetMapping("/user/{id}")
    public User getUser(@PathVariable Long id) {
        // ✅ SAFE - Long type (safe type, automatically excluded)
        String query = "SELECT * FROM users WHERE id = " + id;
        return jdbcTemplate.queryForObject(query, User.class);
    }

    @GetMapping("/users/page")
    public List<User> getPage(@RequestParam Integer page) {
        // ✅ SAFE - Integer type (safe type)
        String sql = "SELECT * FROM users LIMIT " + page;
        return jdbcTemplate.queryForList(sql);
    }

    @GetMapping("/users/count")
    public void logCount(@RequestParam String table) {
        // ✅ SAFE - logging only, not SQL execution
        log.info("SELECT count from " + table);
    }

    @GetMapping("/users/safe")
    public List<User> safeSearch(@RequestParam String input) {
        // ✅ SAFE - sanitized via parseInt
        int id = Integer.parseInt(input);
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE id = " + id);
    }

    @GetMapping("/spring-data")
    public List<User> springData(@RequestParam String name) {
        // ✅ SAFE - Spring Data JPA repository method
        return userRepository.findByName(name);
    }
}
```

---

### 1.2 `spring-data-raw-native-query`

Detects string concatenation usage in `@Query` annotations with `nativeQuery = true`.

#### ❌ Invalid (will be detected)

```java
public interface UserRepository extends JpaRepository<User, Long> {

    // ❌ DETECTED - concatenation in @Query annotation
    @Query(value = "SELECT * FROM users WHERE name = " + "' " + name + " '", nativeQuery = true)
    List<User> findByName(String name);

    // ❌ DETECTED - variable concatenation
    String BASE_QUERY = "SELECT * FROM users ";
    @Query(value = BASE_QUERY + "WHERE status = 'active'", nativeQuery = true)
    List<User> findActive();
}
```

#### ✅ Valid (will not be detected)

```java
public interface UserRepository extends JpaRepository<User, Long> {

    // ✅ SAFE - named parameter
    @Query(value = "SELECT * FROM users WHERE name = :name", nativeQuery = true)
    List<User> findByName(@Param("name") String name);

    // ✅ SAFE - positional parameter
    @Query(value = "SELECT * FROM users WHERE id = ?1", nativeQuery = true)
    User findById(Long id);

    // ✅ SAFE - JPQL without nativeQuery (default)
    @Query("SELECT u FROM User u WHERE u.email = :email")
    User findByEmail(@Param("email") String email);

    // ✅ SAFE - static string without concatenation
    @Query(value = "SELECT * FROM users WHERE status = 'active'", nativeQuery = true)
    List<User> findActive();
}
```

---

## 2. Secrets Rules (`secrets.yaml`)

### 2.1 `java-hardcoded-password`

Detects credentials hardcoded directly in Java variables.

**CWE:** CWE-798 | **OWASP:** A07:2021

#### ❌ Invalid (will be detected)

```java
public class DatabaseConfig {

    // ❌ DETECTED - hardcoded password
    private String password = "MyS3cretP@ss!";

    // ❌ DETECTED - hardcoded API key
    private static final String API_KEY = "sk-1234567890abcdef";

    // ❌ DETECTED - hardcoded token
    String authToken = "eyJhbGciOiJIUzI1NiJ9.xxxxx";

    // ❌ DETECTED - hardcoded secret
    private String clientSecret = "my-oauth-secret-value";

    // ❌ DETECTED - private key
    private static final String PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQE...";

    // ❌ DETECTED - access key
    String accessKey = "AKIAIOSFODNN7EXAMPLE";
}
```

#### ✅ Valid (will not be detected)

```java
public class DatabaseConfig {

    // ✅ SAFE - using environment variable via Spring
    @Value("${db.password}")
    private String password;

    // ✅ SAFE - Spring expression placeholder
    private String apiKey = "${API_KEY}";

    // ✅ SAFE - empty string (default)
    private String secret = "";

    // ✅ SAFE - placeholder value
    private String password = "changeme";

    // ✅ SAFE - variable name does not contain sensitive keyword
    private String databaseUrl = "jdbc:postgresql://localhost:5432/mydb";

    // ✅ SAFE - read from environment
    private String token = System.getenv("AUTH_TOKEN");

    // ✅ SAFE - read from AWS Secrets Manager / Vault
    private String secret = secretsManager.getSecretValue("my-secret");
}
```

---

### 2.2 `spring-hardcoded-credential-properties`

Detects credentials hardcoded in `.properties` or `.yml/.yaml` files.

#### ❌ Invalid (will be detected)

```properties
# application.properties

# ❌ DETECTED - hardcoded password
spring.datasource.password=MyS3cretP@ss
spring.mail.password=email-password-123

# ❌ DETECTED - hardcoded API key
app.api-key=sk-1234567890abcdef
stripe.secret=sk_live_xxxxxxxxxxxxx

# ❌ DETECTED - hardcoded token
jwt.token=my-jwt-secret-token
```

```yaml
# application.yml

# ❌ DETECTED
spring:
  datasource:
    password: MyS3cretP@ss
  security:
    oauth2:
      client:
        registration:
          google:
            client-secret: my-google-secret
```

#### ✅ Valid (will not be detected)

```properties
# application.properties

# ✅ SAFE - environment variable reference
spring.datasource.password=${DB_PASSWORD}
app.api-key=${API_KEY}
jwt.secret=${JWT_SECRET}

# ✅ SAFE - not a credential field
spring.datasource.url=jdbc:postgresql://localhost:5432/mydb
server.port=8080
spring.application.name=my-app
```

```yaml
# application.yml

# ✅ SAFE - environment variable
spring:
  datasource:
    password: ${DB_PASSWORD}
  security:
    oauth2:
      client:
        registration:
          google:
            client-secret: ${GOOGLE_CLIENT_SECRET}
```

---

## 3. Code Quality Rules (`code-quality.yaml`)

### 3.1 `java-empty-catch-block`

Detects empty `catch` blocks (silent failures).

**CWE:** CWE-390

#### ❌ Invalid (will be detected)

```java
public class UserService {

    public User getUser(Long id) {
        try {
            return userRepository.findById(id).orElseThrow();
        } catch (Exception e) {
            // ❌ DETECTED - empty catch block, exception ignored
        }
        return null;
    }

    public void processPayment(Payment payment) {
        try {
            paymentGateway.charge(payment);
        } catch (PaymentException e) {
            // ❌ DETECTED - silent failure, no handling
        }
    }
}
```

#### ✅ Valid (will not be detected)

```java
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    public User getUser(Long id) {
        try {
            return userRepository.findById(id).orElseThrow();
        } catch (Exception e) {
            // ✅ SAFE - exception is logged
            log.error("Failed to get user: {}", id, e);
            throw new ServiceException("User not found", e);
        }
    }

    public void processPayment(Payment payment) {
        try {
            paymentGateway.charge(payment);
        } catch (PaymentException e) {
            // ✅ SAFE - has handling logic
            log.warn("Payment failed for order {}", payment.getOrderId(), e);
            notificationService.notifyPaymentFailure(payment);
        }
    }

    public Optional<Config> loadOptionalConfig() {
        try {
            return Optional.of(configLoader.load());
        } catch (ConfigNotFoundException e) {
            // ✅ SAFE - has comment/logic explaining why it's ignored
            log.debug("Optional config not found, using defaults");
            return Optional.empty();
        }
    }
}
```

---

### 3.2 `java-use-logger-not-sysout`

Detects usage of `System.out.println()`, `System.err.println()`, and `printStackTrace()` which should be replaced with SLF4J/Logback logger.

#### ❌ Invalid (will be detected)

```java
public class OrderService {

    public void processOrder(Order order) {
        // ❌ DETECTED - System.out.println
        System.out.println("Processing order: " + order.getId());

        try {
            orderRepository.save(order);
        } catch (Exception e) {
            // ❌ DETECTED - System.err.println
            System.err.println("Failed to save order!");

            // ❌ DETECTED - printStackTrace
            e.printStackTrace();
        }
    }

    public void debugInfo(String message) {
        // ❌ DETECTED
        System.out.println("[DEBUG] " + message);
    }
}
```

#### ✅ Valid (will not be detected)

```java
@Slf4j
public class OrderService {

    public void processOrder(Order order) {
        // ✅ SAFE - using SLF4J logger
        log.info("Processing order: {}", order.getId());

        try {
            orderRepository.save(order);
        } catch (Exception e) {
            // ✅ SAFE - logger with exception
            log.error("Failed to save order: {}", order.getId(), e);
        }
    }

    public void debugInfo(String message) {
        // ✅ SAFE - proper debug level
        log.debug("{}", message);
    }

    public void warnRetry(int attempt) {
        // ✅ SAFE - proper warn level
        log.warn("Retry attempt {} of 3", attempt);
    }
}
```

---

## How to Run

### All rules at once:

```bash
semgrep --config lefthook/semgrep/rules/ .
```

### Specific rule:

```bash
semgrep --config lefthook/semgrep/rules/sql-injection.yaml .
semgrep --config lefthook/semgrep/rules/secrets.yaml .
semgrep --config lefthook/semgrep/rules/code-quality.yaml .
```

### With Lefthook (pre-commit):

```bash
lefthook run pre-commit
```

---

## References

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Semgrep Taint Mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-798: Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-390: Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
