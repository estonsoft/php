<?php
require_once 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");


if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}



//******* Database Connection *******//
$host = '127.0.0.1';
$user = 'root';
$pass = '';  // empty password for XAMPP/WAMP
$dbname = 'estonsoftdb';

$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode([
        "error" => "Database connection failed",
        "details" => $conn->connect_error
    ]);
    exit;
}

//JWT secret and helper functions
$jwt_secret = "your-very-secure-secret";

// Generate JWT
function create_jwt($payload, $secret) {
// Use current time for issued at and expiration
    $issuedAt   = time();
    $expire     = $issuedAt + 604800; // token valid for 1 week
    $payload['iat'] = $issuedAt;
    $payload['exp'] = $expire;
// Remove password_hash from final token payload for security
    unset($payload['password_hash']);
    return JWT::encode($payload, $secret, 'HS256');
}

// Verify JWT
function verify_jwt($token, $secret) {
    try {
        return (array) JWT::decode($token, new Key($secret, 'HS256'));
    } catch (Exception $e) {
        return null;
    }
}


// ---- Helper functions ----
function getInput()
{
    $data = json_decode(file_get_contents("php://input"), true);
    return is_array($data) ? $data : [];
}

function getUserById($conn, $id)
{
    $stmt = $conn->prepare("SELECT id, name, email, permissions FROM users WHERE id = ?");
    $stmt->bind_param("s", $id);
    if (!$stmt->execute()) return null;
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    if ($user && isset($user['permissions'])) {
        $user['permissions'] = json_decode($user['permissions'], true);
    }
    return $user;
}

function getBlogById($conn, $id)
{
    $stmt = $conn->prepare("SELECT id, title, image, paragraph, content, authorName, authorImage, authorDesignation, tags, publishDate FROM blogs WHERE id = ?");
    $stmt->bind_param("s", $id);
    if (!$stmt->execute()) return null;
    $result = $stmt->get_result();
    $blog = $result->fetch_assoc();
    if ($blog && isset($blog['tags'])) {
        $blog['tags'] = json_decode($blog['tags'], true);
    }
    return $blog;
}

function getPortfolioById($conn, $id)
{
    $stmt = $conn->prepare("SELECT id, title, description, image, link, user_id FROM portfolios WHERE id = ?");
    $stmt->bind_param("s", $id);
    if (!$stmt->execute()) return null;
    $result = $stmt->get_result();
    $portfolio = $result->fetch_assoc();
    return $portfolio;
}

function getTestimonialById($conn, $id)
{
    $stmt = $conn->prepare("SELECT id, star, name, image, content, designation, user_id FROM testimonials WHERE id = ?");
    $stmt->bind_param("s", $id);
    if (!$stmt->execute()) return null;
    $result = $stmt->get_result();
    $testimonial = $result->fetch_assoc();
    return $testimonial;
}

function authenticate($required_permission = null) {
    global $jwt_secret, $conn;
    
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "Missing Authorization header"]);
        exit;
    }

    $token = str_replace("Bearer ", "", $headers['Authorization']);
    $auth_user = verify_jwt($token, $jwt_secret);

    if (!$auth_user) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
        exit;
    }

    $user = getUserById($conn, $auth_user["_id"]);
    if (!$user) {
        http_response_code(404);
        echo json_encode(["error" => "User not found"]);
        exit;
    }

    if ($required_permission && !in_array($required_permission, $user['permissions'])) {
        http_response_code(403);
        echo json_encode(["error" => "Permission denied: You cannot " . $required_permission]);
        exit;
    }

    return $user;
}

function initializeAdmin($conn) {
    $adminEmail = "admin@estonsoft.com";
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $adminEmail);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        $adminId = bin2hex(random_bytes(8));
        $adminPassword = password_hash("admin123", PASSWORD_BCRYPT);
        $adminPermissions = json_encode(["create_user", "view_users", "update_user", "delete_user", "create_blog", "update_blog", "delete_blog", "view_blogs"]);
        
        $insertStmt = $conn->prepare("INSERT INTO users (id, name, email, password, permissions) VALUES (?, ?, ?, ?, ?)");
        $adminName = "Admin User";
        $insertStmt->bind_param("sssss", $adminId, $adminName, $adminEmail, $adminPassword, $adminPermissions);
        $insertStmt->execute();
    }
}

// Parse resource from URL (e.g. /users or /blogs , /portfolios)

$requestUri = $_SERVER['REQUEST_URI'];
$scriptName = $_SERVER['SCRIPT_NAME'];

// remove query string (?id=...)
$path = parse_url($requestUri, PHP_URL_PATH);

$path = str_replace($scriptName, '', $path);
$path = trim($path, '/');
$segments = explode('/', $path);

$resource = isset($segments[0]) && $segments[0] !== '' ? $segments[0] : 'users'; // default to users


$method = $_SERVER['REQUEST_METHOD'];


if ($resource === 'auth' && $method === 'POST' && isset($segments[1]) && $segments[1] === 'login') {
    $data = getInput();
    if (empty($data['email']) || empty($data['password'])) {
        http_response_code(400);
        echo json_encode(["error" => "Email and password required"]);
        exit;
    }

    // Check user in DB
    $stmt = $conn->prepare("SELECT id, name, email, password, permissions FROM users WHERE email = ?");
    $stmt->bind_param("s", $data['email']);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if (!$user || !password_verify($data['password'], $user['password'])) {
        http_response_code(400);
        echo json_encode(["error" => "Invalid email or password"]);
        exit;
    }

    // Generate JWT
    $token = create_jwt([
        "_id" => $user['id'],
        "email" => $user['email'],
        "password_hash" => $user['password']
    ], $jwt_secret);

    echo json_encode(["token" => $token, "message" => "✅ Login successful", "timestamp" => time()]);
    exit;
} 

elseif ($resource === 'auth' && $method === 'GET' && isset($segments[1]) && $segments[1] === 'me') {
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "Missing Authorization header"]);
        exit;
    }

    $token = str_replace("Bearer ", "", $headers['Authorization']);
    $auth_user = verify_jwt($token, $jwt_secret);

    if (!$auth_user) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
        exit;
    }

    // Fetch user data
    $user = getUserById($conn, $auth_user["_id"]);
    if (!$user) {
        http_response_code(404);
        echo json_encode(["error" => "User not found"]);
        exit;
    }

    echo json_encode($user);
    exit;
}

elseif ($resource === 'users') {

    // Normalize segments (remove empty, trim)
    $segments = array_values(array_filter(array_map('trim', explode('/', $path))));

    switch ($method) {

        // GET /users or GET /users/{id}
        case 'GET':
            $auth_user = authenticate("view_users");
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if ($id) {
                $user = getUserById($conn, $id);
                if ($user) {
                    echo json_encode($user);
                } else {
                    http_response_code(404);
                    echo json_encode(["error" => "❌ User not found"]);
                }
            } else {
                $result = $conn->query("SELECT id, name, email, permissions FROM users");
                $users = [];
                while ($row = $result->fetch_assoc()) {
                    if (isset($row['permissions'])) {
                        $row['permissions'] = json_decode($row['permissions'], true);
                    }
                    $users[] = $row;
                }
                echo json_encode($users);
            }
            break;

        // POST /users
        case 'POST':
            $auth_user = authenticate("create_user");
            $data = getInput();

            if (empty($data['name']) || empty($data['email']) || empty($data['password'])) {
                http_response_code(400);
                echo json_encode(["error" => "Missing name, email, or password"]);
                exit;
            }

            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->bind_param("s", $data['email']);
            $stmt->execute();
            if ($stmt->get_result()->num_rows > 0) {
                http_response_code(400);
                echo json_encode(["error" => "❌ Email already registered"]);
                exit;
            }

            $permissions = isset($data['permissions']) && is_array($data['permissions']) ? json_encode($data['permissions']) : json_encode([]);
            $userId = bin2hex(random_bytes(8));
            $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);

            $stmt = $conn->prepare("INSERT INTO users (id, name, email, password, permissions) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $userId, $data['name'], $data['email'], $hashedPassword, $permissions);

            if ($stmt->execute()) {
                echo json_encode([
                    "id" => $userId,
                    "name" => $data['name'],
                    "email" => $data['email'],
                    "permissions" => json_decode($permissions, true)
                ]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Insert failed", "details" => $stmt->error]);
            }
            break;

         // PUT /users/{id} or
        // PUT /users?id={id}
        case 'PUT':
            $auth_user = authenticate("update_user");
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if (!$id) {
                http_response_code(400);
                echo json_encode(["error" => "Missing ID"]);
                exit;
            }

            $data = getInput();

            if (empty($data['name']) || empty($data['email'])) {
                http_response_code(400);
                echo json_encode(["error" => "Missing name or email"]);
                exit;
            }

            $permissions = isset($data['permissions']) && is_array($data['permissions']) ? json_encode($data['permissions']) : json_encode([]);
            $stmt = $conn->prepare("UPDATE users SET name = ?, email = ?, permissions = ? WHERE id = ?");
            $stmt->bind_param("ssss", $data['name'], $data['email'], $permissions, $id);

            if ($stmt->execute()) {
                $user = getUserById($conn, $id);
                if ($user) {
                    echo json_encode($user);
                } else {
                    http_response_code(404);
                    echo json_encode(["error" => "❌ User not found"]);
                }
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Update failed", "details" => $stmt->error]);
            }
            break;

        // DELETE /users/{id} or /users?id={id}
        case 'DELETE':
            $auth_user = authenticate("delete_user");
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if (!$id) {
                http_response_code(400);
                echo json_encode(["error" => "Missing ID"]);
                exit;
            }

            $user = getUserById($conn, $id);
            if (!$user) {
                http_response_code(404);
                echo json_encode(["error" => "❌ User not found"]);
                exit;
            }

            $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
            $stmt->bind_param("s", $id);

            if ($stmt->execute()) {
                echo json_encode($user);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Delete failed", "details" => $stmt->error]);
            }
            break;

        default:
            http_response_code(405);
            echo json_encode(["error" => "Method not allowed"]);
    }
}

elseif ($resource === 'blogs') {
    $segments = array_values(array_filter(array_map('trim', explode('/', $path))));
    
    switch ($method) {
        case 'GET':
            $auth_user = authenticate();
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if ($id) {
                $blog = getBlogById($conn, $id);
                if ($blog) {
                    echo json_encode($blog);
                } else {
                    http_response_code(404);
                    echo json_encode(["error" => "Blog not found"]);
                }
            } else {
                $result = $conn->query("SELECT id, title, image, paragraph, content, authorName, authorImage, authorDesignation, tags, publishDate FROM blogs");
                $blogs = [];
                while ($row = $result->fetch_assoc()) {
                    if (isset($row['tags'])) {
                        $row['tags'] = json_decode($row['tags'], true);
                    }
                    $blogs[] = $row;
                }
                echo json_encode($blogs);
            }
            break;

        case 'POST':
            $auth_user = authenticate();
            $data = getInput();

            $required_fields = ['title', 'image', 'paragraph', 'content', 'authorName', 'authorImage', 'authorDesignation', 'tags', 'publishDate'];
            foreach ($required_fields as $field) {
                if (empty($data[$field])) {
                    http_response_code(400);
                    echo json_encode(["error" => "Missing field: " . $field]);
                    exit;
                }
            }

            $blogId = bin2hex(random_bytes(8));
            $tags = is_array($data['tags']) ? json_encode($data['tags']) : json_encode([]);
            
            $stmt = $conn->prepare("INSERT INTO blogs (id, title, image, paragraph, content, authorName, authorImage, authorDesignation, tags, publishDate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssssssss", $blogId, $data['title'], $data['image'], $data['paragraph'], $data['content'], $data['authorName'], $data['authorImage'], $data['authorDesignation'], $tags, $data['publishDate']);

            if ($stmt->execute()) {
                echo json_encode(["message" => "Blog created successfully", "id" => $blogId]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Insert failed", "details" => $stmt->error]);
            }
            break;

        case 'PUT':
            $auth_user = authenticate();
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if (!$id) {
                http_response_code(400);
                echo json_encode(["error" => "Missing ID"]);
                exit;
            }

            $data = getInput();
            $required_fields = ['title', 'image', 'paragraph', 'content', 'authorName', 'authorImage', 'authorDesignation', 'tags', 'publishDate'];
            foreach ($required_fields as $field) {
                if (empty($data[$field])) {
                    http_response_code(400);
                    echo json_encode(["error" => "Missing field: " . $field]);
                    exit;
                }
            }

            $tags = is_array($data['tags']) ? json_encode($data['tags']) : json_encode([]);
            
            $stmt = $conn->prepare("UPDATE blogs SET title = ?, image = ?, paragraph = ?, content = ?, authorName = ?, authorImage = ?, authorDesignation = ?, tags = ?, publishDate = ? WHERE id = ?");
            $stmt->bind_param("ssssssssss", $data['title'], $data['image'], $data['paragraph'], $data['content'], $data['authorName'], $data['authorImage'], $data['authorDesignation'], $tags, $data['publishDate'], $id);

            if ($stmt->execute()) {
                echo json_encode(["message" => "Blog updated successfully"]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Update failed", "details" => $stmt->error]);
            }
            break;

        case 'DELETE':
            $auth_user = authenticate();
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if (!$id) {
                http_response_code(400);
                echo json_encode(["error" => "Missing ID"]);
                exit;
            }

            $blog = getBlogById($conn, $id);
            if (!$blog) {
                http_response_code(404);
                echo json_encode(["error" => "Blog not found"]);
                exit;
            }

            $stmt = $conn->prepare("DELETE FROM blogs WHERE id = ?");
            $stmt->bind_param("s", $id);

            if ($stmt->execute()) {
                echo json_encode(["message" => "Blog deleted successfully"]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Delete failed", "details" => $stmt->error]);
            }
            break;

        default:
            http_response_code(405);
            echo json_encode(["error" => "Method not allowed"]);
    }
} elseif ($resource === 'portfolios') {
    $segments = array_values(array_filter(array_map('trim', explode('/', $path))));
    
    switch ($method) {
        case 'GET':
            $auth_user = authenticate();
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if ($id) {
                $portfolio = getPortfolioById($conn, $id);
                if ($portfolio) {
                    echo json_encode($portfolio);
                } else {
                    http_response_code(404);
                    echo json_encode(["error" => "Portfolio not found"]);
                }
            } else {
                $result = $conn->query("SELECT id, title, description, image, link, user_id FROM portfolios");
                $portfolios = [];
                while ($row = $result->fetch_assoc()) {
                    $portfolios[] = $row;
                }
                echo json_encode($portfolios);
            }
            break;

        case 'POST':
            $auth_user = authenticate();
            $data = getInput();

            $required_fields = ['title', 'description', 'image', 'link'];
            foreach ($required_fields as $field) {
                if (empty($data[$field])) {
                    http_response_code(400);
                    echo json_encode(["error" => "Missing field: " . $field]);
                    exit;
                }
            }

            $portfolioId = bin2hex(random_bytes(8));
            $userId = isset($data['user_id']) ? $data['user_id'] : $auth_user['id'];
            
            $stmt = $conn->prepare("INSERT INTO portfolios (id, title, description, image, link, user_id) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssss", $portfolioId, $data['title'], $data['description'], $data['image'], $data['link'], $userId);

            if ($stmt->execute()) {
                echo json_encode(["message" => "Portfolio created successfully", "id" => $portfolioId]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Insert failed", "details" => $stmt->error]);
            }
            break;

        case 'PUT':
            $auth_user = authenticate();
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if (!$id) {
                http_response_code(400);
                echo json_encode(["error" => "Missing ID"]);
                exit;
            }

            $data = getInput();
            $required_fields = ['title', 'description', 'image', 'link'];
            foreach ($required_fields as $field) {
                if (empty($data[$field])) {
                    http_response_code(400);
                    echo json_encode(["error" => "Missing field: " . $field]);
                    exit;
                }
            }

            $userId = isset($data['user_id']) ? $data['user_id'] : $auth_user['id'];
            
            $stmt = $conn->prepare("UPDATE portfolios SET title = ?, description = ?, image = ?, link = ?, user_id = ? WHERE id = ?");
            $stmt->bind_param("ssssss", $data['title'], $data['description'], $data['image'], $data['link'], $userId, $id);

            if ($stmt->execute()) {
                echo json_encode(["message" => "Portfolio updated successfully"]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Update failed", "details" => $stmt->error]);
            }
            break;

        case 'DELETE':
            $auth_user = authenticate();
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if (!$id) {
                http_response_code(400);
                echo json_encode(["error" => "Missing ID"]);
                exit;
            }

            $portfolio = getPortfolioById($conn, $id);
            if (!$portfolio) {
                http_response_code(404);
                echo json_encode(["error" => "Portfolio not found"]);
                exit;
            }

            $stmt = $conn->prepare("DELETE FROM portfolios WHERE id = ?");
            $stmt->bind_param("s", $id);

            if ($stmt->execute()) {
                echo json_encode(["message" => "Portfolio deleted successfully"]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Delete failed", "details" => $stmt->error]);
            }
            break;

        default:
            http_response_code(405);
            echo json_encode(["error" => "Method not allowed"]);
    }
} elseif ($resource === 'testimonials') {
    $segments = array_values(array_filter(array_map('trim', explode('/', $path))));
    
    switch ($method) {
        case 'GET':
            $auth_user = authenticate();
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if ($id) {
                $testimonial = getTestimonialById($conn, $id);
                if ($testimonial) {
                    echo json_encode($testimonial);
                } else {
                    http_response_code(404);
                    echo json_encode(["error" => "Testimonial not found"]);
                }
            } else {
                $result = $conn->query("SELECT id, star, name, image, content, designation, user_id FROM testimonials");
                $testimonials = [];
                while ($row = $result->fetch_assoc()) {
                    $testimonials[] = $row;
                }
                echo json_encode($testimonials);
            }
            break;

        case 'POST':
            $auth_user = authenticate();
            $data = getInput();

            $required_fields = ['name', 'content'];
            foreach ($required_fields as $field) {
                if (empty($data[$field])) {
                    http_response_code(400);
                    echo json_encode(["error" => "Missing field: " . $field]);
                    exit;
                }
            }
            
            if (!isset($data['star']) || $data['star'] === '') {
                http_response_code(400);
                echo json_encode(["error" => "Missing field: star"]);
                exit;
            }

            if ($data['star'] < 1 || $data['star'] > 5) {
                http_response_code(400);
                echo json_encode(["error" => "Star rating must be between 1 and 5"]);
                exit;
            }

            $testimonialId = bin2hex(random_bytes(8));
            $userId = isset($data['user_id']) ? $data['user_id'] : $auth_user['id'];
            $image = isset($data['image']) ? $data['image'] : '';
            $designation = isset($data['designation']) ? $data['designation'] : '';
            
            $stmt = $conn->prepare("INSERT INTO testimonials (id, star, name, image, content, designation, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("sisssss", $testimonialId, $data['star'], $data['name'], $image, $data['content'], $designation, $userId);

            if ($stmt->execute()) {
                echo json_encode(["message" => "Testimonial created successfully", "id" => $testimonialId]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Insert failed", "details" => $stmt->error]);
            }
            break;

        case 'PUT':
            $auth_user = authenticate();
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if (!$id) {
                http_response_code(400);
                echo json_encode(["error" => "Missing ID"]);
                exit;
            }

            $data = getInput();
            $required_fields = ['name', 'content'];
            foreach ($required_fields as $field) {
                if (empty($data[$field])) {
                    http_response_code(400);
                    echo json_encode(["error" => "Missing field: " . $field]);
                    exit;
                }
            }
            
            if (!isset($data['star']) || $data['star'] === '') {
                http_response_code(400);
                echo json_encode(["error" => "Missing field: star"]);
                exit;
            }

            if ($data['star'] < 1 || $data['star'] > 5) {
                http_response_code(400);
                echo json_encode(["error" => "Star rating must be between 1 and 5"]);
                exit;
            }

            $userId = isset($data['user_id']) ? $data['user_id'] : $auth_user['id'];
            $image = isset($data['image']) ? $data['image'] : '';
            $designation = isset($data['designation']) ? $data['designation'] : '';
            
            $stmt = $conn->prepare("UPDATE testimonials SET star = ?, name = ?, image = ?, content = ?, designation = ?, user_id = ? WHERE id = ?");
            $stmt->bind_param("issssss", $data['star'], $data['name'], $image, $data['content'], $designation, $userId, $id);

            if ($stmt->execute()) {
                echo json_encode(["message" => "Testimonial updated successfully"]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Update failed", "details" => $stmt->error]);
            }
            break;

        case 'DELETE':
            $auth_user = authenticate();
            $id = null;

            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
            } elseif (!empty($segments[1])) {
                $id = $segments[1];
            }

            if (!$id) {
                http_response_code(400);
                echo json_encode(["error" => "Missing ID"]);
                exit;
            }

            $testimonial = getTestimonialById($conn, $id);
            if (!$testimonial) {
                http_response_code(404);
                echo json_encode(["error" => "Testimonial not found"]);
                exit;
            }

            $stmt = $conn->prepare("DELETE FROM testimonials WHERE id = ?");
            $stmt->bind_param("s", $id);

            if ($stmt->execute()) {
                echo json_encode(["message" => "Testimonial deleted successfully"]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Delete failed", "details" => $stmt->error]);
            }
            break;

        default:
            http_response_code(405);
            echo json_encode(["error" => "Method not allowed"]);
    }
} elseif ($resource === 'healthcheck' || $resource === 'health') {
    if ($method === 'GET') {
        echo json_encode(["status" => "healthy", "message" => "API is running"]);
    } else {
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed"]);
    }
}

else {
    http_response_code(404);
    echo json_encode(["error" => "Resource not found"]);
}
initializeAdmin($conn);
$conn->close();
