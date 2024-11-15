<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $servername = "localhost";
    $username_db = "root"; 
    $password_db = ""; 
    $dbname = "login"; 

    // Crear conexión
    $conn = new mysqli($servername, $username_db, $password_db, $dbname);

    // Comprobar conexión
    if ($conn->connect_error) {
        die("Conexión fallida: " . $conn->connect_error);
    }

    // Establecer la codificación a UTF-8
    $conn->set_charset("utf8mb4");

    // Obtener datos del formulario
    $username = $_POST['usuario'];
    $email = $_POST['email'];
    $password = $_POST['contraseña'];

    // Validar que el usuario no exista
    $stmt = $conn->prepare("SELECT * FROM usuario WHERE Usuario = ? OR email = ?");
    $stmt->bind_param("ss", $username, $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $_SESSION['error'] = "El nombre de usuario o el correo ya están en uso.";
        header("Location: Login.php");
        exit();
    } else {
        // Hashear la contraseña
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Insertar en la base de datos
        $stmt = $conn->prepare("INSERT INTO usuario (Usuario, email, Contraseña) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $hashed_password);

        if ($stmt->execute()) {
            $_SESSION['success'] = "Registro exitoso!";
            header("Location: index.html");
            exit();
        } else {
            $_SESSION['error'] = "Error al registrar: " . $stmt->error;
            header("Location: index.php");
            exit();
        }
    }

    $stmt->close();
    $conn->close();
}
?>
