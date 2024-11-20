<?php

// Connexion à la base de données
$host = 'localhost';
$dbname = 'csrfFaille';
$user = 'login4671';
$password = 'yOvBqvkwMqQMhwu';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $user, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Erreur de connexion : " . $e->getMessage());
}

// Initialisation de la variable message
$message = '';

// Gestion du formulaire
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Récupérer les données du formulaire
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    // Validation des champs
    if (!empty($username) && !empty($password)) {
        // Hachage du mot de passe
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

        try {
            // Insertion dans la base de données
            $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':password', $hashedPassword);

            if ($stmt->execute()) {
                $message = "Bonjour, " . htmlspecialchars($username) . " ! Vous êtes enregistré avec succès.";
            } else {
                $message = "Erreur lors de l'enregistrement dans la base de données.";
            }
        } catch (PDOException $e) {
            $message = "Erreur : " . $e->getMessage();
        }
    } else {
        $message = "Veuillez remplir tous les champs.";
    }
    var_dump($message);

}
?>