<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BIENVENIDOS AL MUNDO GAMER</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        body {
            font-family: 'Press Start 2P', cursive;
            background: linear-gradient(to right, #0f2027, #203a43, #2c5364);
            color: #e0e0e0;
            margin: 0;
            padding: 0;
        }

        header {
            background-color: rgba(0, 0, 0, 0.9);
            padding: 20px;
            text-align: center;
            border-bottom: 3px solid #ffcc00;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.7);
        }

        h1 {
            font-size: 3em;
            color: #ffcc00;
            text-shadow: 2px 2px 10px #ff0000;
        }

        nav ul {
            list-style: none;
            padding: 0;
        }

        nav ul li {
            display: inline;
            margin: 0 20px;
        }

        nav ul li a {
            color: #e0e0e0;
            text-decoration: none;
            font-size: 1.5em;
            transition: color 0.3s ease;
            position: relative;
            padding: 10px; /* Espaciado para el ícono */
            display: inline-flex; /* Cambiado para centrar el icono */
            align-items: center; /* Alineación vertical */
            border: 2px solid transparent; /* Para el efecto de botón */
            border-radius: 5px; /* Bordes redondeados */
        }

        nav ul li a:hover {
            color: #ffcc00;
            text-shadow: 1px 1px 5px #ff9900;
            border-color: #ffcc00; /* Cambia el color del borde al pasar el mouse */
        }

        .login-icon {
            font-size: 1.5em; /* Tamaño del ícono */
            margin-right: 5px; /* Espacio entre el ícono y el texto */
        }

        main {
            padding: 20px;
            text-align: center;
        }

        .presentation {
            background-color: rgba(255, 255, 255, 0.1);
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.6);
            margin-bottom: 40px;
        }

        .presentation h2 {
            font-size: 2.5em;
            color: #ffcc00;
        }

        .presentation p {
            font-size: 1.5em;
            color: #e0e0e0;
            line-height: 1.8;
        }

        .image-container {
            display: inline-block;
            margin: 20px;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
            transition: transform 0.3s;
        }

        img {
            width: 300px;
            height: 400px;
            display: block;
            border-radius: 15px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.6);
            transition: transform 0.3s, box-shadow 0.3s;
        }

        .image-container:hover img {
            transform: scale(1.05);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.8);
        }

        .image-description {
            margin-top: 10px;
            font-size: 1.2em;
            color: #ffcc00;
            text-shadow: 1px 1px 5px #000;
        }

        button {
            background-color: #ffcc00;
            color: black;
            border: none;
            padding: 15px 30px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 1.5em;
            transition: background-color 0.3s, transform 0.2s;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.6);
            margin-top: 20px;
        }

        button:hover {
            background-color: #ff9900;
            transform: scale(1.1);
        }

        footer {
            background-color: rgba(0, 0, 0, 0.8);
            padding: 10px;
            text-align: center;
            border-top: 3px solid #ffcc00;
            color: #e0e0e0;
            position: fixed;
            width: 100%;
            bottom: 0;
        }
    </style>
</head>

<body onclick="document.getElementById('miAudio').play()">
    <audio id="miAudio" loop>
        <source src="Halo Theme Song Original.mp3" type="audio/mpeg">
        Tu navegador no soporta el elemento de audio.
    </audio>

    <header>
        <h1>BIENVENIDO AL MUNDO GAMER</h1>

        <nav>
            <ul>
                <li><a href="pruebas.html">Más videojuegos</a></li>
                <li><a href="lo mas vendido.html">Próximos lanzamientos</a></li>
                <li><a href="pagina de presentacion.html">Inicio</a></li>
                <li><a href="contactos.html">Contacto</a></li>
                <li>
                    <a href="index.html" class="login-icon">
                        <i class="fas fa-user"></i> 
                    </a>
                </li>
            </ul>
        </nav>
    </header>

    <main>
        <div class="presentation">
            <h2>Bienvenido a Mundo Gamer</h2>
            <p>
                ¡Hola, Gamer! Nos emociona darte la bienvenida a Mundo Gamer, el sitio donde encontrarás todo lo que necesitas 
                sobre los mejores videojuegos. Desde lanzamientos, hasta las mejores ofertas y noticias del mundo gamer. 
                Prepárate para disfrutar de una experiencia única donde podrás conocer los títulos más esperados.
            </p>
            <p>
                Explora nuestros catálogos y no te pierdas ninguna novedad. ¡Estamos aquí para llevarte al siguiente nivel!
            </p>
        </div>

        <h2>Lo más popular</h2>
        <div class="image-container">
            <img src="imagen de gta 5.jpg" alt="Videojuego 1">
            <p class="image-description">Precio: $99.99</p>
        </div>
        <div class="image-container">
            <img src="imagen de devil may cry 3.jpg" alt="Videojuego 2">
            <p class="image-description">Precio: $49.99</p>
        </div>
        <div class="image-container">
            <img src="imagen de devil may cry 4.jpg" alt="Videojuego 3">
            <p class="image-description">Precio: $57.99</p>
        </div>
        <div class="image-container">
            <img src="imagen de devil may cry 2.5.jpg" alt="Videojuego 4">
            <p class="image-description">Precio: $86.99</p>
        </div>
        <div class="image-container">
            <img src="imagen de devil may cry 1.jpg" alt="Videojuego 5">
            <p class="image-description">Precio: $36.99</p>
        </div>
        <div class="image-container">
            <img src="imagen de gta.jpg" alt="Videojuego 6">
            <p class="image-description">Precio: $169.99</p>
        </div>
    </main>

    <footer>
        &copy; 2024 Mundo Gamer - Todos los derechos reservados.
    </footer>
</body>

</html>
