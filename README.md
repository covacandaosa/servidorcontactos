# Servidor de Contactos Seguro que mnadó Julio

Proyecto de ejemplo cliente-servidor con comunicación cifrada mediante sockets en Java.

## Tecnologías usadas

- Java 11+
- Sockets TCP
- Cifrado asimétrico (RSA)
- Cifrado simétrico (AES/GCM/NoPadding)
- Derivación de clave (PBKDF2WithHmacSHA256)
- Codificación Base64

## Seguridad implementada

- Clave AES derivada de contraseña mediante PBKDF2 (con salt aleatoria)
- Clave secreta cifrada con la clave pública del servidor
- Comunicación protegida con AES en modo GCM
- Intercambio de IV y algoritmo desde el cliente

## Estructura

src/ ├── fp/dam/psp/servidorcontactos/ │ ├── cliente/ │ │ └── Main.java │ └── servidor/ │ ├── Server.java │ └── RequestHandler.java └── resources/ └── keystore.p12


## ▶Cómo ejecutar

1. Ejecutar `Server.java` (escucha en el puerto 9000).
2. Ejecutar `Main.java` para enviar una petición cifrada.
3. Ver la respuesta descifrada en consola del cliente.

## Estado del proyecto

✅ Cliente y servidor funcionando con cifrado AES/GCM  
✅ Prueba completa con éxito  
✅ Listo para entrega o ampliación


