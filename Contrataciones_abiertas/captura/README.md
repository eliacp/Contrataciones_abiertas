# EDCA - Herramienta de Captura de información de Contrataciones Abiertas 

El Estandar de Datos de Contrataciones Abiertas (EDCA) disponibiliza datos y
documentos en todas las etapas del proceso de contratación al definir un modelo de datos
común.

## Instalación
Instrucciónes para instalar la Herramienta de captura de información de Contrataciones
 Abiertas.

### Dependencias 
1. MongoDB
2. PostgreSQL
3. Nodejs v6 o posterior

### Configuración de la base de datos 
1. `psql -U postgres < sql/edca.sql`

### Creación de usuarios
La creación de usuarios del sistema se realiza de la siguiente manera:
`scripts/useradm add <Nombre_Usuario> <Contraseña>`

### Configuración de la herramienta
1. `cd EDCA/ && npm install`
2. `cd public/ && bower install`
    
## Ejecución
1. `cd EDCA/ && npm start` 
2. A través de un navegador web, apuntar a la siguiente dirección: 
   `http://localhost:3000/`

