# web-service development 2nd midterm task

- [Prologue](#prologue)
- [Process](#process)
- [Requirements](#requirements)
- [Tools and Packages](#tools-and-packages)
  - [Tools and IDE's](#tools-and-ides)
  - [Packages and Libraries](#packages-and-libraries)

## Prologue
## repo created for my 2nd midterm for my subject in - Web services development  

this repo is a "sequel" as my 2nd midterm project in subject "web service applications development", the previous `(prequel)` project can be seen [here](https://github.com/K0d0ku/web-serv_midterm1)  

___after the subject will end both the [prequel](https://github.com/K0d0ku/web-serv_midterm1) and the [sequel](https://github.com/K0d0ku/web-serv_midterm2) repository will be archived___.  
___

## Process
like in the prequel you can see the process and the additional details in the making of this project in the : [the_process2.md](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/the_process2.md) `(it is also mandatory to check)`  
since this project is written in `GO` the list of tools and packages will differ from the previous one  
___

## Requirements
### the project is made with the following requirements:  
![requirements2](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/requirements2.png)  
___

## Tools and Packages
### and used the following tools and packages:

the packages and the Golang version are also listed in the [go.mod](#link)
```
code
```

Created a postgres Database called **KuroApiDb2**  

#### Tools and IDE's  
- Go 1.25.4 — primary backend language
- Goland — IDE for Go development (it was the best suit for my case)
- PostgreSQL 17 — with PgAdmin, main relational database
- DataGrip — database exploration tool (Optional, became useless near end)
- Postman — API testing
- Swagger (Swaggo) — API documentation generator

#### Packages and Libraries  
1. Core Backend Framework:

| Package           | Link                                                                 | Description                                                            |
| ----------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **Echo v4**       | [https://github.com/labstack/echo](https://github.com/labstack/echo) | Web framework used to build REST API routes, middleware, and handlers. |
| **gin-gonic/gin** | [https://github.com/gin-gonic/gin](https://github.com/gin-gonic/gin) | Alternative routing/middleware library; only partially used.           |
  
2. Database / ORM:

| Package                  | Link                                                               | Description                                        |
| ------------------------ | ------------------------------------------------------------------ | -------------------------------------------------- |
| **GORM**                 | [https://gorm.io/gorm](https://gorm.io/gorm)                       | ORM used for interacting with Postgres.            |
| **GORM Postgres Driver** | [https://gorm.io/driver/postgres](https://gorm.io/driver/postgres) | Postgres database driver for GORM.                 |
| **google/uuid**          | [https://github.com/google/uuid](https://github.com/google/uuid)   | UUID generation for models.                        |
| **jackc/pgx**            | [https://github.com/jackc/pgx](https://github.com/jackc/pgx)       | Low-level Postgres driver indirectly used by GORM. |  

3. Authentication / Security

| Package                 | Link                                                                             | Description                            |
| ----------------------- | -------------------------------------------------------------------------------- | -------------------------------------- |
| **golang-jwt/jwt/v5**   | [https://github.com/golang-jwt/jwt](https://github.com/golang-jwt/jwt)           | JWT creation, signing, and validation. |
| **golang.org/x/crypto** | [https://pkg.go.dev/golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | Password hashing utilities (bcrypt).   |

4. Validation

| Package                         | Link                                                                                                           | Description                               |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| **go-playground/validator/v10** | [https://github.com/go-playground/validator](https://github.com/go-playground/validator)                       | Struct validation library used in DTOs.   |
| **go-playground/locales**       | [https://github.com/go-playground/locales](https://github.com/go-playground/locales)                           | Locale support for validator.             |
| **universal-translator**        | [https://github.com/go-playground/universal-translator](https://github.com/go-playground/universal-translator) | Required by validator for error messages. |

5. Logging

| Package                | Link                                                                           | Description                                        |
| ---------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------- |
| **zerolog**            | [https://github.com/rs/zerolog](https://github.com/rs/zerolog)                 | Structured logging library (main logging backend). |
| **mattn/go-isatty**    | [https://github.com/mattn/go-isatty](https://github.com/mattn/go-isatty)       | Supports terminal TTY detection for Zerolog.       |
| **mattn/go-colorable** | [https://github.com/mattn/go-colorable](https://github.com/mattn/go-colorable) | Enables colored logs on Windows.                   |

6. Environment & Utilities

| Package              | Link                                                                       | Description                               |
| -------------------- | -------------------------------------------------------------------------- | ----------------------------------------- |
| **joho/godotenv**    | [https://github.com/joho/godotenv](https://github.com/joho/godotenv)       | Loads `.env` configuration.               |
| **labstack/gommon**  | [https://github.com/labstack/gommon](https://github.com/labstack/gommon)   | Utility helpers required by Echo.         |
| **stretchr/testify** | [https://github.com/stretchr/testify](https://github.com/stretchr/testify) | Assertions library (indirect dependency). |

7. Swagger / Documentation

| Package                 | Link                                                                             | Description                                    |
| ----------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------- |
| **swaggo/swag**         | [https://github.com/swaggo/swag](https://github.com/swaggo/swag)                 | Generates swagger documentation from comments. |
| **swaggo/echo-swagger** | [https://github.com/swaggo/echo-swagger](https://github.com/swaggo/echo-swagger) | Echo middleware for serving Swagger UI.        |
| **swaggo/files**        | [https://github.com/swaggo/files](https://github.com/swaggo/files)               | Static Swagger UI files.                       |
